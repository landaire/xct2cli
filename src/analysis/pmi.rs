//! PMI-overflow sampling.
//!
//! Two surfaces:
//! - `SamplingModeSamples` (Guided-mode templates like L1D Miss Sampling) -
//!   each row carries event name, PC, and inline backtrace.
//! - `counters-profile` (Manual-mode templates) - rows have no per-sample
//!   callstack, so PCs are recovered by joining each PMI timestamp to the
//!   nearest `time-sample` row from a co-recorded Time Profiler.

use std::collections::BTreeSet;
use std::collections::HashMap;

use crate::address::Pid;
use crate::address::RuntimePc;
use crate::address::SampleTime;
use crate::error::Result;
use crate::trace::TraceBundle;
use crate::xml::Cell;
use crate::xml::stream::RowReader;
use crate::xml::stream::RowReaderEvent;

#[derive(Debug, Clone)]
pub struct PmiSample {
    pub time: SampleTime,
    pub pid: Pid,
    pub event: String,
    pub pc: RuntimePc,
}

#[derive(Debug, Clone, Copy)]
struct TimePc {
    time: SampleTime,
    pc: RuntimePc,
}

impl TraceBundle {
    /// Read every row of `SamplingModeSamples` (Guided-mode PMI sampling).
    /// Returns `Ok(vec![])` if the table is absent or empty.
    pub fn pmi_samples(&self, pid: Option<Pid>) -> Result<Vec<PmiSample>> {
        let xml = self.xctrace().export_xpath(self.path(), SMS_XPATH)?;
        let mut reader = RowReader::new(std::io::Cursor::new(xml));
        let mut out: Vec<PmiSample> = Vec::new();
        while let Some(ev) = reader.next_event()? {
            let RowReaderEvent::Row(cells) = ev else {
                continue;
            };
            let mut time: Option<SampleTime> = None;
            let mut sample_pid: i64 = -1;
            let mut event: Option<String> = None;
            let mut pc: Option<RuntimePc> = None;
            for cell in &cells {
                match cell.element() {
                    Some("sample-time") => time = cell.as_u64().map(SampleTime::new),
                    Some("string") => {
                        if event.is_none()
                            && let Cell::Leaf(l) = cell.as_ref()
                        {
                            event = Some(l.text.clone());
                        }
                    }
                    Some("thread") => {
                        if let Some(p) = cell.find("pid") {
                            sample_pid = p.as_i64().unwrap_or(-1);
                        }
                    }
                    Some("uint64") => {
                        // SamplingModeSamples has a `pc` column (uint64) and a
                        // `weight-columns` array. PC is the first uint64 we see.
                        if pc.is_none() {
                            pc = cell.as_u64().map(RuntimePc::new);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(want) = pid
                && Pid::new(sample_pid) != want
            {
                continue;
            }
            let (Some(t), Some(e), Some(p)) = (time, event, pc) else {
                continue;
            };
            out.push(PmiSample {
                time: t,
                pid: Pid::new(sample_pid),
                event: e,
                pc: p,
            });
        }
        Ok(out)
    }

    /// Distinct `pmi-event` names present in `SamplingModeSamples`.
    pub fn pmi_event_names(&self) -> Result<Vec<String>> {
        let samples = self.pmi_samples(None)?;
        let mut set: BTreeSet<String> = BTreeSet::new();
        for s in samples {
            set.insert(s.event);
        }
        Ok(set.into_iter().collect())
    }

    /// Per-PC sample counts for the named PMI event. Tries
    /// `SamplingModeSamples` first; falls back to `counters-profile` joined
    /// against `time-sample` by nearest timestamp.
    pub fn per_pc_pmi_count(
        &self,
        pid: Option<Pid>,
        event: &str,
    ) -> Result<HashMap<RuntimePc, u64>> {
        let samples = self.pmi_samples(pid)?;
        let mut out: HashMap<RuntimePc, u64> = HashMap::new();
        for s in samples {
            if s.event == event {
                *out.entry(s.pc).or_insert(0) += 1;
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
        let Some(toc_event) = self.counters_profile_event()? else {
            return Ok(out);
        };
        if !toc_event.eq_ignore_ascii_case(event) {
            return Ok(out);
        }
        let pmi_times = self.read_counters_profile_times(pid)?;
        if pmi_times.is_empty() {
            return Ok(out);
        }
        let mut time_pcs = self.read_time_sample_times_pcs(pid)?;
        time_pcs.sort_by_key(|tp| tp.time);
        const MAX_WINDOW_NS: u64 = 1_000_000;
        for t in pmi_times {
            let Some(pc) = nearest_pc(&time_pcs, t, MAX_WINDOW_NS) else {
                continue;
            };
            *out.entry(pc).or_insert(0) += 1;
        }
        Ok(out)
    }

    /// Read the `pmi-event` attribute from the trace's `counters-profile`
    /// table - i.e. the event the Manual-mode template was configured to
    /// sample on. Returns `None` if no such table exists.
    pub fn counters_profile_event(&self) -> Result<Option<String>> {
        let toc = self.toc()?;
        let Some(run) = toc.first_run() else {
            return Ok(None);
        };
        let Some(t) = run.tables.iter().find(|t| t.schema == "counters-profile") else {
            return Ok(None);
        };
        Ok(t.attributes
            .get("pmi-event")
            .map(|v| v.trim_matches('"').to_string()))
    }

    fn read_counters_profile_times(&self, pid: Option<Pid>) -> Result<Vec<SampleTime>> {
        let xml = self.xctrace().export_xpath(self.path(), CP_XPATH)?;
        let mut reader = RowReader::new(std::io::Cursor::new(xml));
        let mut out: Vec<SampleTime> = Vec::new();
        while let Some(ev) = reader.next_event()? {
            let RowReaderEvent::Row(cells) = ev else {
                continue;
            };
            let mut time: Option<SampleTime> = None;
            let mut sample_pid: i64 = -1;
            for cell in &cells {
                match cell.element() {
                    Some("sample-time") => time = cell.as_u64().map(SampleTime::new),
                    Some("thread") => {
                        if let Some(p) = cell.find("pid") {
                            sample_pid = p.as_i64().unwrap_or(-1);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(want) = pid
                && Pid::new(sample_pid) != want
            {
                continue;
            }
            if let Some(t) = time {
                out.push(t);
            }
        }
        Ok(out)
    }

    fn read_time_sample_times_pcs(&self, pid: Option<Pid>) -> Result<Vec<TimePc>> {
        let xml = self.xctrace().export_xpath(self.path(), TS_XPATH)?;
        let mut reader = RowReader::new(std::io::Cursor::new(xml));
        let mut out: Vec<TimePc> = Vec::new();
        while let Some(ev) = reader.next_event()? {
            let RowReaderEvent::Row(cells) = ev else {
                continue;
            };
            let mut time: Option<SampleTime> = None;
            let mut sample_pid: i64 = -1;
            let mut state: Option<&str> = None;
            let mut pc: Option<RuntimePc> = None;
            for cell in &cells {
                match cell.element() {
                    Some("sample-time") => time = cell.as_u64().map(SampleTime::new),
                    Some("thread") => {
                        if let Some(p) = cell.find("pid") {
                            sample_pid = p.as_i64().unwrap_or(-1);
                        }
                    }
                    Some("thread-state") => {
                        state = match cell.as_ref() {
                            Cell::Leaf(l) => Some(l.text.as_str()),
                            _ => None,
                        };
                    }
                    Some("kperf-bt") => {
                        if let Some(pcc) = cell.find("text-address") {
                            pc = pcc.as_u64().map(RuntimePc::new);
                        }
                    }
                    _ => {}
                }
            }
            if state == Some("Blocked") {
                continue;
            }
            if let Some(want) = pid
                && Pid::new(sample_pid) != want
            {
                continue;
            }
            let (Some(t), Some(p)) = (time, pc) else {
                continue;
            };
            out.push(TimePc { time: t, pc: p });
        }
        Ok(out)
    }
}

fn nearest_pc(time_pcs: &[TimePc], target: SampleTime, max_window: u64) -> Option<RuntimePc> {
    let i = time_pcs.partition_point(|tp| tp.time <= target);
    let prev = i.checked_sub(1).map(|j| time_pcs[j]);
    let next = time_pcs.get(i).copied();
    let best = match (prev, next) {
        (Some(p), Some(n)) => {
            if target.ns() - p.time.ns() <= n.time.ns() - target.ns() {
                p
            } else {
                n
            }
        }
        (Some(p), None) => p,
        (None, Some(n)) => n,
        (None, None) => return None,
    };
    let dist = if best.time.ns() > target.ns() {
        best.time.ns() - target.ns()
    } else {
        target.ns() - best.time.ns()
    };
    if dist > max_window {
        return None;
    }
    Some(best.pc)
}

const SMS_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"SamplingModeSamples\"]";
const CP_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"counters-profile\"]";
const TS_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"time-sample\"]";
