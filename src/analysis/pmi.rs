//! PMI-overflow sample reading from `SamplingModeSamples`.
//!
//! L1D miss / TLB miss / etc. traces emit one row per Nth event in the
//! `SamplingModeSamples` table. Each row carries the precise PC, the
//! event name (`pmi-event`, e.g. `l1d_load_miss`), and an inline
//! backtrace.

use std::collections::BTreeSet;
use std::collections::HashMap;

use crate::error::Result;
use crate::trace::TraceBundle;
use crate::xml::Cell;
use crate::xml::stream::RowReader;
use crate::xml::stream::RowReaderEvent;

#[derive(Debug, Clone)]
pub struct PmiSample {
    pub time: u64,
    pub pid: i64,
    pub event: String,
    pub pc: u64,
}

const SMS_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"SamplingModeSamples\"]";

pub fn read_pmi_samples(bundle: &TraceBundle, pid: Option<i64>) -> Result<Vec<PmiSample>> {
    let xml = bundle.xctrace().export_xpath(bundle.path(), SMS_XPATH)?;
    let mut reader = RowReader::new(std::io::Cursor::new(xml));
    let mut out: Vec<PmiSample> = Vec::new();
    while let Some(ev) = reader.next_event()? {
        let RowReaderEvent::Row(cells) = ev else {
            continue;
        };
        let mut time: Option<u64> = None;
        let mut sample_pid: i64 = -1;
        let mut event: Option<String> = None;
        let mut pc: Option<u64> = None;
        for cell in &cells {
            match cell.element() {
                Some("sample-time") => time = cell.as_u64(),
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
                    // `weight-columns` array. PC is the first uint64 we see
                    // (the array elements are `<uint64-array>`-typed).
                    if pc.is_none() {
                        pc = cell.as_u64();
                    }
                }
                _ => {}
            }
        }
        if let Some(want) = pid
            && sample_pid != want
        {
            continue;
        }
        let (Some(t), Some(e), Some(p)) = (time, event, pc) else {
            continue;
        };
        out.push(PmiSample {
            time: t,
            pid: sample_pid,
            event: e,
            pc: p,
        });
    }
    Ok(out)
}

/// Distinct `pmi-event` names present in the trace (e.g. `l1d_load_miss`).
pub fn pmi_event_names(bundle: &TraceBundle) -> Result<Vec<String>> {
    let samples = read_pmi_samples(bundle, None)?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    for s in samples {
        set.insert(s.event);
    }
    Ok(set.into_iter().collect())
}

/// Per-PC sample counts for the named PMI event. Tries
/// `SamplingModeSamples` first (Guided-mode templates carry their own
/// PCs); falls back to `counters-profile` (Manual-mode templates have
/// no per-sample callstacks, so PCs are recovered by joining each PMI
/// timestamp to the nearest `time-sample` row).
pub fn per_pc_pmi_count(
    bundle: &TraceBundle,
    pid: Option<i64>,
    event: &str,
) -> Result<HashMap<u64, u64>> {
    let samples = read_pmi_samples(bundle, pid)?;
    let mut out: HashMap<u64, u64> = HashMap::new();
    for s in samples {
        if s.event == event {
            *out.entry(s.pc).or_insert(0) += 1;
        }
    }
    if !out.is_empty() {
        return Ok(out);
    }
    // Fallback: counters-profile (Manual mode). Match the event name
    // recorded in the TOC, then join each row to the nearest time-sample
    // by timestamp.
    let toc_event = counters_profile_event(bundle)?;
    let Some(toc_event) = toc_event else {
        return Ok(out);
    };
    if !toc_event.eq_ignore_ascii_case(event) {
        return Ok(out);
    }
    let pmi_times = read_counters_profile_times(bundle, pid)?;
    if pmi_times.is_empty() {
        return Ok(out);
    }
    let mut time_pcs = read_time_sample_times_pcs(bundle, pid)?;
    time_pcs.sort_by_key(|(t, _)| *t);
    let times: Vec<u64> = time_pcs.iter().map(|(t, _)| *t).collect();
    const MAX_WINDOW_NS: u64 = 1_000_000;
    for t in pmi_times {
        let Some(pc) = nearest_pc(&times, &time_pcs, t, MAX_WINDOW_NS) else {
            continue;
        };
        *out.entry(pc).or_insert(0) += 1;
    }
    Ok(out)
}

/// Read the `pmi-event` attribute on the trace's `counters-profile`
/// table. Returns `None` if the table is absent.
pub fn counters_profile_event(bundle: &TraceBundle) -> Result<Option<String>> {
    let toc = bundle.toc()?;
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

fn read_counters_profile_times(bundle: &TraceBundle, pid: Option<i64>) -> Result<Vec<u64>> {
    let xml = bundle.xctrace().export_xpath(bundle.path(), CP_XPATH)?;
    let mut reader = RowReader::new(std::io::Cursor::new(xml));
    let mut out: Vec<u64> = Vec::new();
    while let Some(ev) = reader.next_event()? {
        let RowReaderEvent::Row(cells) = ev else {
            continue;
        };
        let mut time: Option<u64> = None;
        let mut sample_pid: i64 = -1;
        for cell in &cells {
            match cell.element() {
                Some("sample-time") => time = cell.as_u64(),
                Some("thread") => {
                    if let Some(p) = cell.find("pid") {
                        sample_pid = p.as_i64().unwrap_or(-1);
                    }
                }
                _ => {}
            }
        }
        if let Some(want) = pid
            && sample_pid != want
        {
            continue;
        }
        if let Some(t) = time {
            out.push(t);
        }
    }
    Ok(out)
}

fn read_time_sample_times_pcs(bundle: &TraceBundle, pid: Option<i64>) -> Result<Vec<(u64, u64)>> {
    let xml = bundle.xctrace().export_xpath(bundle.path(), TS_XPATH)?;
    let mut reader = RowReader::new(std::io::Cursor::new(xml));
    let mut out: Vec<(u64, u64)> = Vec::new();
    while let Some(ev) = reader.next_event()? {
        let RowReaderEvent::Row(cells) = ev else {
            continue;
        };
        let mut time: Option<u64> = None;
        let mut sample_pid: i64 = -1;
        let mut state: Option<&str> = None;
        let mut pc: Option<u64> = None;
        for cell in &cells {
            match cell.element() {
                Some("sample-time") => time = cell.as_u64(),
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
                        pc = pcc.as_u64();
                    }
                }
                _ => {}
            }
        }
        if state == Some("Blocked") {
            continue;
        }
        if let Some(want) = pid
            && sample_pid != want
        {
            continue;
        }
        let (Some(t), Some(p)) = (time, pc) else {
            continue;
        };
        out.push((t, p));
    }
    Ok(out)
}

fn nearest_pc(times: &[u64], time_pcs: &[(u64, u64)], target: u64, max_window: u64) -> Option<u64> {
    let i = times.partition_point(|t| *t <= target);
    let prev = if i > 0 { Some(time_pcs[i - 1]) } else { None };
    let next = time_pcs.get(i).copied();
    let best = match (prev, next) {
        (Some(p), Some(n)) => {
            if target - p.0 <= n.0 - target {
                p
            } else {
                n
            }
        }
        (Some(p), None) => p,
        (None, Some(n)) => n,
        (None, None) => return None,
    };
    let dist = best.0.abs_diff(target);
    if dist > max_window {
        return None;
    }
    Some(best.1)
}

const CP_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"counters-profile\"]";
const TS_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"time-sample\"]";
