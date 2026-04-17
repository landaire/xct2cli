//! Per-CPU hotspot aggregation from the `time-sample` table.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::rc::Rc;

use serde::Serialize;

use std::path::PathBuf;

use crate::error::Result;
use crate::symbol::Symbolicator;
use crate::symbol::SymbolicatorOptions;
use crate::symbol::binary_info;
use crate::symbol::read_image_loads;
use crate::symbol::slide_from_kdebug;
use crate::trace::TraceBundle;
use crate::xml::Cell;
use crate::xml::stream::RowReader;
use crate::xml::stream::RowReaderEvent;

#[derive(Clone, Serialize)]
pub struct HotspotReport {
    pub total_samples: u64,
    pub per_cpu: BTreeMap<u32, CpuStats>,
    pub timeline_buckets_ns: u64,
    pub timeline: Vec<TimelineBucket>,
    pub top_pcs: Vec<Hotspot>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CpuStats {
    pub samples: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineBucket {
    pub start_ns: u64,
    pub end_ns: u64,
    pub samples_per_cpu: BTreeMap<u32, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hotspot {
    pub pc: u64,
    pub samples: u64,
    pub fmt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

pub struct HotspotsBuilder<'a> {
    bundle: &'a TraceBundle,
    pid: Option<i64>,
    bucket_ns: u64,
    top_n: usize,
    time_window_ns: Option<(u64, u64)>,
    binary: Option<PathBuf>,
    dsym: Option<PathBuf>,
    slide: Option<u64>,
}

impl<'a> HotspotsBuilder<'a> {
    pub fn new(bundle: &'a TraceBundle) -> Self {
        Self {
            bundle,
            pid: None,
            bucket_ns: 10_000_000,
            top_n: 25,
            time_window_ns: None,
            binary: None,
            dsym: None,
            slide: None,
        }
    }

    pub fn binary(mut self, path: Option<PathBuf>) -> Self {
        self.binary = path;
        self
    }

    pub fn dsym(mut self, path: Option<PathBuf>) -> Self {
        self.dsym = path;
        self
    }

    pub fn slide(mut self, slide: Option<u64>) -> Self {
        self.slide = slide;
        self
    }

    pub fn pid(mut self, pid: i64) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn bucket_ns(mut self, ns: u64) -> Self {
        self.bucket_ns = ns.max(1);
        self
    }

    pub fn top(mut self, n: usize) -> Self {
        self.top_n = n;
        self
    }

    pub fn time_window_ns(mut self, start: u64, end: u64) -> Self {
        self.time_window_ns = Some((start, end));
        self
    }

    pub fn run(self) -> Result<HotspotReport> {
        let xml = self
            .bundle
            .xctrace()
            .export_xpath(self.bundle.path(), TIME_SAMPLE_XPATH)?;
        let mut reader = RowReader::new(std::io::Cursor::new(xml));

        let mut total_samples: u64 = 0;
        let mut per_cpu: BTreeMap<u32, CpuStats> = BTreeMap::new();
        let mut pc_counts: HashMap<u64, (u64, Option<String>)> = HashMap::new();
        let mut bucket_map: BTreeMap<u64, BTreeMap<u32, u64>> = BTreeMap::new();
        let mut origin_ns: Option<u64> = None;

        while let Some(ev) = reader.next_event()? {
            let RowReaderEvent::Row(cells) = ev else {
                continue;
            };
            let Some(sample) = parse_time_sample(&cells) else {
                continue;
            };
            if let Some(want_pid) = self.pid
                && sample.pid != want_pid
            {
                continue;
            }
            if let Some((lo, hi)) = self.time_window_ns
                && (sample.time_ns < lo || sample.time_ns >= hi)
            {
                continue;
            }
            let Some(core) = sample.core else { continue };

            total_samples += 1;
            let entry = per_cpu.entry(core).or_default();
            entry.samples += 1;
            if entry.label.is_none() {
                entry.label = sample.core_label;
            }

            let origin = *origin_ns.get_or_insert(sample.time_ns);
            let bucket_key = (sample.time_ns.saturating_sub(origin)) / self.bucket_ns;
            *bucket_map
                .entry(bucket_key)
                .or_default()
                .entry(core)
                .or_default() += 1;

            if let Some(pc) = sample.pc {
                let e = pc_counts.entry(pc).or_insert((0, sample.pc_fmt));
                e.0 += 1;
            }
        }

        let mut timeline: Vec<TimelineBucket> = bucket_map
            .into_iter()
            .map(|(k, samples_per_cpu)| {
                let start_ns = k * self.bucket_ns;
                TimelineBucket {
                    start_ns,
                    end_ns: start_ns + self.bucket_ns,
                    samples_per_cpu,
                }
            })
            .collect();
        timeline.sort_by_key(|b| b.start_ns);

        let mut top_pcs: Vec<Hotspot> = pc_counts
            .into_iter()
            .map(|(pc, (samples, fmt))| Hotspot {
                pc,
                samples,
                fmt,
                function: None,
                file: None,
                line: None,
            })
            .collect();
        top_pcs.sort_by(|a, b| b.samples.cmp(&a.samples));
        top_pcs.truncate(self.top_n);

        if self.binary.is_some() || self.dsym.is_some() {
            let slide = match self.slide {
                Some(s) => Some(s),
                None => match self.binary.as_deref() {
                    Some(bin) => {
                        let info = binary_info(bin)?;
                        let loads = match read_image_loads(self.bundle) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!("read_image_loads failed: {e}");
                                Vec::new()
                            }
                        };
                        let s = slide_from_kdebug(&info, &loads);
                        match s {
                            Some(s) => {
                                tracing::info!(
                                    slide = format!("0x{:x}", s),
                                    "auto-detected slide from kdebug DBG_DYLD events"
                                );
                            }
                            None => {
                                tracing::warn!(
                                    "could not auto-detect slide; symbols will be wrong. Use `xct2cli slide` to inspect candidates and pass --slide explicitly."
                                );
                            }
                        }
                        s
                    }
                    None => None,
                },
            };
            let opts = SymbolicatorOptions {
                binary: self.binary.clone(),
                dsym: self.dsym.clone(),
                slide: slide.unwrap_or(0),
            };
            let sym = Symbolicator::new(opts)?;
            for h in &mut top_pcs {
                if let Ok(frame) = sym.resolve(h.pc) {
                    h.function = frame.function;
                    h.file = frame.file;
                    h.line = frame.line;
                }
            }
        }

        Ok(HotspotReport {
            total_samples,
            per_cpu,
            timeline_buckets_ns: self.bucket_ns,
            timeline,
            top_pcs,
        })
    }
}

const TIME_SAMPLE_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"time-sample\"]";

#[derive(Debug, Default)]
struct ParsedSample {
    time_ns: u64,
    pid: i64,
    core: Option<u32>,
    core_label: Option<String>,
    pc: Option<u64>,
    pc_fmt: Option<String>,
    thread_state: Option<String>,
}

fn parse_time_sample(cells: &[Rc<Cell>]) -> Option<ParsedSample> {
    let mut s = ParsedSample::default();
    for cell in cells {
        match cell.element() {
            Some("sample-time") => {
                s.time_ns = cell.as_u64().unwrap_or(0);
            }
            Some("thread") => {
                if let Some(pid_cell) = cell.find("pid") {
                    s.pid = pid_cell.as_i64().unwrap_or(-1);
                }
            }
            Some("core") => {
                s.core = cell.as_u64().map(|v| v as u32);
                s.core_label = cell.fmt().map(str::to_string);
            }
            Some("thread-state") => {
                s.thread_state = cell.text().map(str::to_string);
            }
            Some("kperf-bt") => {
                if let Some(pc_cell) = cell.find("text-address") {
                    s.pc = pc_cell.as_u64();
                    s.pc_fmt = pc_cell.fmt().map(str::to_string);
                }
            }
            _ => {}
        }
    }
    if s.time_ns == 0 && s.core.is_none() {
        return None;
    }
    if matches!(s.thread_state.as_deref(), Some("Blocked")) {
        // Blocked samples have no real CPU; skip from hot-spot accounting.
        return None;
    }
    Some(s)
}

impl HotspotReport {
    pub fn empty(bucket_ns: u64) -> Self {
        Self {
            total_samples: 0,
            per_cpu: BTreeMap::new(),
            timeline_buckets_ns: bucket_ns,
            timeline: Vec::new(),
            top_pcs: Vec::new(),
        }
    }
}
