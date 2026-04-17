//! CPU Counters: per-PC counter aggregation. Joins the `time-sample`
//! table (sample-time -> PC) with `kdebug-counters-with-time-sample`
//! (sample-time -> counter values) on `sample-time`.

use std::collections::HashMap;

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

#[derive(Debug, Clone, Serialize)]
pub struct CounterReport {
    pub labels: Vec<String>,
    pub total_samples: u64,
    pub per_pc: Vec<PerPcCounter>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerPcCounter {
    pub pc: u64,
    pub samples: u64,
    pub values: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// Read counter labels (e.g. `["Cycles", "Instruction Delivery Bottleneck", ...]`)
/// from the trace's `MetricTable` swift-table debug dump.
pub fn metric_labels(bundle: &TraceBundle) -> Result<Vec<String>> {
    read_labels(bundle)
}

/// Compute the per-PC sum of `metric_idx`'s sample-to-sample deltas
/// (per-CPU). This is the same join that `CountersBuilder::run` does,
/// but returns a flat `pc -> delta-sum` map for one metric so other
/// commands (notably `annotate`) can overlay it.
pub fn per_pc_metric_deltas(
    bundle: &TraceBundle,
    pid: Option<i64>,
    metric_idx: usize,
) -> Result<HashMap<u64, u64>> {
    let time_samples = read_time_samples(bundle, pid)?;
    let counter_rows = read_counters_with_core(bundle, pid)?;

    let mut by_time: HashMap<u64, &TimeSample> = HashMap::with_capacity(time_samples.len());
    for ts in &time_samples {
        by_time.insert(ts.time, ts);
    }
    let mut by_core: HashMap<u32, Vec<&CounterSample>> = HashMap::new();
    for cs in &counter_rows {
        by_core.entry(cs.core).or_default().push(cs);
    }

    let mut out: HashMap<u64, u64> = HashMap::new();
    for (_core, samples) in by_core {
        for win in samples.windows(2) {
            let prev = win[0];
            let curr = win[1];
            if curr.counters.len() != prev.counters.len() {
                continue;
            }
            let Some(ts) = by_time.get(&curr.time).copied() else {
                continue;
            };
            let Some(c) = curr.counters.get(metric_idx) else {
                continue;
            };
            let Some(p) = prev.counters.get(metric_idx) else {
                continue;
            };
            let delta = c.saturating_sub(*p);
            // Drop suspicious deltas (thread migration, counter reset).
            if delta > 1_000_000_000 {
                continue;
            }
            *out.entry(ts.pc).or_insert(0) += delta;
        }
    }
    Ok(out)
}

pub struct CountersBuilder<'a> {
    bundle: &'a TraceBundle,
    pid: Option<i64>,
    top_n: usize,
    sort_by_index: Option<usize>,
    binary: Option<PathBuf>,
    dsym: Option<PathBuf>,
    slide: Option<u64>,
}

impl<'a> CountersBuilder<'a> {
    pub fn new(bundle: &'a TraceBundle) -> Self {
        Self {
            bundle,
            pid: None,
            top_n: 25,
            sort_by_index: None,
            binary: None,
            dsym: None,
            slide: None,
        }
    }

    pub fn pid(mut self, pid: i64) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn top(mut self, n: usize) -> Self {
        self.top_n = n;
        self
    }

    pub fn sort_by_index(mut self, idx: usize) -> Self {
        self.sort_by_index = Some(idx);
        self
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

    pub fn run(self) -> Result<CounterReport> {
        let labels = read_labels(self.bundle).unwrap_or_default();

        let time_samples = read_time_samples(self.bundle, self.pid)?;
        let counter_rows = read_counters_with_core(self.bundle, self.pid)?;

        let mut by_time: HashMap<u64, &TimeSample> = HashMap::with_capacity(time_samples.len());
        for ts in &time_samples {
            by_time.insert(ts.time, ts);
        }

        // Group counter rows by core, in trace order, so we can diff
        // consecutive samples on the same physical CPU.
        let mut by_core: HashMap<u32, Vec<&CounterSample>> = HashMap::new();
        for cs in &counter_rows {
            by_core.entry(cs.core).or_default().push(cs);
        }

        let mut per_pc: HashMap<u64, PerPcCounter> = HashMap::new();
        let mut total_attributed: u64 = 0;

        for (_core, samples) in by_core {
            for win in samples.windows(2) {
                let prev = win[0];
                let curr = win[1];
                if curr.counters.len() != prev.counters.len() {
                    continue;
                }
                let Some(ts) = by_time.get(&curr.time).copied() else {
                    continue;
                };
                if let Some(want) = self.pid
                    && ts.pid != want
                {
                    continue;
                }
                let deltas: Vec<u64> = curr
                    .counters
                    .iter()
                    .zip(prev.counters.iter())
                    .map(|(c, p)| c.saturating_sub(*p))
                    .collect();
                // A monotonic counter can appear to "wrap" if the thread
                // got migrated mid-window or kperf reset; bail on the
                // sample if any non-tail counter implausibly large.
                if deltas
                    .iter()
                    .take(deltas.len().saturating_sub(4))
                    .any(|d| *d > 1_000_000_000)
                {
                    continue;
                }
                let entry = per_pc.entry(ts.pc).or_insert_with(|| PerPcCounter {
                    pc: ts.pc,
                    samples: 0,
                    values: vec![0; deltas.len()],
                    function: None,
                    file: None,
                    line: None,
                });
                entry.samples += 1;
                if entry.values.len() < deltas.len() {
                    entry.values.resize(deltas.len(), 0);
                }
                for (i, d) in deltas.iter().enumerate() {
                    entry.values[i] = entry.values[i].saturating_add(*d);
                }
                total_attributed += 1;
            }
        }

        let mut rows: Vec<PerPcCounter> = per_pc.into_values().collect();
        match self.sort_by_index {
            Some(idx) => rows.sort_by(|a, b| {
                b.values
                    .get(idx)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&a.values.get(idx).copied().unwrap_or(0))
            }),
            None => rows.sort_by(|a, b| b.samples.cmp(&a.samples)),
        }
        rows.truncate(self.top_n);

        if self.binary.is_some() || self.dsym.is_some() {
            let slide = match self.slide {
                Some(s) => Some(s),
                None => match self.binary.as_deref() {
                    Some(bin) => {
                        let info = binary_info(bin)?;
                        let loads = read_image_loads(self.bundle).unwrap_or_default();
                        slide_from_kdebug(&info, &loads)
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
            for r in &mut rows {
                if let Ok(frame) = sym.resolve(r.pc) {
                    r.function = frame.function;
                    r.file = frame.file;
                    r.line = frame.line;
                }
            }
        }

        Ok(CounterReport {
            labels,
            total_samples: total_attributed,
            per_pc: rows,
        })
    }
}

#[derive(Debug)]
struct TimeSample {
    time: u64,
    pid: i64,
    pc: u64,
}

#[derive(Debug)]
struct CounterSample {
    time: u64,
    core: u32,
    counters: Vec<u64>,
}

fn read_time_samples(bundle: &TraceBundle, pid_filter: Option<i64>) -> Result<Vec<TimeSample>> {
    let xml = bundle
        .xctrace()
        .export_xpath(bundle.path(), TIME_SAMPLE_XPATH)?;
    let mut reader = RowReader::new(std::io::Cursor::new(xml));
    let mut out: Vec<TimeSample> = Vec::new();
    while let Some(ev) = reader.next_event()? {
        let RowReaderEvent::Row(cells) = ev else {
            continue;
        };
        let mut time: Option<u64> = None;
        let mut pid: i64 = -1;
        let mut state: Option<&str> = None;
        let mut pc: Option<u64> = None;
        for cell in &cells {
            match cell.element() {
                Some("sample-time") => time = cell.as_u64(),
                Some("thread") => {
                    if let Some(p) = cell.find("pid") {
                        pid = p.as_i64().unwrap_or(-1);
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
        if let Some(want) = pid_filter
            && pid != want
        {
            continue;
        }
        let (Some(t), Some(p)) = (time, pc) else {
            continue;
        };
        out.push(TimeSample {
            time: t,
            pid,
            pc: p,
        });
    }
    Ok(out)
}

fn read_counters_with_core(
    bundle: &TraceBundle,
    pid_filter: Option<i64>,
) -> Result<Vec<CounterSample>> {
    let xml = bundle.xctrace().export_xpath(bundle.path(), KDC_XPATH)?;
    let mut reader = RowReader::new(std::io::Cursor::new(xml));
    let mut out: Vec<CounterSample> = Vec::new();
    while let Some(ev) = reader.next_event()? {
        let RowReaderEvent::Row(cells) = ev else {
            continue;
        };
        let mut time: Option<u64> = None;
        let mut pid: i64 = -1;
        let mut state: Option<&str> = None;
        let mut core: Option<u32> = None;
        let mut counters: Option<Vec<u64>> = None;
        for cell in &cells {
            match cell.element() {
                Some("sample-time") => time = cell.as_u64(),
                Some("thread") => {
                    if let Some(p) = cell.find("pid") {
                        pid = p.as_i64().unwrap_or(-1);
                    }
                }
                Some("core") => core = cell.as_u64().map(|v| v as u32),
                Some("thread-state") => {
                    state = match cell.as_ref() {
                        Cell::Leaf(l) => Some(l.text.as_str()),
                        _ => None,
                    };
                }
                Some("pmc-events") => counters = parse_pmc_text(cell),
                _ => {}
            }
        }
        if state == Some("Blocked") {
            continue;
        }
        if let Some(want) = pid_filter
            && pid != want
        {
            continue;
        }
        let (Some(t), Some(c), Some(cs)) = (time, core, counters) else {
            continue;
        };
        out.push(CounterSample {
            time: t,
            core: c,
            counters: cs,
        });
    }
    Ok(out)
}

const TIME_SAMPLE_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"time-sample\"]";

fn parse_pmc_text(cell: &Cell) -> Option<Vec<u64>> {
    let text = cell.text()?;
    let mut out = Vec::new();
    for tok in text.split_ascii_whitespace() {
        out.push(tok.parse::<u64>().ok()?);
    }
    Some(out)
}

const KDC_XPATH: &str =
    "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"kdebug-counters-with-time-sample\"]";

/// Pull metric labels from `MetricTable`'s `swift-table` attribute. The
/// attribute is a Swift `Mirror` debug dump that contains a `metricLegend`
/// substring of the form `"index 0: Cycles \n\nindex 1: ...\n\n"`. We
/// extract the labels positionally by index.
fn read_labels(bundle: &TraceBundle) -> Result<Vec<String>> {
    let toc = bundle.toc()?;
    let Some(run) = toc.first_run() else {
        return Ok(Vec::new());
    };
    let Some(table) = run.table("MetricTable") else {
        return Ok(Vec::new());
    };
    let Some(swift) = table.attributes.get("swift-table") else {
        return Ok(Vec::new());
    };
    Ok(parse_metric_legend(swift))
}

fn parse_metric_legend(swift_table: &str) -> Vec<String> {
    let needle = "metricLegend:";
    let start = match swift_table.find(needle) {
        Some(s) => s + needle.len(),
        None => return Vec::new(),
    };
    let rest = &swift_table[start..];
    let after_quote = match rest.find('"') {
        Some(s) => s + 1,
        None => return Vec::new(),
    };
    let body = &rest[after_quote..];
    let end = match body.find("\\\"") {
        Some(e) => e,
        None => match body.find('"') {
            Some(e) => e,
            None => return Vec::new(),
        },
    };
    let body = &body[..end];

    let mut labels = Vec::new();
    for chunk in body.split("\\n\\n") {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        if let Some(colon) = chunk.find(':') {
            let label = chunk[colon + 1..]
                .trim()
                .trim_end_matches(['\\', 'n'])
                .trim();
            if !label.is_empty() {
                labels.push(label.to_string());
            }
        }
    }
    labels
}
