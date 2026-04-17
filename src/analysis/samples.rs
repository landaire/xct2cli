use std::collections::HashMap;

use crate::address::Pid;
use crate::address::RuntimePc;
use crate::error::Result;
use crate::trace::TraceBundle;
use crate::xml::Cell;
use crate::xml::stream::RowReader;
use crate::xml::stream::RowReaderEvent;

#[derive(Debug, Clone, Copy)]
pub struct PcSample {
    pub pc: RuntimePc,
    pub samples: u64,
}

impl TraceBundle {
    /// Per-PC sample counts from the `time-sample` table (running-state
    /// rows only). Sorted descending by count.
    pub fn pc_samples(&self, pid: Option<Pid>) -> Result<Vec<PcSample>> {
        let xml = self
            .xctrace()
            .export_xpath(self.path(), TIME_SAMPLE_XPATH)?;
        let mut reader = RowReader::new(std::io::Cursor::new(xml));
        let mut counts: HashMap<RuntimePc, u64> = HashMap::new();
        while let Some(ev) = reader.next_event()? {
            let RowReaderEvent::Row(cells) = ev else {
                continue;
            };
            let mut sample_pid: i64 = -1;
            let mut state: Option<&str> = None;
            let mut pc: Option<RuntimePc> = None;
            for cell in &cells {
                match cell.element() {
                    Some("thread") => {
                        if let Some(pidc) = cell.find("pid") {
                            sample_pid = pidc.as_i64().unwrap_or(-1);
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
            let Some(pc) = pc else { continue };
            *counts.entry(pc).or_insert(0) += 1;
        }
        let mut out: Vec<PcSample> = counts
            .into_iter()
            .map(|(pc, samples)| PcSample { pc, samples })
            .collect();
        out.sort_by(|a, b| b.samples.cmp(&a.samples));
        Ok(out)
    }
}

const TIME_SAMPLE_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"time-sample\"]";
