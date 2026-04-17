use std::fmt::Write;

use crate::analysis::CallgraphReport;
use crate::analysis::CounterReport;
use crate::analysis::HotspotReport;
use crate::render::Palette;
use crate::trace::Toc;

impl Toc {
    /// Pretty-printed multi-run summary (target, processes, table list).
    pub fn to_text(&self, palette: Palette) -> String {
        let mut out = String::new();
        for run in &self.runs {
            let _ = writeln!(
                out,
                "{}",
                palette.bold().style(format!("run #{}", run.number))
            );
            if let Some(info) = &run.info.summary {
                if let Some(t) = &info.template_name {
                    let _ = writeln!(out, "  template: {t}");
                }
                if let Some(d) = &info.duration {
                    let _ = writeln!(out, "  duration: {d}s");
                }
                if let Some(s) = &info.start_date {
                    let _ = writeln!(out, "  start:    {s}");
                }
            }
            if let Some(target) = &run.info.target {
                if let (Some(name), Some(model), Some(os)) = (
                    target.device.get("name"),
                    target.device.get("model"),
                    target.device.get("os-version"),
                ) {
                    let _ = writeln!(out, "  device:   {name} ({model}, {os})");
                }
                if let Some(name) = target.process.get("name") {
                    let pid = target.process.get("pid").map(String::as_str).unwrap_or("?");
                    let _ = writeln!(
                        out,
                        "  process:  {} (pid {pid})",
                        palette.function().style(name)
                    );
                }
            }
            let _ = writeln!(out, "  processes:");
            for p in &run.processes {
                let path = p.path.as_deref().unwrap_or("");
                let _ = writeln!(
                    out,
                    "    pid {:>5}  {}  {}",
                    p.pid,
                    palette.function().style(&p.name),
                    palette.path().style(path)
                );
            }
            let _ = writeln!(out, "  tables ({}):", run.tables.len());
            for t in &run.tables {
                let _ = writeln!(out, "    {}", t.schema);
            }
        }
        out
    }
}

impl HotspotReport {
    /// Per-CPU summary, burst timeline, and top-N PC table.
    pub fn to_text(&self, palette: Palette) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "samples: {}", self.total_samples);
        let _ = writeln!(out, "{}", palette.header().style("per CPU:"));
        let cpu_max = self.per_cpu.values().map(|s| s.samples).max().unwrap_or(0);
        for (cpu, stats) in &self.per_cpu {
            let label = stats.label.as_deref().unwrap_or("");
            let intensity = if cpu_max == 0 {
                0.0
            } else {
                stats.samples as f64 / cpu_max as f64
            };
            let _ = writeln!(
                out,
                "  CPU {:>2} {:<20} {} samples",
                cpu,
                label,
                palette
                    .heat(intensity)
                    .style(format!("{:>8}", stats.samples))
            );
        }

        let _ = writeln!(
            out,
            "\n{}",
            palette.header().style(format!(
                "timeline ({}ms buckets, {} buckets):",
                self.timeline_buckets_ns / 1_000_000,
                self.timeline.len()
            ))
        );
        let cpus: Vec<crate::address::CoreId> = self.per_cpu.keys().copied().collect();
        let bucket_max = self
            .timeline
            .iter()
            .flat_map(|b| b.samples_per_cpu.values().copied())
            .max()
            .unwrap_or(0);
        let _ = write!(out, "  ms_off");
        for c in &cpus {
            let _ = write!(out, " cpu{:>2}", c);
        }
        let _ = writeln!(out);
        for bucket in &self.timeline {
            let _ = write!(out, "  {:>6}", bucket.start_ns / 1_000_000);
            for c in &cpus {
                let v = bucket.samples_per_cpu.get(c).copied().unwrap_or(0);
                let intensity = if bucket_max == 0 {
                    0.0
                } else {
                    v as f64 / bucket_max as f64
                };
                let _ = write!(
                    out,
                    " {}",
                    palette.heat(intensity).style(format!("{:>5}", v))
                );
            }
            let _ = writeln!(out);
        }

        let _ = writeln!(
            out,
            "\n{}",
            palette
                .header()
                .style(format!("top {} PCs:", self.top_pcs.len()))
        );
        let pc_max = self.top_pcs.iter().map(|h| h.samples).max().unwrap_or(0);
        for h in &self.top_pcs {
            let func = h.function.as_deref().unwrap_or("?");
            let loc = match (&h.file, h.line) {
                (Some(f), Some(l)) => format!("  {}:{}", f, l),
                (Some(f), None) => format!("  {}", f),
                _ => String::new(),
            };
            let intensity = if pc_max == 0 {
                0.0
            } else {
                h.samples as f64 / pc_max as f64
            };
            let _ = writeln!(
                out,
                "  {}  {}  {}{}",
                palette.heat(intensity).style(format!("{:>6}", h.samples)),
                palette.dim().style(h.pc),
                palette.function().style(func),
                palette.path().style(loc),
            );
        }
        out
    }
}

impl CounterReport {
    /// Per-PC counter table with metric labels.
    pub fn to_text(&self, palette: Palette) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "samples: {}", self.total_samples);
        if self.labels.is_empty() {
            let _ = writeln!(out, "metric labels: (none)");
        } else {
            let _ = writeln!(out, "{}", palette.header().style("metric labels:"));
            for (i, l) in self.labels.iter().enumerate() {
                let _ = writeln!(out, "  [{}] {}", i, l);
            }
        }
        let _ = writeln!(out);

        let _ = write!(
            out,
            "  {}  {}",
            palette.bold().style(format!("{:>5}", "smpls")),
            palette.bold().style(format!("{:<18}", "PC")),
        );
        let n_cols = self
            .per_pc
            .iter()
            .map(|r| r.values.len())
            .max()
            .unwrap_or(0);
        for i in 0..n_cols {
            let label = self.labels.get(i).map(|s| s.as_str()).unwrap_or("?");
            let short: String = label.chars().take(14).collect();
            let _ = write!(out, "  {}", palette.bold().style(format!("{:>14}", short)));
        }
        let _ = writeln!(out);
        let smp_max = self.per_pc.iter().map(|r| r.samples).max().unwrap_or(0);
        for r in &self.per_pc {
            let intensity = if smp_max == 0 {
                0.0
            } else {
                r.samples as f64 / smp_max as f64
            };
            let _ = write!(
                out,
                "  {}  {}",
                palette.heat(intensity).style(format!("{:>5}", r.samples)),
                palette.dim().style(r.pc),
            );
            for v in &r.values {
                let _ = write!(out, "  {:>14}", thousands(*v));
            }
            if let Some(func) = &r.function {
                let _ = write!(out, "  {}", palette.function().style(func));
                if let (Some(file), Some(line)) = (&r.file, r.line) {
                    let _ = write!(
                        out,
                        "  {}",
                        palette
                            .path()
                            .style(format!("{}:{}", short_path(file), line))
                    );
                }
            }
            let _ = writeln!(out);
        }
        out
    }
}

impl CallgraphReport {
    pub fn to_text(&self, palette: Palette) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{}  ({} samples)",
            palette.header().style(&self.view),
            self.total_samples,
        );
        let _ = writeln!(out);
        let max = self.stats.iter().map(|s| s.samples).max().unwrap_or(0);
        for stat in &self.stats {
            let intensity = if max == 0 {
                0.0
            } else {
                stat.samples as f64 / max as f64
            };
            let pct = stat.fraction * 100.0;
            let _ = writeln!(
                out,
                "  {}  {:>5.1}%  {}",
                palette
                    .heat(intensity)
                    .style(format!("{:>7}", stat.samples)),
                pct,
                palette.function().style(&stat.function),
            );
        }
        out
    }
}

fn short_path(p: &str) -> String {
    let pb = std::path::Path::new(p);
    let comps: Vec<_> = pb.components().collect();
    if comps.len() <= 4 {
        return p.to_string();
    }
    let kept: Vec<_> = comps.iter().rev().take(3).collect();
    let mut tail = String::new();
    for c in kept.iter().rev() {
        if !tail.is_empty() {
            tail.push('/');
        }
        tail.push_str(c.as_os_str().to_str().unwrap_or(""));
    }
    format!(".../{tail}")
}

fn thousands(v: u64) -> String {
    let s = v.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}
