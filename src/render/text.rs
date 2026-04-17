use std::fmt::Write;

use crate::analysis::CounterReport;
use crate::analysis::HotspotReport;
use crate::trace::Toc;

pub fn render_toc(toc: &Toc) -> String {
    let mut out = String::new();
    for run in &toc.runs {
        let _ = writeln!(out, "run #{}", run.number);
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
                let _ = writeln!(out, "  process:  {name} (pid {pid})");
            }
        }
        let _ = writeln!(out, "  processes:");
        for p in &run.processes {
            let path = p.path.as_deref().unwrap_or("");
            let _ = writeln!(out, "    pid {:>5}  {}  {}", p.pid, p.name, path);
        }
        let _ = writeln!(out, "  tables ({}):", run.tables.len());
        for t in &run.tables {
            let _ = writeln!(out, "    {}", t.schema);
        }
    }
    out
}

pub fn render_hotspots(report: &HotspotReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "samples: {}", report.total_samples);
    let _ = writeln!(out, "per CPU:");
    for (cpu, stats) in &report.per_cpu {
        let label = stats.label.as_deref().unwrap_or("");
        let _ = writeln!(
            out,
            "  CPU {:>2} {:<20} {:>8} samples",
            cpu, label, stats.samples
        );
    }

    let _ = writeln!(
        out,
        "\ntimeline ({}ms buckets, {} buckets):",
        report.timeline_buckets_ns / 1_000_000,
        report.timeline.len()
    );
    let cpus: Vec<u32> = report.per_cpu.keys().copied().collect();
    let _ = write!(out, "  ms_off");
    for c in &cpus {
        let _ = write!(out, " cpu{:>2}", c);
    }
    let _ = writeln!(out);
    for bucket in &report.timeline {
        let _ = write!(out, "  {:>6}", bucket.start_ns / 1_000_000);
        for c in &cpus {
            let v = bucket.samples_per_cpu.get(c).copied().unwrap_or(0);
            let _ = write!(out, " {:>5}", v);
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "\ntop {} PCs:", report.top_pcs.len());
    for h in &report.top_pcs {
        let func = h.function.as_deref().unwrap_or("?");
        let loc = match (&h.file, h.line) {
            (Some(f), Some(l)) => format!("  {}:{}", f, l),
            (Some(f), None) => format!("  {}", f),
            _ => String::new(),
        };
        let _ = writeln!(out, "  {:>6}  0x{:016x}  {}{}", h.samples, h.pc, func, loc);
    }
    out
}

pub fn render_counters(report: &CounterReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "samples: {}", report.total_samples);
    if report.labels.is_empty() {
        let _ = writeln!(out, "metric labels: (none)");
    } else {
        let _ = writeln!(out, "metric labels:");
        for (i, l) in report.labels.iter().enumerate() {
            let _ = writeln!(out, "  [{}] {}", i, l);
        }
    }
    let _ = writeln!(out);

    let _ = write!(out, "  {:>5}  {:<18}", "smpls", "PC");
    let n_cols = report
        .per_pc
        .iter()
        .map(|r| r.values.len())
        .max()
        .unwrap_or(0);
    for i in 0..n_cols {
        let label = report.labels.get(i).map(|s| s.as_str()).unwrap_or("?");
        let short: String = label.chars().take(14).collect();
        let _ = write!(out, "  {:>14}", short);
    }
    let _ = writeln!(out);
    for r in &report.per_pc {
        let _ = write!(out, "  {:>5}  0x{:014x}", r.samples, r.pc);
        for v in &r.values {
            let _ = write!(out, "  {:>14}", thousands(*v));
        }
        if let Some(func) = &r.function {
            let _ = write!(out, "  {}", func);
            if let (Some(file), Some(line)) = (&r.file, r.line) {
                let _ = write!(out, "  {}:{}", short_path(file), line);
            }
        }
        let _ = writeln!(out);
    }
    out
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
