//! Per-instruction annotation: disassemble a function and attach source lines + samples.

use std::collections::HashMap;
use std::path::PathBuf;

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use object::Object;
use object::ObjectSection;
use object::ObjectSegment;
use object::ObjectSymbol;
use object::SymbolKind;
use serde::Serialize;

use crate::analysis::collect_pc_samples;
use crate::analysis::metric_labels;
use crate::analysis::per_pc_metric_deltas;
use crate::analysis::per_pc_pmi_count;
use crate::error::Error;
use crate::error::Result;
use crate::symbol::Symbolicator;
use crate::symbol::SymbolicatorOptions;
use crate::symbol::binary_info;
use crate::symbol::read_image_loads;
use crate::symbol::slide_from_kdebug;
use crate::trace::TraceBundle;

#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedFunction {
    pub name: String,
    pub demangled_name: String,
    pub runtime_start: u64,
    pub runtime_end: u64,
    pub file_start: u64,
    pub file_end: u64,
    pub binary: PathBuf,
    pub total_samples: u64,
    /// What the per-instruction `.samples` field actually represents,
    /// e.g. `"samples"` or `"Instruction Processing Bottleneck"`.
    pub weight_label: String,
    pub instructions: Vec<AnnotatedInstruction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedInstruction {
    pub runtime_address: u64,
    pub file_address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub samples: u64,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

pub struct AnnotateOptions {
    pub function: String,
    pub binary: PathBuf,
    pub dsym: Option<PathBuf>,
    /// `None` means auto-detect from kdebug DBG_DYLD events.
    pub slide: Option<u64>,
    pub pid: Option<i64>,
    /// When `Some(idx)`, use the counter at that index from
    /// `kdebug-counters-with-time-sample` (per-CPU deltas summed per PC)
    /// instead of raw sample counts. Requires a CPU Counters trace.
    pub metric: Option<usize>,
    /// When `Some(name)`, count PMI-overflow samples (one per cache miss
    /// or other PMU event) from `SamplingModeSamples` filtered by the
    /// given `pmi-event` name (e.g. `"l1d_load_miss"`). Requires a
    /// CPU Counters trace recorded in a sampling mode (e.g. L1D Miss).
    pub event: Option<String>,
}

pub fn annotate(bundle: &TraceBundle, opts: AnnotateOptions) -> Result<AnnotatedFunction> {
    let data = std::fs::read(&opts.binary)?;
    let macho = object::File::parse(&*data)?;
    let slide = match opts.slide {
        Some(s) => s,
        None => {
            let info = binary_info(&opts.binary)?;
            let loads = read_image_loads(bundle).unwrap_or_default();
            slide_from_kdebug(&info, &loads).ok_or_else(|| {
                Error::Schema(
                    "could not auto-detect slide from kdebug DBG_DYLD events; pass --slide".into(),
                )
            })?
        }
    };

    let (sym_addr, sym_size, raw_name, demangled) = find_function(&macho, &opts.function)?;

    let text = macho
        .section_by_name("__text")
        .ok_or_else(|| Error::Schema("binary has no __text section".into()))?;
    let text_addr = text.address();
    let text_data = text.data().map_err(Error::MachO)?;
    let _ = text_addr;
    let offset_in_text = sym_addr
        .checked_sub(text.address())
        .ok_or_else(|| Error::Schema(format!("symbol {raw_name:?} outside __text")))?
        as usize;
    let end_in_text = offset_in_text
        .checked_add(sym_size as usize)
        .ok_or_else(|| Error::Schema("symbol size overflow".into()))?;
    if end_in_text > text_data.len() {
        return Err(Error::Schema(format!(
            "symbol {raw_name:?} extends past __text"
        )));
    }
    let func_bytes = &text_data[offset_in_text..end_in_text];

    let runtime_start = sym_addr.wrapping_add(slide);
    let runtime_end = runtime_start + sym_size;

    let symbolicator = Symbolicator::new(SymbolicatorOptions {
        binary: Some(opts.binary.clone()),
        dsym: opts.dsym.clone(),
        slide,
    })?;

    let (samples_by_pc, weight_label) = if let Some(event) = &opts.event {
        let counts = per_pc_pmi_count(bundle, opts.pid, event)?;
        let mut filtered: HashMap<u64, u64> = HashMap::new();
        for (pc, v) in counts {
            if pc >= runtime_start && pc < runtime_end {
                filtered.insert(pc, v);
            }
        }
        (filtered, format!("{event} samples"))
    } else if let Some(idx) = opts.metric {
        let labels = metric_labels(bundle).unwrap_or_default();
        let deltas = per_pc_metric_deltas(bundle, opts.pid, idx)?;
        let mut filtered: HashMap<u64, u64> = HashMap::new();
        for (pc, v) in deltas {
            if pc >= runtime_start && pc < runtime_end {
                filtered.insert(pc, v);
            }
        }
        let label = labels
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("metric[{idx}]"));
        (filtered, label)
    } else {
        let pc_samples = collect_pc_samples(bundle, opts.pid)?;
        let mut filtered: HashMap<u64, u64> = HashMap::new();
        for s in &pc_samples {
            if s.pc >= runtime_start && s.pc < runtime_end {
                filtered.insert(s.pc, s.samples);
            }
        }
        (filtered, "samples".to_string())
    };

    let cs = Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .build()
        .map_err(|e| Error::Addr2Line(format!("capstone init: {e}")))?;
    let insns = cs
        .disasm_all(func_bytes, sym_addr)
        .map_err(|e| Error::Addr2Line(format!("disassemble: {e}")))?;

    let mut instructions: Vec<AnnotatedInstruction> = Vec::with_capacity(insns.len());
    let mut total_samples: u64 = 0;
    for ins in insns.iter() {
        let file_addr = ins.address();
        let runtime_addr = file_addr.wrapping_add(slide);
        let frame = symbolicator.resolve(runtime_addr).ok();
        let samples = samples_by_pc.get(&runtime_addr).copied().unwrap_or(0);
        total_samples += samples;
        instructions.push(AnnotatedInstruction {
            runtime_address: runtime_addr,
            file_address: file_addr,
            bytes: ins.bytes().to_vec(),
            mnemonic: ins.mnemonic().unwrap_or("").to_string(),
            operands: ins.op_str().unwrap_or("").to_string(),
            samples,
            file: frame.as_ref().and_then(|f| f.file.clone()),
            line: frame.as_ref().and_then(|f| f.line),
            column: frame.as_ref().and_then(|f| f.column),
        });
    }

    Ok(AnnotatedFunction {
        name: raw_name,
        demangled_name: demangled,
        runtime_start,
        runtime_end,
        file_start: sym_addr,
        file_end: sym_addr + sym_size,
        binary: opts.binary,
        total_samples,
        weight_label,
        instructions,
    })
}

fn find_function<'a>(
    macho: &'a object::File<'a>,
    needle: &str,
) -> Result<(u64, u64, String, String)> {
    let mut text_syms: Vec<(u64, &str)> = macho
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text)
        .filter_map(|s| s.name().ok().map(|n| (s.address(), n)))
        .collect();
    text_syms.sort_by_key(|(a, _)| *a);

    let text_end = macho
        .segments()
        .filter_map(|s| {
            s.name()
                .ok()
                .flatten()
                .map(|n| (n.to_string(), s.address() + s.size()))
        })
        .find(|(n, _)| n == "__TEXT")
        .map(|(_, e)| e)
        .unwrap_or(u64::MAX);

    let needle_lower = needle.to_lowercase();
    let mut best: Option<(usize, &str, String)> = None;
    for (idx, (_, raw)) in text_syms.iter().enumerate() {
        let dem = demangle_name(raw);
        let matches_full = dem == needle || raw == &needle;
        let matches_partial = dem.contains(needle) || dem.to_lowercase().contains(&needle_lower);
        if matches_full {
            best = Some((idx, raw, dem));
            break;
        }
        if matches_partial && best.is_none() {
            best = Some((idx, raw, dem));
        }
    }
    let (idx, raw, dem) = best.ok_or_else(|| {
        Error::Schema(format!(
            "no Mach-O Text symbol matches function name {needle:?}"
        ))
    })?;
    let (addr, _) = text_syms[idx];
    let next_addr = text_syms.get(idx + 1).map(|(a, _)| *a).unwrap_or(text_end);
    let size = next_addr.saturating_sub(addr);
    Ok((addr, size, raw.to_string(), dem))
}

fn demangle_name(s: &str) -> String {
    let stripped = s.strip_prefix('_').unwrap_or(s);
    if let Ok(d) = rustc_demangle::try_demangle(stripped) {
        return format!("{:#}", d);
    }
    if let Ok(sym) = cpp_demangle::Symbol::new(s)
        && let Ok(out) = sym.demangle()
    {
        return out;
    }
    s.to_string()
}
