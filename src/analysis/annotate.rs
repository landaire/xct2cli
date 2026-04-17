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

use crate::address::FilePc;
use crate::address::Pid;
use crate::address::RuntimePc;
use crate::analysis::SlideMode;
use crate::error::Error;
use crate::error::Result;
use crate::symbol::BinaryInfo;
use crate::symbol::Symbolicator;
use crate::symbol::SymbolicatorOptions;
use crate::trace::TraceBundle;

/// What the per-instruction `samples` field on each `AnnotatedInstruction`
/// should represent. Mutually exclusive by construction (vs the prior
/// `Option<usize>` + `Option<String>` combo where `Some + Some` was
/// representable but invalid).
#[derive(Debug, Clone, Default)]
pub enum Weight {
    /// Raw sample counts from `time-sample` (the default; works on any
    /// trace with a Time Profiler instrument).
    #[default]
    Samples,
    /// Per-PC delta sum of the counter at this index in the trace's
    /// `MetricTable` / `kdebug-counters-with-time-sample`. Requires a
    /// CPU Counters trace.
    Metric { index: usize },
    /// Per-PC PMI-overflow sample counts for the given event name
    /// (e.g. `"l1d_load_miss"`, `"PL2_CACHE_MISS_LD"`). Requires a
    /// CPU Counters trace recorded in a sampling mode.
    PmiEvent { name: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedFunction {
    pub name: String,
    pub demangled_name: String,
    pub runtime_start: RuntimePc,
    pub runtime_end: RuntimePc,
    pub file_start: FilePc,
    pub file_end: FilePc,
    pub binary: PathBuf,
    pub total_samples: u64,
    /// What the per-instruction `samples` field actually represents
    /// (e.g. `"samples"` or `"l1d_load_miss samples"`).
    pub weight_label: String,
    pub instructions: Vec<AnnotatedInstruction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedInstruction {
    pub runtime_address: RuntimePc,
    pub file_address: FilePc,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub samples: u64,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AnnotateOptions {
    pub function: String,
    pub binary: PathBuf,
    pub dsym: Option<PathBuf>,
    pub slide: SlideMode,
    pub pid: Option<Pid>,
    pub weight: Weight,
}

#[derive(Debug, Clone)]
struct FoundSymbol {
    file_addr: FilePc,
    size: u64,
    raw_name: String,
    demangled: String,
}

pub fn annotate(bundle: &TraceBundle, opts: AnnotateOptions) -> Result<AnnotatedFunction> {
    let data = std::fs::read(&opts.binary)?;
    let macho = object::File::parse(&*data)?;
    let slide = match &opts.slide {
        SlideMode::Manual(s) => *s,
        SlideMode::Auto => {
            let info = BinaryInfo::open(&opts.binary)?;
            let loads = bundle.image_loads().unwrap_or_default();
            info.slide_from(&loads).ok_or_else(|| {
                Error::Schema(
                    "could not auto-detect slide from kdebug DBG_DYLD events; pass --slide".into(),
                )
            })?
        }
    };

    let sym = find_function(&macho, &opts.function)?;

    let text = macho
        .section_by_name("__text")
        .ok_or_else(|| Error::Schema("binary has no __text section".into()))?;
    let text_data = text.data().map_err(Error::MachO)?;
    let offset_in_text = sym
        .file_addr
        .raw()
        .checked_sub(text.address())
        .ok_or_else(|| Error::Schema(format!("symbol {:?} outside __text", sym.raw_name)))?
        as usize;
    let end_in_text = offset_in_text
        .checked_add(sym.size as usize)
        .ok_or_else(|| Error::Schema("symbol size overflow".into()))?;
    if end_in_text > text_data.len() {
        return Err(Error::Schema(format!(
            "symbol {:?} extends past __text",
            sym.raw_name
        )));
    }
    let func_bytes = &text_data[offset_in_text..end_in_text];

    let runtime_start = sym.file_addr.to_runtime(slide);
    let runtime_end_file = FilePc::new(sym.file_addr.raw() + sym.size);
    let runtime_end = runtime_end_file.to_runtime(slide);

    let symbolicator = Symbolicator::new(SymbolicatorOptions {
        binary: Some(opts.binary.clone()),
        dsym: opts.dsym.clone(),
        slide,
    })?;

    let (samples_by_pc, weight_label) =
        collect_weight(bundle, &opts.weight, opts.pid, runtime_start, runtime_end)?;

    let cs = Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .build()
        .map_err(|e| Error::Addr2Line(format!("capstone init: {e}")))?;
    let insns = cs
        .disasm_all(func_bytes, sym.file_addr.raw())
        .map_err(|e| Error::Addr2Line(format!("disassemble: {e}")))?;

    let mut instructions: Vec<AnnotatedInstruction> = Vec::with_capacity(insns.len());
    let mut total_samples: u64 = 0;
    for ins in insns.iter() {
        let file_addr = FilePc::new(ins.address());
        let runtime_addr = file_addr.to_runtime(slide);
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
        name: sym.raw_name,
        demangled_name: sym.demangled,
        runtime_start,
        runtime_end,
        file_start: sym.file_addr,
        file_end: FilePc::new(sym.file_addr.raw() + sym.size),
        binary: opts.binary,
        total_samples,
        weight_label,
        instructions,
    })
}

fn collect_weight(
    bundle: &TraceBundle,
    weight: &Weight,
    pid: Option<Pid>,
    runtime_start: RuntimePc,
    runtime_end: RuntimePc,
) -> Result<(HashMap<RuntimePc, u64>, String)> {
    match weight {
        Weight::PmiEvent { name } => {
            let counts = bundle.per_pc_pmi_count(pid, name)?;
            let mut filtered: HashMap<RuntimePc, u64> = HashMap::new();
            for (pc, v) in counts {
                if pc >= runtime_start && pc < runtime_end {
                    filtered.insert(pc, v);
                }
            }
            Ok((filtered, format!("{name} samples")))
        }
        Weight::Metric { index } => {
            let labels = bundle.metric_labels().unwrap_or_default();
            let deltas = bundle.per_pc_metric_deltas(pid, *index)?;
            let mut filtered: HashMap<RuntimePc, u64> = HashMap::new();
            for (pc, v) in deltas {
                if pc >= runtime_start && pc < runtime_end {
                    filtered.insert(pc, v);
                }
            }
            let label = labels
                .get(*index)
                .cloned()
                .unwrap_or_else(|| format!("metric[{index}]"));
            Ok((filtered, label))
        }
        Weight::Samples => {
            let pc_samples = bundle.pc_samples(pid)?;
            let mut filtered: HashMap<RuntimePc, u64> = HashMap::new();
            for s in &pc_samples {
                if s.pc >= runtime_start && s.pc < runtime_end {
                    filtered.insert(s.pc, s.samples);
                }
            }
            Ok((filtered, "samples".to_string()))
        }
    }
}

fn find_function<'a>(macho: &'a object::File<'a>, needle: &str) -> Result<FoundSymbol> {
    let mut text_syms: Vec<(u64, &'a str)> = macho
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
    let mut best: Option<(usize, &'a str, String)> = None;
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
    Ok(FoundSymbol {
        file_addr: FilePc::new(addr),
        size,
        raw_name: raw.to_string(),
        demangled: dem,
    })
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
