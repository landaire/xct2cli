//! Per-instruction annotation: disassemble a function and attach source lines + samples.

use std::collections::HashMap;
use std::path::PathBuf;

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use capstone::arch::DetailsArchInsn;
use capstone::arch::arm64::Arm64OperandType;
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
use crate::symbol::InlinedFrame;
use crate::symbol::Symbolicator;
use crate::symbol::SymbolicatorOptions;
use crate::trace::TraceBundle;

/// What the per-instruction `samples` field represents. Variants are
/// mutually exclusive; this replaces a prior `(Option<usize>, Option<String>)`
/// shape where `Some + Some` was representable but invalid.
#[derive(Debug, Clone, Default)]
pub enum Weight {
    /// Time-sample counts. Works on any trace with Time Profiler.
    #[default]
    Samples,
    /// Per-CPU delta sum of `MetricTable[index]`. Requires a CPU
    /// Counters trace.
    Metric { index: usize },
    /// PMI-overflow sample count for the given event (e.g.
    /// `l1d_load_miss`, `PL2_CACHE_MISS_LD`). Requires a CPU Counters
    /// trace recorded in a sampling mode.
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
    /// Human-readable name for what `samples` counts.
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
    /// Innermost (deepest-inlined) source location.
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    /// Innermost function name; may be inlined.
    pub function: Option<String>,
    /// Outer call sites that inlined this code, closest-out first.
    pub inlined_into: Vec<InlinedFrame>,
    /// PC of a recent load whose write feeds a register this instruction
    /// reads. Heuristic — Apple Silicon OoO can stall on a different load
    /// than the most-recent producer, but for memory-bound code this is
    /// usually the right one. Explains why ALU ops show hot when the
    /// actual miss is two instructions upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stalled_on: Option<RuntimePc>,
    /// Resolved branch target, when within this function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_target_loc: Option<(String, u32)>,
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
        .detail(true)
        .build()
        .map_err(|e| Error::Addr2Line(format!("capstone init: {e}")))?;
    let insns = cs
        .disasm_all(func_bytes, sym.file_addr.raw())
        .map_err(|e| Error::Addr2Line(format!("disassemble: {e}")))?;

    let mut reads: Vec<Vec<u16>> = Vec::with_capacity(insns.len());
    let mut writes: Vec<Vec<u16>> = Vec::with_capacity(insns.len());
    let mut branch_targets: Vec<Option<RuntimePc>> = Vec::with_capacity(insns.len());

    let mut instructions: Vec<AnnotatedInstruction> = Vec::with_capacity(insns.len());
    let mut total_samples: u64 = 0;

    for ins in insns.iter() {
        let detail = cs.insn_detail(ins).ok();
        let (rs, ws) = detail
            .as_ref()
            .map(|d| {
                (
                    d.regs_read().iter().map(|r| r.0).collect::<Vec<_>>(),
                    d.regs_write().iter().map(|r| r.0).collect::<Vec<_>>(),
                )
            })
            .unwrap_or_default();
        reads.push(rs);
        writes.push(ws);
        let mnemonic = ins.mnemonic().unwrap_or("").to_string();
        let target = if is_branch(&mnemonic) {
            detail
                .as_ref()
                .and_then(|d| extract_branch_target(d, slide))
        } else {
            None
        };
        branch_targets.push(target);

        let file_addr = FilePc::new(ins.address());
        let runtime_addr = file_addr.to_runtime(slide);
        let frame = symbolicator.resolve(runtime_addr).ok();
        let samples = samples_by_pc.get(&runtime_addr).copied().unwrap_or(0);
        total_samples += samples;
        instructions.push(AnnotatedInstruction {
            runtime_address: runtime_addr,
            file_address: file_addr,
            bytes: ins.bytes().to_vec(),
            mnemonic,
            operands: ins.op_str().unwrap_or("").to_string(),
            samples,
            file: frame.as_ref().and_then(|f| f.file.clone()),
            line: frame.as_ref().and_then(|f| f.line),
            column: frame.as_ref().and_then(|f| f.column),
            function: frame.as_ref().and_then(|f| f.function.clone()),
            inlined_into: frame
                .as_ref()
                .map(|f| f.inlined_into.clone())
                .unwrap_or_default(),
            stalled_on: None,
            branch_target_loc: None,
        });
    }

    // ARM64 OoO cores can have many in-flight uops; 8 is a coarse but
    // useful "recently produced" window. Larger and we tag too many
    // unrelated dependencies; smaller and we miss real stalls.
    const STALL_WINDOW: usize = 8;
    for i in 0..instructions.len() {
        if is_load(&instructions[i].mnemonic) {
            continue;
        }
        if reads[i].is_empty() {
            continue;
        }
        let lo = i.saturating_sub(STALL_WINDOW);
        for j in (lo..i).rev() {
            if !is_load(&instructions[j].mnemonic) {
                continue;
            }
            if writes[j].iter().any(|w| reads[i].contains(w)) {
                instructions[i].stalled_on = Some(instructions[j].runtime_address);
                break;
            }
        }
    }

    let mut pc_to_loc: HashMap<RuntimePc, (String, u32)> = HashMap::new();
    for ins in &instructions {
        if let (Some(f), Some(l)) = (&ins.file, ins.line) {
            pc_to_loc.insert(ins.runtime_address, (f.clone(), l));
        }
    }
    for (i, ins) in instructions.iter_mut().enumerate() {
        if let Some(target) = branch_targets[i]
            && let Some(loc) = pc_to_loc.get(&target)
        {
            ins.branch_target_loc = Some(loc.clone());
        }
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

/// Prefix match catches the whole `ld`-family (ldr/ldp/ldur/ldrb/...).
fn is_load(mnemonic: &str) -> bool {
    mnemonic.starts_with("ld")
}

fn is_branch(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "b" | "bl" | "br" | "blr" | "cbz" | "cbnz" | "tbz" | "tbnz" | "ret"
    ) || mnemonic.starts_with("b.")
}

/// Returns `None` for register-indirect branches (`br`, `blr`, `ret`).
fn extract_branch_target(
    detail: &capstone::InsnDetail<'_>,
    slide: crate::address::Slide,
) -> Option<RuntimePc> {
    let arch = detail.arch_detail();
    let arm64 = arch.arm64()?;
    for op in arm64.operands() {
        if let Arm64OperandType::Imm(addr) = op.op_type
            && addr >= 0
        {
            return Some(FilePc::new(addr as u64).to_runtime(slide));
        }
    }
    None
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
