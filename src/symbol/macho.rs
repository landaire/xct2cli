use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use addr2line::Loader;
use object::Object;
use object::ObjectSection;
use object::ObjectSegment;
use object::ObjectSymbol;
use object::SymbolKind;
use serde::Serialize;

use crate::error::Error;
use crate::error::Result;
use crate::trace::TraceBundle;
use crate::xml::Cell;
use crate::xml::stream::RowReader;
use crate::xml::stream::RowReaderEvent;

#[derive(Debug, Clone, Default)]
pub struct SymbolicatorOptions {
    pub binary: Option<PathBuf>,
    pub dsym: Option<PathBuf>,
    /// Subtracted from runtime PCs before lookup. Use this when the
    /// binary was loaded with ASLR offset (slide).
    pub slide: u64,
}

pub struct Symbolicator {
    loader: Option<Loader>,
    slide: u64,
    binary: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolicatedFrame {
    pub address: u64,
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub inlined: Vec<InlinedFrame>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InlinedFrame {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl Symbolicator {
    pub fn new(opts: SymbolicatorOptions) -> Result<Self> {
        let pick = opts.dsym.as_ref().or(opts.binary.as_ref()).cloned();
        let loader = match pick {
            Some(p) => Some(load(&p)?),
            None => None,
        };
        Ok(Self {
            loader,
            slide: opts.slide,
            binary: opts.binary,
        })
    }

    pub fn binary(&self) -> Option<&Path> {
        self.binary.as_deref()
    }

    pub fn slide(&self) -> u64 {
        self.slide
    }

    pub fn resolve(&self, runtime_pc: u64) -> Result<SymbolicatedFrame> {
        let mut frame = SymbolicatedFrame {
            address: runtime_pc,
            function: None,
            file: None,
            line: None,
            column: None,
            inlined: Vec::new(),
        };
        let Some(loader) = &self.loader else {
            return Ok(frame);
        };
        let Some(probe) = runtime_pc.checked_sub(self.slide) else {
            return Ok(frame);
        };

        if let Some(sym) = loader.find_symbol_info(probe) {
            frame.function = Some(demangle(sym.name()));
        }

        let mut iter = loader
            .find_frames(probe)
            .map_err(|e| Error::Addr2Line(e.to_string()))?;
        let mut innermost: Option<addr2line::Frame<'_, _>> = None;
        let mut inlined: Vec<InlinedFrame> = Vec::new();
        while let Some(f) = iter.next().map_err(|e| Error::Addr2Line(e.to_string()))? {
            if let Some(prev) = innermost.take() {
                inlined.push(InlinedFrame {
                    function: prev.function.as_ref().and_then(demangled_function),
                    file: prev
                        .location
                        .as_ref()
                        .and_then(|l| l.file.map(str::to_string)),
                    line: prev.location.as_ref().and_then(|l| l.line),
                });
            }
            innermost = Some(f);
        }
        if let Some(f) = innermost {
            if frame.function.is_none()
                && let Some(fun) = f.function.as_ref()
            {
                frame.function = demangled_function(fun);
            }
            if let Some(loc) = f.location {
                frame.file = loc.file.map(str::to_string);
                frame.line = loc.line;
                frame.column = loc.column;
            }
        }
        frame.inlined = inlined;
        Ok(frame)
    }
}

fn load(path: &Path) -> Result<Loader> {
    let resolved = resolve_dsym(path);
    Loader::new(&resolved).map_err(|e| Error::Addr2Line(e.to_string()))
}

#[derive(Debug, Clone)]
pub struct BinaryInfo {
    /// Preferred VM address of `__text` (the executable section).
    pub text_start: u64,
    pub text_end: u64,
    /// Preferred VM address of the `__TEXT` segment (i.e. of the Mach-O
    /// header). Used to convert kdebug-reported load addresses into a slide.
    pub segment_text_start: u64,
    /// Sorted ascending. Each entry is the file address of a function symbol
    /// in `__text`.
    pub function_addrs: Vec<u64>,
    /// The binary's `LC_UUID`.
    pub uuid: Option<[u8; 16]>,
}

/// Parse a Mach-O binary for the data needed to detect ASLR slide.
pub fn binary_info(binary: &Path) -> Result<BinaryInfo> {
    let data = std::fs::read(binary)?;
    let file = object::File::parse(&*data)?;
    let mut segment_text_start = u64::MAX;
    let mut segment_text_end: u64 = 0;
    for seg in file.segments() {
        if let Some(name) = seg.name()?
            && name == "__TEXT"
        {
            segment_text_start = seg.address();
            segment_text_end = segment_text_start + seg.size();
        }
    }
    let (text_start, text_end) = match file.section_by_name("__text") {
        Some(sec) => (sec.address(), sec.address() + sec.size()),
        None => (segment_text_start, segment_text_end),
    };
    if text_end <= text_start {
        return Err(Error::Schema("binary has no __TEXT segment".into()));
    }
    let mut function_addrs: Vec<u64> = file
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text)
        .map(|s| s.address())
        .filter(|a| *a >= text_start && *a < text_end)
        .collect();
    function_addrs.sort_unstable();
    function_addrs.dedup();
    let uuid = file.mach_uuid()?;
    let segment_text_start = if segment_text_start == u64::MAX {
        text_start
    } else {
        segment_text_start
    };
    Ok(BinaryInfo {
        text_start,
        text_end,
        segment_text_start,
        function_addrs,
        uuid,
    })
}

/// Read every `DBG_DYLD_UUID_MAP_A` event from the trace and decode the
/// (UUID, runtime load address) pairs. These events are kernel ground
/// truth — when dyld maps an image, the kernel records the runtime base
/// address it chose under ASLR.
///
/// Class 31 (`DBG_DYLD`), subclass 5 (`DBG_DYLD_UUID`), code 0
/// (`MAP_A`). Args 1 and 2 are the UUID's two halves as little-endian
/// `u64`s; arg 3 is the runtime load address.
pub fn read_image_loads(bundle: &TraceBundle) -> Result<Vec<ImageLoad>> {
    let xml = bundle
        .xctrace()
        .export_xpath(bundle.path(), DBG_DYLD_XPATH)?;
    let mut reader = RowReader::new(std::io::Cursor::new(xml));
    let mut out: Vec<ImageLoad> = Vec::new();
    while let Some(ev) = reader.next_event()? {
        let RowReaderEvent::Row(cells) = ev else {
            continue;
        };
        let Some(decoded) = decode_dyld_map_a(&cells) else {
            continue;
        };
        out.push(decoded);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ImageLoad {
    pub uuid: [u8; 16],
    pub load_address: u64,
}

const DBG_DYLD_XPATH: &str = "/trace-toc/run[@number=\"1\"]/data/table[@schema=\"kdebug\"]";

fn decode_dyld_map_a(cells: &[std::rc::Rc<Cell>]) -> Option<ImageLoad> {
    let mut class: Option<u64> = None;
    let mut subclass: Option<u64> = None;
    let mut code: Option<u64> = None;
    let mut args: Vec<u64> = Vec::new();
    for cell in cells {
        let Some(name) = cell.element() else { continue };
        match name {
            "kdebug-class" => class = cell.as_u64(),
            "kdebug-subclass" => subclass = cell.as_u64(),
            "kdebug-code" => code = cell.as_u64(),
            "kdebug-arg" => {
                if let Some(v) = cell.as_u64() {
                    args.push(v);
                }
            }
            _ => {}
        }
    }
    if class? != 31 || subclass? != 5 || code? != 0 {
        return None;
    }
    if args.len() < 3 {
        return None;
    }
    let mut uuid = [0u8; 16];
    uuid[0..8].copy_from_slice(&args[0].to_le_bytes());
    uuid[8..16].copy_from_slice(&args[1].to_le_bytes());
    Some(ImageLoad {
        uuid,
        load_address: args[2],
    })
}

/// Look up the slide for a Mach-O binary by matching its `LC_UUID`
/// against the trace's recorded image loads. Returns the slide as
/// `(load_address - segment_text_start)`.
pub fn slide_from_kdebug(info: &BinaryInfo, loads: &[ImageLoad]) -> Option<u64> {
    let uuid = info.uuid?;
    let load = loads.iter().find(|l| l.uuid == uuid)?;
    load.load_address.checked_sub(info.segment_text_start)
}

#[derive(Debug, Clone, Serialize)]
pub struct SlideCandidate {
    pub slide: u64,
    pub covered_samples: u64,
    pub top_function_samples: u64,
    pub top_function_address: u64,
    pub top_function_size: u64,
    pub top_function_name: Option<String>,
}

/// Enumerate plausible page-aligned ASLR slides that map the sampled PCs
/// into the binary's `__text` segment. Returns candidates sorted by a
/// heuristic ranking, but **the ranking is not authoritative** — for
/// stripped binaries or short traces multiple slides will look equally
/// plausible. The CLI surfaces this list for a human to pick from.
pub fn enumerate_slides(
    info: &BinaryInfo,
    pcs_with_weight: &[(u64, u64)],
    dwarf_path: &Path,
) -> Vec<SlideCandidate> {
    const PAGE: u64 = 0x4000;
    let resolved = resolve_dsym(dwarf_path);
    let loader = Loader::new(&resolved).ok();

    let mut candidates: HashMap<u64, ()> = HashMap::new();
    for &(pc, _) in pcs_with_weight {
        if pc < info.text_start {
            continue;
        }
        let max_slide = pc.saturating_sub(info.text_start);
        let min_slide = pc.saturating_sub(info.text_end.saturating_sub(1));
        let max_aligned = max_slide & !(PAGE - 1);
        let min_aligned = (min_slide + PAGE - 1) & !(PAGE - 1);
        let mut s = min_aligned;
        while s <= max_aligned {
            candidates.insert(s, ());
            s = match s.checked_add(PAGE) {
                Some(v) => v,
                None => break,
            };
        }
    }

    let mut out: Vec<SlideCandidate> = Vec::new();
    for slide in candidates.into_keys() {
        let mut per_func: HashMap<u64, u64> = HashMap::new();
        let mut covered: u64 = 0;
        for &(pc, w) in pcs_with_weight {
            let Some(probe) = pc.checked_sub(slide) else {
                continue;
            };
            let Some(func_start) = function_containing(&info.function_addrs, probe, info.text_end)
            else {
                continue;
            };
            *per_func.entry(func_start).or_insert(0) += w;
            covered += w;
        }
        if covered == 0 {
            continue;
        }
        let mut entries: Vec<(u64, u64)> = per_func.into_iter().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        let (top_addr, top_share) = entries[0];
        let func_len = function_length(&info.function_addrs, top_addr, info.text_end);
        let top_function_name = loader.as_ref().and_then(|l| top_function_at(l, top_addr));
        out.push(SlideCandidate {
            slide,
            covered_samples: covered,
            top_function_samples: top_share,
            top_function_address: top_addr,
            top_function_size: func_len,
            top_function_name,
        });
    }
    out.sort_by(|a, b| {
        b.top_function_samples
            .cmp(&a.top_function_samples)
            .then_with(|| a.top_function_size.cmp(&b.top_function_size))
    });
    out
}

fn top_function_at(loader: &Loader, probe: u64) -> Option<String> {
    let mut iter = loader.find_frames(probe).ok()?;
    let mut last: Option<String> = None;
    while let Ok(Some(f)) = iter.next() {
        if let Some(name) = f.function.as_ref().and_then(|n| n.raw_name().ok()) {
            last = Some(demangle(&name));
        }
    }
    last
}

fn function_containing(starts: &[u64], probe: u64, text_end: u64) -> Option<u64> {
    let i = starts.partition_point(|&s| s <= probe);
    if i == 0 {
        return None;
    }
    let func_start = starts[i - 1];
    let func_end = starts.get(i).copied().unwrap_or(text_end);
    if probe >= func_start && probe < func_end {
        Some(func_start)
    } else {
        None
    }
}

fn function_length(starts: &[u64], func_start: u64, text_end: u64) -> u64 {
    let i = starts.partition_point(|&s| s <= func_start);
    let func_end = starts.get(i).copied().unwrap_or(text_end);
    func_end.saturating_sub(func_start)
}

fn resolve_dsym(path: &Path) -> PathBuf {
    if path.extension().and_then(|s| s.to_str()) != Some("dSYM") {
        return path.to_path_buf();
    }
    let dwarf_dir = path.join("Contents").join("Resources").join("DWARF");
    let Ok(entries) = std::fs::read_dir(&dwarf_dir) else {
        return path.to_path_buf();
    };
    let mut candidates: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    if candidates.is_empty() {
        return path.to_path_buf();
    }
    candidates.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.len().try_into().or(Ok(0u64)))
            .unwrap_or(0)
    });
    candidates.pop().unwrap()
}

fn demangle(s: &str) -> String {
    if let Ok(sym) = rustc_demangle_try(s) {
        return sym;
    }
    if let Ok(sym) = cpp_demangle_try(s) {
        return sym;
    }
    s.to_string()
}

fn demangled_function<R>(f: &addr2line::FunctionName<R>) -> Option<String>
where
    R: gimli::Reader,
{
    let raw = f.raw_name().ok()?;
    Some(demangle(&raw))
}

fn rustc_demangle_try(s: &str) -> std::result::Result<String, ()> {
    Ok(format!(
        "{:#}",
        rustc_demangle::try_demangle(s).map_err(|_| ())?
    ))
}

fn cpp_demangle_try(s: &str) -> std::result::Result<String, ()> {
    let sym = cpp_demangle::Symbol::new(s).map_err(|_| ())?;
    sym.demangle().map_err(|_| ())
}
