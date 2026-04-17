use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;

use annotate_snippets::AnnotationKind;
use annotate_snippets::Group;
use annotate_snippets::Level;
use annotate_snippets::Renderer;
use annotate_snippets::Snippet;
use owo_colors::Style;

use crate::analysis::AnnotatedFunction;
use crate::error::Result;
use crate::render::Palette;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotateMode {
    /// Per-instruction overlay (asm-first), with the source-snippet block.
    Instructions,
    /// Just the source-snippet block (annotate-snippets) showing hot lines.
    Source,
    /// Source line headers with their disassembly grouped underneath.
    Interleaved,
}

pub struct AnnotateRenderOptions {
    pub show_zero: bool,
    pub source_root: Option<PathBuf>,
    pub mode: AnnotateMode,
    pub colored: bool,
    /// Source-snippet context. Hot lines within `2 * context` of each
    /// other share one snippet; further apart, they split.
    pub context: u32,
    /// When `Some`, use this value as the bar-scale denominator instead
    /// of the function-local max. Pass the trace-wide max for the
    /// chosen weight so bars are comparable across `annotate` runs on
    /// different functions in the same trace.
    pub bar_scale_max: Option<u64>,
}

impl AnnotatedFunction {
    pub fn render(&self, opts: &AnnotateRenderOptions) -> Result<String> {
        match opts.mode {
            AnnotateMode::Instructions => render_instructions(self, opts),
            AnnotateMode::Source => render_source_only(self, opts),
            AnnotateMode::Interleaved => render_interleaved(self, opts),
        }
    }
}

fn render_instructions(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    let mut out = String::new();
    write_header(&mut out, func, opts);
    let pal = Palette::new(opts.colored);
    let hot_colors = build_hot_line_colors(func, pal);
    let producer_colors = build_producer_colors(func, pal, opts.show_zero);

    let max_samples = opts.bar_scale_max.unwrap_or_else(|| {
        func.instructions
            .iter()
            .map(|i| i.samples)
            .max()
            .unwrap_or(0)
    });
    let mut prev_pc: Option<crate::address::RuntimePc> = None;
    for ins in &func.instructions {
        if ins.samples == 0 && !opts.show_zero {
            continue;
        }
        if let Some(prev) = prev_pc
            && ins.runtime_address.raw() != prev.raw() + 4
        {
            let _ = writeln!(out, "  {}", pal.dim().style("..."));
        }
        prev_pc = Some(ins.runtime_address);
        let intensity = intensity(ins.samples, max_samples);
        let bar = bar_str(ins.samples, max_samples);
        let loc = match (&ins.file, ins.line) {
            (Some(f), Some(l)) => {
                let marker = hot_colors.get(&(f.clone(), l)).copied();
                let line_part = match marker {
                    Some(style) => format!("{}", style.style(format!(":{}", l))),
                    None => format!("{}", pal.path().style(format!(":{}", l))),
                };
                format!(
                    "  {} {}{}",
                    pal.path().style("//"),
                    pal.path().style(short_path(f)),
                    line_part
                )
            }
            _ => String::new(),
        };
        let extra = annotation_suffix(ins, &pal, &producer_colors);
        let heat = pal.heat(intensity);
        let pc_str = format!("0x{:012x}", ins.runtime_address.raw());
        let pc_styled = match producer_colors.get(&ins.runtime_address) {
            Some(style) => format!("{}", style.style(pc_str)),
            None => pc_str,
        };
        let _ = writeln!(
            out,
            "  {}  {}  {}  {} {}{}{}",
            heat.style(format!("{:>5}", ins.samples)),
            heat.style(format!("{:<10}", bar)),
            pc_styled,
            ins.mnemonic,
            ins.operands,
            loc,
            extra,
        );
    }

    let _ = writeln!(
        out,
        "\n{}",
        pal.header()
            .style(format!("source hot-spots ({}):", func.weight_label))
    );
    write_source_blocks(&mut out, func, opts, &hot_colors);
    Ok(out)
}

fn render_source_only(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    let mut out = String::new();
    write_header(&mut out, func, opts);
    let pal = Palette::new(opts.colored);
    let hot_colors = build_hot_line_colors(func, pal);
    write_source_blocks(&mut out, func, opts, &hot_colors);
    Ok(out)
}

fn render_interleaved(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    let mut out = String::new();
    write_header(&mut out, func, opts);
    let pal = Palette::new(opts.colored);
    let producer_colors = build_producer_colors(func, pal, opts.show_zero);

    let max_samples = opts.bar_scale_max.unwrap_or_else(|| {
        func.instructions
            .iter()
            .map(|i| i.samples)
            .max()
            .unwrap_or(0)
    });
    let mut source_cache: BTreeMap<String, Option<String>> = BTreeMap::new();

    let groups = group_consecutive_by_source(&func.instructions);
    for group in groups {
        let total: u64 = group.instructions.iter().map(|i| i.samples).sum();
        if total == 0 && !opts.show_zero {
            continue;
        }
        let group_intensity = intensity(total, max_samples);
        let stats = pal.heat(group_intensity).style(format!(
            "[{} {} / {} insns]",
            total,
            func.weight_label,
            group.instructions.len(),
        ));
        let inlined_label = group_inlined_label(&group);

        match (&group.file, group.line) {
            (Some(f), Some(l)) => {
                let loc = pal.path().style(format!("{}:{}", short_path(f), l));
                let func_part = group
                    .function
                    .as_deref()
                    .map(|fn_name| format!("  {}", pal.function().style(fn_name)))
                    .unwrap_or_default();
                let inline_part = inlined_label
                    .as_deref()
                    .map(|s| format!("    {}", pal.dim().style(s)))
                    .unwrap_or_default();
                let _ = writeln!(out, "{stats}{func_part}  {loc}{inline_part}");
            }
            _ => {
                let inline_part = inlined_label
                    .as_deref()
                    .map(|s| format!("    {}", pal.dim().style(s)))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "{stats}  {}{inline_part}",
                    pal.dim().style("(no source mapping)")
                );
            }
        }

        if let (Some(f), Some(l)) = (&group.file, group.line) {
            let text = source_cache
                .entry(f.clone())
                .or_insert_with(|| read_source(f, opts.source_root.as_deref()));
            if let Some(src) = text.as_deref().and_then(|t| nth_line(t, l)) {
                let _ = writeln!(out, "    {}", src.trim());
            }
        }

        let mut prev_pc: Option<crate::address::RuntimePc> = None;
        for ins in group.instructions {
            if ins.samples == 0 && !opts.show_zero {
                continue;
            }
            if let Some(prev) = prev_pc
                && ins.runtime_address.raw() != prev.raw() + 4
            {
                let _ = writeln!(out, "        {}", pal.dim().style("..."));
            }
            prev_pc = Some(ins.runtime_address);
            let intensity = intensity(ins.samples, max_samples);
            let bar = bar_str(ins.samples, max_samples);
            let heat = pal.heat(intensity);
            let extra = annotation_suffix(ins, &pal, &producer_colors);
            let pc_str = format!("0x{:012x}", ins.runtime_address.raw());
            let pc_styled = match producer_colors.get(&ins.runtime_address) {
                Some(style) => format!("{}", style.style(pc_str)),
                None => pc_str,
            };
            let _ = writeln!(
                out,
                "        {}  {}  {}  {} {}{}",
                heat.style(format!("{:>5}", ins.samples)),
                heat.style(format!("{:<10}", bar)),
                pc_styled,
                ins.mnemonic,
                ins.operands,
                extra,
            );
        }
        let _ = writeln!(out);
    }
    Ok(out)
}

fn write_header(out: &mut String, func: &AnnotatedFunction, opts: &AnnotateRenderOptions) {
    let pal = Palette::new(opts.colored);
    let _ = writeln!(
        out,
        "function: {} ({} {} in window, {} bytes)",
        pal.function().style(&func.demangled_name),
        func.total_samples,
        func.weight_label,
        func.runtime_end.raw() - func.runtime_start.raw()
    );
    let _ = writeln!(
        out,
        "  binary:  {}",
        pal.path().style(func.binary.display())
    );
    let _ = writeln!(
        out,
        "  runtime: {}   file: {}\n",
        pal.dim().style(format!(
            "0x{:x}..0x{:x}",
            func.runtime_start, func.runtime_end
        )),
        pal.dim()
            .style(format!("0x{:x}..0x{:x}", func.file_start, func.file_end)),
    );
}

fn annotation_suffix(
    ins: &crate::analysis::AnnotatedInstruction,
    pal: &Palette,
    producer_colors: &HashMap<crate::address::RuntimePc, Style>,
) -> String {
    let mut out = String::new();
    if let Some(target_pc) = ins.stalled_on {
        let pc_text = format!("0x{:x}", target_pc.raw());
        let pc_styled = match producer_colors.get(&target_pc) {
            Some(style) => format!("{}", style.style(pc_text)),
            None => pc_text,
        };
        out.push_str("  ");
        out.push_str(&format!("{}", pal.dim().style("[stalled on @ ")));
        out.push_str(&pc_styled);
        out.push_str(&format!("{}", pal.dim().style("]")));
    }
    if let Some((file, line)) = &ins.branch_target_loc {
        out.push_str("  ");
        out.push_str(&format!(
            "{}",
            pal.dim().style(format!(
                "[→ {}:{}]",
                super::annotate::short_path(file),
                line
            ))
        ));
    }
    out
}

/// Color map for stall-producer PCs: any load referenced by a
/// *visible* consumer's `stalled_on`. Filtering by visibility avoids
/// painting a producer whose only reference was a hidden 0-sample
/// instruction (yields an orphaned colored address with no matching
/// `[stalled on @ ...]` annotation anywhere on screen).
fn build_producer_colors(
    func: &AnnotatedFunction,
    pal: Palette,
    show_zero: bool,
) -> HashMap<crate::address::RuntimePc, Style> {
    use std::collections::BTreeSet;
    let producers: BTreeSet<crate::address::RuntimePc> = func
        .instructions
        .iter()
        .filter(|i| show_zero || i.samples > 0)
        .filter_map(|i| i.stalled_on)
        .collect();
    producers
        .into_iter()
        .enumerate()
        .map(|(idx, pc)| (pc, pal.line_marker(idx)))
        .collect()
}

fn intensity(value: u64, max: u64) -> f64 {
    if max == 0 {
        return 0.0;
    }
    value as f64 / max as f64
}

fn bar_str(value: u64, max: u64) -> String {
    if max == 0 {
        return String::new();
    }
    let n = (value as f64 / max as f64 * 10.0).round() as usize;
    "#".repeat(n)
}

fn write_source_blocks(
    out: &mut String,
    func: &AnnotatedFunction,
    opts: &AnnotateRenderOptions,
    hot_colors: &HashMap<(String, u32), Style>,
) {
    let blocks = group_by_source(func);
    let renderer = if opts.colored {
        Renderer::styled()
    } else {
        Renderer::plain()
    };
    let context = opts.context.max(1);
    let cluster_gap = context.saturating_mul(2);
    for (file, lines) in blocks {
        let Some(text) = read_source(&file, opts.source_root.as_deref()) else {
            let _ = writeln!(out, "  (source unavailable: {file})");
            continue;
        };
        let max_samples = lines.iter().map(|(_, s)| *s).max().unwrap_or(0);
        for cluster in cluster_hot_lines(&lines, cluster_gap) {
            let min_line = cluster.first().map(|(l, _)| *l).unwrap_or(1);
            let max_line = cluster.last().map(|(l, _)| *l).unwrap_or(1);
            let display_start = min_line.saturating_sub(context).max(1);
            let display_end = max_line + context;
            let Some(display_text) = take_lines(&text, display_start, display_end) else {
                continue;
            };
            let display_text = dedent_block(display_text);
            let display_text_static: &'static str = Box::leak(display_text.into_boxed_str());

            let mut snippet = Snippet::source(display_text_static)
                .path(string_static(&file))
                .line_start(display_start as usize)
                .fold(false);
            for (line, samples) in &cluster {
                let Some(span) = line_byte_range(display_text_static, *line, display_start) else {
                    continue;
                };
                let marker = hot_colors.get(&(file.clone(), *line)).copied();
                let line_tag = match marker {
                    Some(style) => format!("{}", style.style(format!(":{}", line))),
                    None => format!(":{}", line),
                };
                let label = format!("{}  {} {}", line_tag, samples, func.weight_label);
                let kind = if max_samples > 0 && samples * 2 >= max_samples {
                    AnnotationKind::Primary
                } else {
                    AnnotationKind::Context
                };
                snippet = snippet.annotation(kind.span(span).label(string_static(&label)));
            }

            let title = format!("hot lines in {}", short_path(&file));
            let group = Group::with_title(Level::NOTE.primary_title(string_static(&title)))
                .element(snippet);
            let _ = writeln!(out, "{}", renderer.render(&[group]));
            let _ = writeln!(out);
        }
    }
}

/// Stable (file, line) -> color map shared by the asm overlay and the
/// source snippet so identical lines render in the same color in both.
fn build_hot_line_colors(func: &AnnotatedFunction, pal: Palette) -> HashMap<(String, u32), Style> {
    let mut out: HashMap<(String, u32), Style> = HashMap::new();
    let mut idx = 0usize;
    for (file, lines) in group_by_source(func) {
        let mut sorted: Vec<u32> = lines.iter().map(|(l, _)| *l).collect();
        sorted.sort();
        sorted.dedup();
        for line in sorted {
            out.insert((file.clone(), line), pal.line_marker(idx));
            idx += 1;
        }
    }
    out
}

/// Splits hot lines into clusters separated by gaps > `max_gap`. Without
/// this a function with hot lines at e.g. line 38 and line 278 would
/// dump 240 lines of unrelated source into one snippet.
fn cluster_hot_lines(lines: &[(u32, u64)], max_gap: u32) -> Vec<Vec<(u32, u64)>> {
    let mut sorted = lines.to_vec();
    sorted.sort_by_key(|(l, _)| *l);
    let mut clusters: Vec<Vec<(u32, u64)>> = Vec::new();
    for entry in sorted {
        match clusters.last_mut() {
            Some(c) if entry.0.saturating_sub(c.last().unwrap().0) <= max_gap => {
                c.push(entry);
            }
            _ => clusters.push(vec![entry]),
        }
    }
    clusters
}

/// Strips the first non-empty line's leading whitespace uniformly from
/// every line, so deeply-indented Rust code starts at column 0 while
/// inner blocks keep their relative indent.
fn dedent_block(text: &str) -> String {
    let indent = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .unwrap_or(0);
    if indent == 0 {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut first = true;
    for line in text.lines() {
        if !first {
            out.push('\n');
        }
        first = false;
        let leading = line.len() - line.trim_start().len();
        if leading >= indent {
            out.push_str(&line[indent..]);
        } else {
            out.push_str(line.trim_start());
        }
    }
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

struct InstructionGroup<'a> {
    file: Option<String>,
    line: Option<u32>,
    function: Option<String>,
    instructions: Vec<&'a crate::analysis::AnnotatedInstruction>,
}

fn group_consecutive_by_source(
    insns: &[crate::analysis::AnnotatedInstruction],
) -> Vec<InstructionGroup<'_>> {
    let mut out: Vec<InstructionGroup<'_>> = Vec::new();
    for ins in insns {
        let key = (ins.file.clone(), ins.line, ins.function.clone());
        match out.last_mut() {
            Some(last) if (last.file.clone(), last.line, last.function.clone()) == key => {
                last.instructions.push(ins);
            }
            _ => out.push(InstructionGroup {
                file: key.0,
                line: key.1,
                function: key.2,
                instructions: vec![ins],
            }),
        }
    }
    out
}

/// Builds the `inlined into <fn> at <file>:<line>` suffix using the
/// innermost outer call site (most useful "where this came from").
fn group_inlined_label(group: &InstructionGroup<'_>) -> Option<String> {
    let first = group.instructions.first()?;
    let outer = first.inlined_into.first()?;
    let func = outer.function.as_deref()?;
    let func_short = func.rsplit("::").next().unwrap_or(func);
    match (outer.file.as_deref(), outer.line) {
        (Some(file), Some(line)) => Some(format!(
            "inlined into {} at {}:{}",
            func,
            short_path(file),
            line
        )),
        _ => Some(format!("inlined into {}", func_short)),
    }
}

fn nth_line(text: &str, n: u32) -> Option<&str> {
    text.lines().nth(n.saturating_sub(1) as usize)
}

fn group_by_source(func: &AnnotatedFunction) -> Vec<(String, Vec<(u32, u64)>)> {
    let mut by_file: BTreeMap<String, BTreeMap<u32, u64>> = BTreeMap::new();
    for ins in &func.instructions {
        let (Some(file), Some(line)) = (&ins.file, ins.line) else {
            continue;
        };
        if ins.samples == 0 {
            continue;
        }
        *by_file
            .entry(file.clone())
            .or_default()
            .entry(line)
            .or_insert(0) += ins.samples;
    }
    by_file
        .into_iter()
        .map(|(f, m)| (f, m.into_iter().collect()))
        .collect()
}

fn take_lines(text: &str, start: u32, end: u32) -> Option<&str> {
    let mut byte_start: Option<usize> = None;
    let mut byte_end = text.len();
    let mut current_line = 1u32;
    if current_line == start {
        byte_start = Some(0);
    }
    for (idx, ch) in text.char_indices() {
        if ch == '\n' {
            if current_line == end {
                byte_end = idx + 1;
                break;
            }
            current_line += 1;
            if current_line == start && byte_start.is_none() {
                byte_start = Some(idx + 1);
            }
        }
    }
    let start = byte_start?;
    Some(&text[start..byte_end.min(text.len())])
}

fn line_byte_range(text: &str, target_line: u32, base_line: u32) -> Option<std::ops::Range<usize>> {
    if target_line < base_line {
        return None;
    }
    let mut line = base_line;
    let mut line_start = 0usize;
    for (idx, ch) in text.char_indices() {
        if line == target_line && ch == '\n' {
            return Some(line_start..idx);
        }
        if ch == '\n' {
            line += 1;
            line_start = idx + 1;
        }
    }
    if line == target_line {
        return Some(line_start..text.len());
    }
    None
}

fn read_source(file: &str, root: Option<&std::path::Path>) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(file) {
        return Some(text);
    }
    let root = root?;
    let candidate = root.join(file);
    std::fs::read_to_string(candidate).ok()
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

fn string_static(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}
