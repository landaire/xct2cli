use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;

use annotate_snippets::AnnotationKind;
use annotate_snippets::Group;
use annotate_snippets::Level;
use annotate_snippets::Renderer;
use annotate_snippets::Snippet;

use crate::analysis::AnnotatedFunction;
use crate::error::Result;

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
}

pub fn render_annotated(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    match opts.mode {
        AnnotateMode::Instructions => render_instructions(func, opts),
        AnnotateMode::Source => render_source_only(func, opts),
        AnnotateMode::Interleaved => render_interleaved(func, opts),
    }
}

fn render_instructions(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    let mut out = String::new();
    write_header(&mut out, func);

    let max_samples = func
        .instructions
        .iter()
        .map(|i| i.samples)
        .max()
        .unwrap_or(0);
    for ins in &func.instructions {
        if ins.samples == 0 && !opts.show_zero {
            continue;
        }
        let bar = if max_samples > 0 {
            let n = (ins.samples as f64 / max_samples as f64 * 10.0).round() as usize;
            "#".repeat(n)
        } else {
            String::new()
        };
        let loc = match (&ins.file, ins.line) {
            (Some(f), Some(l)) => format!("  // {}:{}", short_path(f), l),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "  {:>5}  {:<10} 0x{:012x}  {} {}{}",
            ins.samples, bar, ins.runtime_address, ins.mnemonic, ins.operands, loc
        );
    }

    let _ = writeln!(out, "\nsource hot-spots ({}):", func.weight_label);
    write_source_blocks(&mut out, func, opts);
    Ok(out)
}

fn render_source_only(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    let mut out = String::new();
    write_header(&mut out, func);
    write_source_blocks(&mut out, func, opts);
    Ok(out)
}

fn render_interleaved(func: &AnnotatedFunction, opts: &AnnotateRenderOptions) -> Result<String> {
    let mut out = String::new();
    write_header(&mut out, func);

    let max_samples = func
        .instructions
        .iter()
        .map(|i| i.samples)
        .max()
        .unwrap_or(0);
    let mut source_cache: BTreeMap<String, Option<String>> = BTreeMap::new();

    let groups = group_consecutive_by_source(&func.instructions);
    for group in groups {
        let total: u64 = group.instructions.iter().map(|i| i.samples).sum();
        if total == 0 && !opts.show_zero {
            continue;
        }
        let header = match (&group.file, group.line) {
            (Some(f), Some(l)) => {
                let text = source_cache
                    .entry(f.clone())
                    .or_insert_with(|| read_source(f, opts.source_root.as_deref()));
                let snippet_line = text.as_deref().and_then(|t| nth_line(t, l));
                match snippet_line {
                    Some(s) => format!("{}:{}  {}", short_path(f), l, s.trim_end()),
                    None => format!("{}:{}", short_path(f), l),
                }
            }
            _ => "(no source mapping)".to_string(),
        };
        let _ = writeln!(
            out,
            "{header}    [{} insns, {} {}]",
            group.instructions.len(),
            total,
            func.weight_label
        );
        for ins in group.instructions {
            if ins.samples == 0 && !opts.show_zero {
                continue;
            }
            let bar = if max_samples > 0 {
                let n = (ins.samples as f64 / max_samples as f64 * 10.0).round() as usize;
                "#".repeat(n)
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "      {:>5}  {:<10} 0x{:012x}  {} {}",
                ins.samples, bar, ins.runtime_address, ins.mnemonic, ins.operands
            );
        }
        let _ = writeln!(out);
    }
    Ok(out)
}

fn write_header(out: &mut String, func: &AnnotatedFunction) {
    let _ = writeln!(
        out,
        "function: {} ({} {} in window, {} bytes)",
        func.demangled_name,
        func.total_samples,
        func.weight_label,
        func.runtime_end - func.runtime_start
    );
    let _ = writeln!(out, "  binary:  {}", func.binary.display());
    let _ = writeln!(
        out,
        "  runtime: 0x{:x}..0x{:x}   file: 0x{:x}..0x{:x}\n",
        func.runtime_start, func.runtime_end, func.file_start, func.file_end
    );
}

fn write_source_blocks(out: &mut String, func: &AnnotatedFunction, opts: &AnnotateRenderOptions) {
    let blocks = group_by_source(func);
    let renderer = Renderer::plain();
    for (file, lines) in blocks {
        let Some(text) = read_source(&file, opts.source_root.as_deref()) else {
            let _ = writeln!(out, "  (source unavailable: {file})");
            continue;
        };
        let max_samples = lines.iter().map(|(_, s)| *s).max().unwrap_or(0);
        let min_line = lines.iter().map(|(l, _)| *l).min().unwrap_or(1);
        let max_line = lines.iter().map(|(l, _)| *l).max().unwrap_or(1);
        let pad = 2u32;
        let display_start = min_line.saturating_sub(pad).max(1);
        let display_end = max_line + pad;
        let Some(display_text) = take_lines(&text, display_start, display_end) else {
            continue;
        };
        let display_text = display_text.to_string();
        let display_text_static: &'static str = Box::leak(display_text.into_boxed_str());

        let mut snippet = Snippet::source(display_text_static)
            .path(string_static(&file))
            .line_start(display_start as usize)
            .fold(false);
        for (line, samples) in &lines {
            let Some(span) = line_byte_range(display_text_static, *line, display_start) else {
                continue;
            };
            let label = format!("{} {}", samples, func.weight_label);
            let kind = if max_samples > 0 && samples * 2 >= max_samples {
                AnnotationKind::Primary
            } else {
                AnnotationKind::Context
            };
            snippet = snippet.annotation(kind.span(span).label(string_static(&label)));
        }

        let title = format!("hot lines in {}", short_path(&file));
        let group =
            Group::with_title(Level::NOTE.primary_title(string_static(&title))).element(snippet);
        let _ = writeln!(out, "{}", renderer.render(&[group]));
    }
}

struct InstructionGroup<'a> {
    file: Option<String>,
    line: Option<u32>,
    instructions: Vec<&'a crate::analysis::AnnotatedInstruction>,
}

fn group_consecutive_by_source(
    insns: &[crate::analysis::AnnotatedInstruction],
) -> Vec<InstructionGroup<'_>> {
    let mut out: Vec<InstructionGroup<'_>> = Vec::new();
    for ins in insns {
        let key = (ins.file.clone(), ins.line);
        match out.last_mut() {
            Some(last) if (last.file.clone(), last.line) == key => {
                last.instructions.push(ins);
            }
            _ => out.push(InstructionGroup {
                file: key.0,
                line: key.1,
                instructions: vec![ins],
            }),
        }
    }
    out
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
