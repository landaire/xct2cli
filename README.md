# xct2cli

Library and CLI for transforming Xcode Instruments `.trace` bundles into
output that's useful to humans **and** LLMs. Apple Silicon only.

The crate is library-forward: `xct2cli` (the binary) is a thin `clap`
shell over `xct2cli` (the lib). Other tools can depend on the lib with
`default-features = false` to skip the CLI deps.

**NOTE:** This is kind of some LLM bullshit. I kept having Claude Code use Instruments to profile code and it would always create a Python script to interpret the results. This project is my attempt to kill the Python script it would always generate, and get richer info at the same time.

## Why

Instruments and `xctrace` are not super LLM-friendly. `xctrace` supports data export as XML, but still requires some parsing to get a bird's eye view info.

This `xct2cli` helps convert the report to plaintext that's easier to consume.

## Requirements

- macOS with Xcode (`/usr/bin/xctrace` ships with it).
- Apple Silicon for the disassembler (we use `capstone` in arm64 mode).
- Optional: `cargo-instruments` for recording from Cargo projects.

## Commands

```
xct2cli toc       <trace>                    # what's in the bundle
xct2cli hotspots  <trace> [--slide HEX] ...  # per-CPU timeline + top PCs
xct2cli slide     <trace> --binary BIN ...   # enumerate plausible ASLR slides
xct2cli annotate  <trace> --function NAME ...# disassembly + source via annotate-snippets
xct2cli counters  <trace>                    # per-PC PMU counter aggregation
xct2cli record    -t TEMPLATE -o OUT.trace -- ./bin args
```

Every command supports `--json` for machine-readable output.

## End-to-end example (`lzxc` benchmark)

```sh
xct2cli record -t "Time Profiler" -o run.trace -- \
    target/release/examples/profile_compress

xct2cli toc run.trace                   # confirm template, processes
xct2cli hotspots run.trace              # auto-detects slide from kdebug
xct2cli annotate run.trace --function MatchFinder::process
```

`hotspots` produces a per-CPU burst timeline plus the top PCs, each
resolved to function + file:line via DWARF when a binary or dSYM is
provided.

`annotate` disassembles a function (matched by demangled or raw Mach-O
symbol name), pairs every instruction with its source line, overlays
sample counts, and emits an `annotate-snippets` block per source file
showing the hot lines:

```
hot lines in .../lzxc/src/lib.rs
   --> .../lzxc/src/lib.rs:310
    |
307 |         let effective_input: &[u8] = if let Some(size) = self.e8_translation_size {
    | ----------------------------------------------------------------------------------- 15 samples
310 |             e8_preprocess_in_place(&mut self.e8_scratch, self.input_offset, size as i32);
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 136 samples
```

## ASLR slide

Apple Silicon binaries are PIE; their `__TEXT` is loaded at a randomised
slide each run. The trace records `DBG_DYLD_UUID_MAP_A` kdebug events
(class 31, subclass 5, code 0) for every loaded image: arg1+arg2 hold
the image's UUID, arg3 holds its runtime load address. We match the
binary's `LC_UUID` against those events to recover the slide
deterministically.

`hotspots` and `annotate` use this automatically when given `--binary`
or `--dsym`. `xct2cli slide <trace>` prints the recovered slide
alongside a fallback heuristic ranking for the rare case the kdebug
events are absent (e.g. attached to a long-running process where dyld
mapped the image before recording started).

## Library use

```rust
use xct2cli::trace::TraceBundle;
use xct2cli::analysis::HotspotsBuilder;

let bundle = TraceBundle::open("run.trace")?;
let report = HotspotsBuilder::new(&bundle)
    .top(50)
    .binary(Some("target/release/myapp".into()))
    .run()?;
```

The streaming XML reader is exposed as `xct2cli::xml::RowReader` for
callers that need to consume custom tables not yet covered by an
analysis module.

## What's not (yet) supported

- Per-PC cache-miss counters. `counters` aggregates per-PC where the
  trace's counter table includes user callstacks; the default _CPU
  Counters_ template does not, so the output collapses to one row per
  trace. Cache-by-PC needs a custom Instruments package or recording
  config.
- Templates other than Time Profiler / CPU Counters have not been
  exercised end-to-end. The TOC reader works on any trace; the analyses
  assume the time-sample / kdebug-counters schemas Apple ships with
  Time Profiler / CPU Counters.
