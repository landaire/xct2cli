# xct2cli

Library and CLI for transforming Xcode Instruments `.trace` bundles into
output that's useful to humans **and** LLMs. Apple Silicon only.

The crate is library-forward: `xct2cli` (the binary) is a thin `clap`
shell over `xct2cli` (the lib). Other tools can depend on the lib with
`default-features = false` to skip the CLI deps.

**NOTE:** This is kind of some LLM bullshit. I kept having Claude Code use Instruments to profile code and it would always create a Python script to interpret the results. This project is my attempt to kill the Python script it would always generate, and get richer info at the same time.

## Why

Instruments and `xctrace` are not super LLM-friendly. `xctrace` exports
data as XML, but it still requires a lot of XPath probing and
schema-specific knowledge to get useful output. `xct2cli` does the
parsing, the symbolication, the per-CPU counter joins, and the
per-instruction inlining attribution for you, and prints something both
a human and an LLM can read.

## Requirements

- macOS with Xcode (`/usr/bin/xctrace` ships with it).
- Apple Silicon for the disassembler (we use `capstone` in arm64 mode).
- Optional: `cargo-instruments` for recording from Cargo projects.

## Commands

```
xct2cli toc       <trace>                          # what's in the bundle
xct2cli hotspots  <trace> [--binary BIN] [--dsym DSYM]
xct2cli slide     <trace> [--binary BIN] [--dsym DSYM]
xct2cli annotate  <trace> --function NAME [--mode interleaved] [--event NAME | --metric N]
xct2cli counters  <trace> [--sort-by N]
xct2cli events    <trace>                          # list metric / pmi-event names
xct2cli record    -t TEMPLATE -o OUT.trace -- ./bin args
```

Global flags: `--color {auto,always,never}` (auto-detect TTY + honor
`NO_COLOR`), `--verbose`, `--json` on every command for
machine-readable output (color is suppressed in JSON mode).

## End-to-end example (`lzxc` benchmark)

```sh
# record a Time Profiler trace
xct2cli record -t "Time Profiler" -o /tmp/run.trace -- \
    target/release/examples/profile_compress

# what's in it?
xct2cli toc /tmp/run.trace

# top hotspots, auto-symbolicated against the launched binary
xct2cli hotspots /tmp/run.trace

# disassemble a function with per-instruction sample counts grouped by
# source line — the inlined-from layer surfaces find_best_match's lines
# even though they were inlined into MatchFinder::process
xct2cli annotate /tmp/run.trace --function MatchFinder::process --mode interleaved
```

`hotspots` produces a per-CPU sample summary, a 10-ms-bucket burst
timeline, and the top-N hottest PCs resolved to `function file:line` via
DWARF. ASLR slide is recovered automatically from kdebug events when a
binary or dSYM is provided.

`annotate` has three modes:

- `--mode instructions` (default) — every sampled instruction with its
  asm + source-line comment, plus an `annotate-snippets` block per
  source file showing the hot lines.
- `--mode source` — just the `annotate-snippets` source-line callouts.
- `--mode interleaved` — source-grouped: each contiguous run of
  instructions sharing a source line gets its own block with stats,
  function (innermost inlined name), location, source code, and the
  asm underneath. Best for understanding *which inlined function* the
  hot loop actually came from.

`annotate --event <name>` and `annotate --metric N` swap the
per-instruction weight from "raw samples" to "L1D misses" / "back-end
stall events" / etc. when the trace has CPU Counters data — same code
path, different attribution.

## Cache thrash analysis

For real per-instruction cache miss attribution, record with a
`.tracetemplate` configured for PMI-overflow sampling on a memory
event. Templates are checked in under `templates/`:

- `templates/L1D_Miss.tracetemplate` — Apple's Guided "L1D Miss
  Sampling" mode. Captures `l1d_load_miss`, `l1d_store_miss`,
  `l1d_tlb_miss` events with full callstacks at the PMI overflow.
- `templates/l2_miss.tracetemplate` — Manual mode sampling
  `PL2_CACHE_MISS_LD` (Apple Silicon's per-cluster L2). Manual mode
  doesn't capture per-PMI callstacks, so PCs are recovered by joining
  each PMI sample to the nearest `time-sample` row from the
  co-recorded Time Profiler.

```sh
xct2cli record -t templates/L1D_Miss.tracetemplate -o /tmp/l1d.trace -- \
    target/release/examples/profile_compress

# what events / counters did the trace capture?
xct2cli events /tmp/l1d.trace

# overlay literal L1D load misses per instruction
xct2cli annotate /tmp/l1d.trace --function MatchFinder::process \
    --event l1d_load_miss --mode interleaved
```

The interleaved view groups instructions by their innermost inlined
source location, so you can immediately see *which* inlined function
generated the hot block — even when the binary symbol that contains the
PC is something else:

![L1D miss interleaved view of MatchFinder::process](img/l1d_miss.png)

In this trace, 931 of 2124 L1D load misses (44%) come from a single
`prev[c_rel]` read in `find_best_match` at `match_finder.rs:278` — the
hash-chain walk inlined into `MatchFinder::process`.

## Discovering events

`xct2cli events <trace>` lists everything weight-able in the trace:

```
$ xct2cli events /tmp/l1d.trace
metrics (use with `annotate --metric N` or `counters --sort-by N`):
  [0]  Cycles
  [1]  L1D Cache Load Misses
  [2]  L1D Cache Store Misses
  [3]  L1D TLB Misses

pmi events (use with `annotate --event NAME`):
  l1d_load_miss              2473   61.2%
  l1d_store_miss             1546   38.3%
  l1d_tlb_miss                 20    0.5%
```

For Manual-mode templates (e.g. the L2 one), it also lists the single
configured event name from the trace's `counters-profile` table.

## ASLR slide

Apple Silicon binaries are PIE; their `__TEXT` is loaded at a randomised
slide each run. The trace records `DBG_DYLD_UUID_MAP_A` kdebug events
(class 31, subclass 5, code 0) for every loaded image: arg1+arg2 hold
the image's UUID, arg3 holds its runtime load address. We match the
binary's `LC_UUID` against those events to recover the slide
deterministically.

`hotspots`, `annotate`, and `counters` use this automatically when
given `--binary` or `--dsym`. `xct2cli slide <trace>` prints the
recovered slide alongside a fallback heuristic ranking for the rare
case the kdebug events are absent (e.g. attached to a long-running
process where dyld mapped the image before recording started).

## Building your own templates

`xctrace`'s CLI doesn't expose CPU Counters' Mode dropdown, so to use
non-default sampling you have to build a `.tracetemplate` once in
Instruments.app and check it in. To add a new one (say, for branch
mispredict sampling):

1. Open Instruments → New Document → Blank
2. Add the **CPU Counters** instrument
3. Set Configuration: **Manual**, Sample By: **Events**, pick the
   Sampling Event (e.g. `BRANCH_MISPRED_NONSPEC`), pick Sample Every
   (start at 1M; lower if samples are too sparse)
4. Add a **Time Profiler** instrument with **High Frequency Sampling**
   on, so PMI samples can be joined by timestamp to a PC
5. File → Save as Template, into `templates/`

Then `xct2cli record -t templates/your-template.tracetemplate -o ...`
and `xct2cli events <trace>` will show whatever event name Apple
recorded. `--event NAME` works the same way as for the bundled
templates.

## Library use

```rust
use xct2cli::trace::TraceBundle;
use xct2cli::analysis::HotspotsBuilder;

let bundle = TraceBundle::open("run.trace")?;
let report = HotspotsBuilder::new(&bundle)
    .top(50)
    .binary(Some("target/release/myapp".into()))
    .run()?;
println!("{}", report.to_text(Default::default()));
```

Most data-extraction helpers are inherent methods on `TraceBundle`:
`pc_samples`, `pmi_samples`, `pmi_event_names`, `metric_labels`,
`per_pc_pmi_count`, `per_pc_metric_deltas`, `image_loads`,
`counters_profile_event`. `BinaryInfo::open(path)` parses Mach-O for
slide detection (`info.slide_from(&loads)`).

The streaming XML reader is exposed as `xct2cli::xml::RowReader` for
callers that need to consume custom tables not yet covered by an
analysis module.

## What's not (yet) supported

- Templates other than Time Profiler / CPU Counters haven't been
  exercised end-to-end. The TOC reader works on any trace; the
  analyses assume the time-sample / kdebug-counters schemas Apple
  ships with Time Profiler / CPU Counters.
- Multi-run traces (`xctrace record --append-run`) are partially
  parsed (`Toc::runs` is a `Vec`) but the analysis builders only
  consume run #1.
