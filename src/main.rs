use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use clap::Subcommand;
use tracing_subscriber::EnvFilter;
use xct2cli::xctrace::Xctrace;

use xct2cli::Pid;
use xct2cli::Slide;
use xct2cli::analysis::AnnotateOptions;
use xct2cli::analysis::CountersBuilder;
use xct2cli::analysis::HotspotsBuilder;
use xct2cli::analysis::SlideMode;
use xct2cli::analysis::Weight;
use xct2cli::analysis::annotate;
use xct2cli::render::AnnotateMode;
use xct2cli::render::AnnotateRenderOptions;
use xct2cli::render::ColorMode;
use xct2cli::render::Palette;
use xct2cli::symbol::BinaryInfo;
use xct2cli::trace::TraceBundle;

#[derive(Parser, Debug)]
#[command(
    name = "xct2cli",
    version,
    about = "Transform Xcode Instruments traces into CLI- and LLM-friendly output."
)]
struct Cli {
    #[arg(long, global = true)]
    verbose: bool,

    /// Color output: `auto` (default; on if stdout is a TTY and
    /// `NO_COLOR` is unset), `always`, `never`.
    #[arg(long, global = true, value_enum, default_value_t = CliColor::Auto)]
    color: CliColor,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
enum CliColor {
    #[default]
    Auto,
    Always,
    Never,
}

impl From<CliColor> for ColorMode {
    fn from(c: CliColor) -> Self {
        match c {
            CliColor::Auto => ColorMode::Auto,
            CliColor::Always => ColorMode::Always,
            CliColor::Never => ColorMode::Never,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the table of contents of a `.trace` bundle.
    Toc(TocArgs),

    /// High-level CPU hotspot summary with a per-CPU burst timeline.
    Hotspots(HotspotsArgs),

    /// Enumerate plausible ASLR slides for a binary against the trace's
    /// sampled PCs. Use the printed value with `--slide` for other commands.
    Slide(SlideArgs),

    /// Disassemble a function and overlay per-instruction sample counts +
    /// source-line callouts via `annotate-snippets`.
    Annotate(AnnotateArgs),

    /// Per-PC CPU counter aggregation from a CPU Counters trace.
    Counters(CountersArgs),

    /// Record a new trace by launching a binary under `xctrace`.
    Record(RecordArgs),

    /// List the metric and PMI event names in a trace, for use with
    /// `--metric` / `--event` on `annotate` and `counters`.
    Events(EventsArgs),
}

#[derive(clap::Args, Debug)]
struct EventsArgs {
    trace: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct RecordArgs {
    /// Output `.trace` bundle path.
    #[arg(long, short = 'o')]
    output: Utf8PathBuf,
    /// Instruments template name. Common: "Time Profiler", "CPU Counters",
    /// "System Trace", "Allocations".
    #[arg(long, short = 't', default_value = "Time Profiler")]
    template: String,
    /// `KEY=VALUE` env vars forwarded to the launched binary; repeat for many.
    #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Binary to launch, followed by its args after `--`.
    #[arg(required = true, last = true)]
    target: Vec<OsString>,
}

#[derive(clap::Args, Debug)]
struct CountersArgs {
    trace: PathBuf,
    #[arg(long)]
    pid: Option<i64>,
    /// Show top N hottest PCs.
    #[arg(long, default_value_t = 25)]
    top: usize,
    /// Sort by counter index N instead of sample count.
    #[arg(long)]
    sort_by: Option<usize>,
    #[arg(long)]
    binary: Option<PathBuf>,
    #[arg(long)]
    dsym: Option<PathBuf>,
    #[arg(long, value_parser = parse_u64)]
    slide: Option<u64>,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct AnnotateArgs {
    trace: PathBuf,
    /// Function name to annotate (matches mangled or demangled names; partial
    /// substring match is allowed).
    #[arg(long)]
    function: String,
    #[arg(long)]
    binary: Option<PathBuf>,
    #[arg(long)]
    dsym: Option<PathBuf>,
    #[arg(long, value_parser = parse_u64)]
    slide: Option<u64>,
    #[arg(long)]
    pid: Option<i64>,
    /// Show every instruction, not just sampled ones.
    #[arg(long)]
    show_zero: bool,
    /// Prepend this directory to relative source-file paths.
    #[arg(long)]
    source_root: Option<PathBuf>,
    /// Output mode.
    /// `instructions`: per-instruction overlay + source-snippet hot block (default).
    /// `source`: just the annotate-snippets source-line callouts.
    /// `interleaved`: source line headers grouping the asm that came from each.
    #[arg(long, value_enum, default_value_t = CliAnnotateMode::Instructions)]
    mode: CliAnnotateMode,

    /// Lines of source context shown above/below each hot-line cluster
    /// in the source-snippet view. Hot lines within `2 * context` lines
    /// of each other share one snippet.
    #[arg(long, default_value_t = 4)]
    context: u32,
    /// Overlay a CPU-Counters metric (per-PC delta sum) instead of raw
    /// sample counts. The index matches the `[N] <name>` legend printed
    /// by `xct2cli events`. Requires a CPU Counters trace.
    #[arg(long, conflicts_with = "event")]
    metric: Option<usize>,
    /// Overlay PMI-overflow sample counts for the given event name
    /// (e.g. `l1d_load_miss`, `PL2_CACHE_MISS_LD`). Requires a CPU
    /// Counters trace recorded in a sampling mode.
    #[arg(long, conflicts_with = "metric")]
    event: Option<String>,
    #[arg(long)]
    json: bool,
}

impl AnnotateArgs {
    fn weight(&self) -> Weight {
        if let Some(name) = &self.event {
            Weight::PmiEvent { name: name.clone() }
        } else if let Some(idx) = self.metric {
            Weight::Metric { index: idx }
        } else {
            Weight::Samples
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum CliAnnotateMode {
    Instructions,
    Source,
    Interleaved,
}

impl From<CliAnnotateMode> for AnnotateMode {
    fn from(m: CliAnnotateMode) -> Self {
        match m {
            CliAnnotateMode::Instructions => AnnotateMode::Instructions,
            CliAnnotateMode::Source => AnnotateMode::Source,
            CliAnnotateMode::Interleaved => AnnotateMode::Interleaved,
        }
    }
}

#[derive(clap::Args, Debug)]
struct SlideArgs {
    trace: PathBuf,
    #[arg(long)]
    binary: Option<PathBuf>,
    #[arg(long)]
    dsym: Option<PathBuf>,
    #[arg(long)]
    pid: Option<i64>,
    /// Show this many top candidates.
    #[arg(long, default_value_t = 10)]
    top: usize,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct TocArgs {
    /// Path to a `.trace` bundle.
    trace: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct HotspotsArgs {
    trace: PathBuf,
    /// Restrict to samples from this PID. Defaults to the launched target.
    #[arg(long)]
    pid: Option<i64>,
    /// Timeline bucket width in milliseconds.
    #[arg(long, default_value_t = 10)]
    bucket_ms: u64,
    /// Show top N hottest program counters.
    #[arg(long, default_value_t = 25)]
    top: usize,
    /// Restrict to a time window, in `START..END` milliseconds since the
    /// first sample (e.g. `0..500`).
    #[arg(long)]
    window_ms: Option<String>,
    /// Path to the launched binary (for symbol resolution). Inferred from
    /// the trace's process info when omitted.
    #[arg(long)]
    binary: Option<PathBuf>,
    /// Path to a `.dSYM` bundle (or its inner DWARF file). Optional;
    /// addr2line will also pick up DWARF embedded in the binary.
    #[arg(long)]
    dsym: Option<PathBuf>,
    /// ASLR slide subtracted from runtime PCs before DWARF lookup.
    /// Hex (`0x...`) or decimal. When omitted, auto-detected from kdebug.
    #[arg(long, value_parser = parse_u64)]
    slide: Option<u64>,
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let palette = Palette::new(ColorMode::from(cli.color).resolve());

    match cli.command {
        Command::Toc(args) => run_toc(args, palette),
        Command::Hotspots(args) => run_hotspots(args, palette),
        Command::Slide(args) => run_slide(args),
        Command::Annotate(args) => run_annotate(args, palette),
        Command::Counters(args) => run_counters(args, palette),
        Command::Record(args) => run_record(args),
        Command::Events(args) => run_events(args),
    }
}

fn slide_mode(slide: Option<u64>) -> SlideMode {
    match slide {
        Some(s) => SlideMode::Manual(Slide::new(s)),
        None => SlideMode::Auto,
    }
}

fn run_events(args: EventsArgs) -> anyhow::Result<()> {
    let bundle = TraceBundle::open(&args.trace).context("opening trace bundle")?;

    let metrics = bundle.metric_labels().unwrap_or_default();
    let mut events: BTreeMap<String, u64> = BTreeMap::new();
    if let Ok(samples) = bundle.pmi_samples(None) {
        for s in samples {
            *events.entry(s.event).or_insert(0) += 1;
        }
    }

    if args.json {
        let payload = serde_json::json!({
            "metrics": metrics
                .iter()
                .enumerate()
                .map(|(i, n)| serde_json::json!({"index": i, "name": n}))
                .collect::<Vec<_>>(),
            "pmi_events": events
                .iter()
                .map(|(name, count)| serde_json::json!({"name": name, "samples": count}))
                .collect::<Vec<_>>(),
            "counters_profile_event": bundle.counters_profile_event().ok().flatten(),
        });
        serde_json::to_writer_pretty(std::io::stdout().lock(), &payload)?;
        println!();
        return Ok(());
    }

    if metrics.is_empty() {
        println!("metrics: (no MetricTable in trace)");
    } else {
        println!("metrics (use with `annotate --metric N` or `counters --sort-by N`):");
        for (i, name) in metrics.iter().enumerate() {
            println!("  [{i}]  {name}");
        }
    }
    println!();
    if events.is_empty() {
        println!("pmi events: (no SamplingModeSamples in trace)");
    } else {
        println!("pmi events (use with `annotate --event NAME`):");
        let total: u64 = events.values().sum();
        for (name, count) in &events {
            let pct = (*count as f64 / total.max(1) as f64) * 100.0;
            println!("  {:<24}  {:>8}  {:>5.1}%", name, count, pct);
        }
    }

    if let Ok(Some(name)) = bundle.counters_profile_event() {
        println!();
        println!("counters-profile event (Manual-mode template; use `annotate --event {name}`):");
        println!("  {name}    (PCs recovered by nearest-timestamp join with time-sample)");
    }
    Ok(())
}

fn run_record(args: RecordArgs) -> anyhow::Result<()> {
    let mut iter = args.target.into_iter();
    let bin_os = iter
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing target binary after `--`"))?;
    let target_args: Vec<OsString> = iter.collect();
    let bin_path = PathBuf::from(bin_os);
    if !bin_path.exists() {
        anyhow::bail!("target binary does not exist: {}", bin_path.display());
    }
    let env: Vec<(String, String)> = args
        .env
        .into_iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow::anyhow!("--env expects KEY=VALUE, got {kv:?}"))
        })
        .collect::<anyhow::Result<_>>()?;

    let xctrace = Xctrace::discover();
    xctrace
        .record_launch(&args.template, &args.output, &bin_path, &target_args, &env)
        .context("xctrace record")?;
    println!("recorded: {}", args.output);
    Ok(())
}

fn run_counters(args: CountersArgs, palette: Palette) -> anyhow::Result<()> {
    let bundle = TraceBundle::open(&args.trace).context("opening trace bundle")?;
    let mut builder = CountersBuilder::new(&bundle).top(args.top);
    if let Some(pid) = args.pid {
        builder = builder.pid(Pid::new(pid));
    }
    if let Some(idx) = args.sort_by {
        builder = builder.sort_by_index(idx);
    }
    let binary = match args.binary {
        Some(b) => Some(b),
        None => infer_binary_from_toc(&bundle).unwrap_or(None),
    };
    builder = builder
        .binary(binary)
        .dsym(args.dsym)
        .slide(slide_mode(args.slide));
    let report = builder.run().context("building counter report")?;
    if args.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
        println!();
    } else {
        print!("{}", report.to_text(palette));
    }
    Ok(())
}

fn run_annotate(args: AnnotateArgs, palette: Palette) -> anyhow::Result<()> {
    let bundle = TraceBundle::open(&args.trace).context("opening trace bundle")?;
    let binary = match args.binary.clone() {
        Some(b) => b,
        None => infer_binary_from_toc(&bundle)?
            .ok_or_else(|| anyhow::anyhow!("no --binary and TOC has no usable process path"))?,
    };
    let opts = AnnotateOptions {
        function: args.function.clone(),
        binary,
        dsym: args.dsym.clone(),
        slide: slide_mode(args.slide),
        pid: args.pid.map(Pid::new),
        weight: args.weight(),
    };
    let func = annotate(&bundle, opts).context("annotating function")?;
    if args.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &func)?;
        println!();
    } else {
        let render_opts = AnnotateRenderOptions {
            show_zero: args.show_zero,
            source_root: args.source_root,
            mode: args.mode.into(),
            colored: palette.colored,
            context: args.context,
        };
        let text = func.render(&render_opts)?;
        print!("{}", text);
    }
    Ok(())
}

fn run_slide(args: SlideArgs) -> anyhow::Result<()> {
    let bundle = TraceBundle::open(&args.trace).context("opening trace bundle")?;
    let binary = match args.binary {
        Some(b) => Some(b),
        None => infer_binary_from_toc(&bundle).unwrap_or(None),
    };
    let binary = binary
        .ok_or_else(|| anyhow::anyhow!("no --binary given and TOC has no usable process path"))?;
    let info = BinaryInfo::open(&binary).context("reading Mach-O binary info")?;
    let loads = bundle
        .image_loads()
        .context("reading kdebug image-load events")?;
    let kdebug_slide = info.slide_from(&loads);

    let pcs = bundle
        .pc_samples(args.pid.map(Pid::new))
        .context("collecting PC samples")?;
    let dwarf = args.dsym.as_deref().unwrap_or(binary.as_path());
    let candidates = info.enumerate_slides(&pcs, dwarf);
    let take: Vec<_> = candidates.into_iter().take(args.top).collect();

    if args.json {
        let payload = serde_json::json!({
            "binary": binary,
            "uuid": info.uuid.map(|u| format_uuid(&u)),
            "kdebug_slide": kdebug_slide,
            "candidates": take,
            "image_loads": loads,
        });
        serde_json::to_writer_pretty(std::io::stdout().lock(), &payload)?;
        println!();
        return Ok(());
    }

    println!("binary: {}", binary.display());
    if let Some(uuid) = info.uuid {
        println!("uuid:   {}", format_uuid(&uuid));
    }
    println!("text:   {}..{}", info.text_start, info.text_end);
    println!("pcs in trace: {} unique", pcs.len());
    println!();
    if let Some(s) = kdebug_slide {
        println!("kdebug DBG_DYLD slide: {s}   (recommended; matched by UUID)");
    } else {
        println!(
            "kdebug DBG_DYLD slide: not found ({} image-load events in trace, none matched the binary's UUID)",
            loads.len()
        );
    }
    println!();
    println!("Heuristic candidates (use only if kdebug detection failed):");
    println!(
        "{:<14}  {:>9}  {:>9}  {:>10}  function",
        "slide", "covered", "top", "fn-bytes"
    );
    for c in &take {
        let name = c.top_function_name.as_deref().unwrap_or("?");
        println!(
            "{:<14}  {:>9}  {:>9}  {:>10}  {}",
            format!("{}", c.slide),
            c.covered_samples,
            c.top_function_samples,
            c.top_function_size,
            name
        );
    }
    Ok(())
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15],
    )
}

fn init_tracing(verbose: bool) {
    let default = if verbose {
        "xct2cli=debug"
    } else {
        "xct2cli=info"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn run_toc(args: TocArgs, palette: Palette) -> anyhow::Result<()> {
    let bundle = TraceBundle::open(&args.trace).context("opening trace bundle")?;
    let toc = bundle.toc().context("loading TOC")?;
    if args.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &toc)?;
        println!();
    } else {
        print!("{}", toc.to_text(palette));
    }
    Ok(())
}

fn run_hotspots(args: HotspotsArgs, palette: Palette) -> anyhow::Result<()> {
    let bundle = TraceBundle::open(&args.trace).context("opening trace bundle")?;
    let mut builder = HotspotsBuilder::new(&bundle)
        .bucket_ns(args.bucket_ms.saturating_mul(1_000_000))
        .top(args.top);
    if let Some(pid) = args.pid {
        builder = builder.pid(Pid::new(pid));
    }
    if let Some(window) = &args.window_ms {
        let (lo, hi) = parse_window_ms(window).context("parsing --window-ms")?;
        builder = builder.time_window_ns(lo * 1_000_000, hi * 1_000_000);
    }
    let binary = match args.binary {
        Some(b) => Some(b),
        None => infer_binary_from_toc(&bundle).unwrap_or(None),
    };
    builder = builder
        .binary(binary)
        .dsym(args.dsym)
        .slide(slide_mode(args.slide));
    let report = builder.run().context("building hotspot report")?;
    if args.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
        println!();
    } else {
        print!("{}", report.to_text(palette));
    }
    Ok(())
}

fn infer_binary_from_toc(bundle: &TraceBundle) -> anyhow::Result<Option<PathBuf>> {
    let toc = bundle.toc()?;
    let Some(run) = toc.first_run() else {
        return Ok(None);
    };
    let target_name = run
        .info
        .target
        .as_ref()
        .and_then(|t| t.process.get("name").cloned());
    let path = run
        .processes
        .iter()
        .find(|p| Some(&p.name) == target_name.as_ref())
        .and_then(|p| p.path.clone())
        .map(PathBuf::from);
    Ok(path)
}

fn parse_u64(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (radix, body) = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, rest)
    } else {
        (10, s)
    };
    Ok(u64::from_str_radix(body, radix)?)
}

fn parse_window_ms(spec: &str) -> anyhow::Result<(u64, u64)> {
    let (lo, hi) = spec
        .split_once("..")
        .ok_or_else(|| anyhow::anyhow!("expected START..END, got {spec:?}"))?;
    let lo: u64 = lo.trim().parse().context("START")?;
    let hi: u64 = hi.trim().parse().context("END")?;
    if hi <= lo {
        anyhow::bail!("window END ({hi}) must be greater than START ({lo})");
    }
    Ok((lo, hi))
}
