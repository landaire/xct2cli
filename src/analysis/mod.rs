//! Higher-level analyses built on `xml::RowReader`.

pub mod annotate;
pub mod callgraph;
pub mod counters;
pub mod hotspots;
pub mod pmi;
pub mod samples;

pub use annotate::AnnotateOptions;
pub use annotate::AnnotatedFunction;
pub use annotate::AnnotatedInstruction;
pub use annotate::Weight;
pub use annotate::annotate;
pub use callgraph::CallgraphBuilder;
pub use callgraph::CallgraphReport;
pub use callgraph::FunctionStat;
pub use counters::CounterReport;
pub use counters::CountersBuilder;
pub use counters::PerPcCounter;
pub use hotspots::Hotspot;
pub use hotspots::HotspotReport;
pub use hotspots::HotspotsBuilder;
pub use hotspots::SlideMode;
pub use pmi::PmiSample;
pub use samples::Callstack;
pub use samples::PcSample;
