//! Higher-level analyses built on `xml::RowReader`.

pub mod annotate;
pub mod counters;
pub mod hotspots;
pub mod pmi;
pub mod samples;

pub use annotate::AnnotateOptions;
pub use annotate::AnnotatedFunction;
pub use annotate::AnnotatedInstruction;
pub use annotate::annotate;
pub use counters::CounterReport;
pub use counters::CountersBuilder;
pub use counters::PerPcCounter;
pub use counters::metric_labels;
pub use counters::per_pc_metric_deltas;
pub use hotspots::Hotspot;
pub use hotspots::HotspotReport;
pub use hotspots::HotspotsBuilder;
pub use pmi::PmiSample;
pub use pmi::counters_profile_event;
pub use pmi::per_pc_pmi_count;
pub use pmi::pmi_event_names;
pub use pmi::read_pmi_samples;
pub use samples::PcSample;
pub use samples::collect_pc_samples;
