//! Output formatting helpers for human and JSON consumers.

pub mod annotate;
pub mod text;

pub use annotate::AnnotateMode;
pub use annotate::AnnotateRenderOptions;
pub use annotate::render_annotated;
pub use text::render_counters;
pub use text::render_hotspots;
pub use text::render_toc;
