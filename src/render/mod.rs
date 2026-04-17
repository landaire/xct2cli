//! Output formatting helpers for human consumers. Inherent `to_text` /
//! `render` methods on the report types live in `annotate.rs` and
//! `text.rs` here.

pub mod annotate;
pub mod text;

pub use annotate::AnnotateMode;
pub use annotate::AnnotateRenderOptions;
