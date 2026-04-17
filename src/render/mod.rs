//! Output formatting helpers for human consumers. Inherent `to_text` /
//! `render` methods on the report types live in `annotate.rs` and
//! `text.rs` here.

pub mod annotate;
pub mod color;
pub mod text;

pub use annotate::AnnotateMode;
pub use annotate::AnnotateRenderOptions;
pub use color::ColorMode;
pub use color::Palette;
