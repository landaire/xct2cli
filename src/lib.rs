//! Library + CLI for transforming Xcode Instruments traces.

pub mod analysis;
pub mod error;
pub mod render;
pub mod symbol;
pub mod trace;
pub mod xctrace;
pub mod xml;

pub use error::Error;
pub use error::Result;
pub use trace::Trace;
pub use trace::TraceBundle;
