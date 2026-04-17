//! Library + CLI for transforming Xcode Instruments traces.

pub mod address;
pub mod analysis;
pub mod error;
pub mod render;
pub mod symbol;
pub mod trace;
pub mod xctrace;
pub mod xml;

pub use address::CoreId;
pub use address::FilePc;
pub use address::Pid;
pub use address::RuntimePc;
pub use address::SampleTime;
pub use address::Slide;
pub use error::Error;
pub use error::Result;
pub use trace::TraceBundle;
