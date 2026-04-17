//! Mach-O + DWARF symbolication for instruction-level drilldowns.

pub mod macho;

pub use macho::BinaryInfo;
pub use macho::ImageLoad;
pub use macho::InlinedFrame;
pub use macho::SlideCandidate;
pub use macho::SymbolicatedFrame;
pub use macho::Symbolicator;
pub use macho::SymbolicatorOptions;
