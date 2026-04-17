//! Mach-O + DWARF symbolication for instruction-level drilldowns.

pub mod macho;

pub use macho::BinaryInfo;
pub use macho::ImageLoad;
pub use macho::InlinedFrame;
pub use macho::SlideCandidate;
pub use macho::SymbolicatedFrame;
pub use macho::Symbolicator;
pub use macho::SymbolicatorOptions;
pub use macho::binary_info;
pub use macho::enumerate_slides;
pub use macho::read_image_loads;
pub use macho::slide_from_kdebug;
