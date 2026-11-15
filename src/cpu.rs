//! Native CPU initialization and protection mechanisms. Device discovery and
//! firmware ownership belong to the boot/platform layers.
pub use crate::arch::cpu::*;
pub use crate::arch::exception as context;
