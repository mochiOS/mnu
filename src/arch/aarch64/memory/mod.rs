//! VM-facing address and descriptor types. Logical flags retain the shared
//! VM policy representation; only this backend encodes AArch64 hardware bits.
mod address;
pub mod paging;
pub use address::{PhysAddr, VirtAddr};
