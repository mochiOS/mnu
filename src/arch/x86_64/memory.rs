//! Native address and page-table types exposed at the architecture boundary.
//! Shared VM ownership/backing code uses this surface rather than an ISA crate.
pub use x86_64::structures::paging;
pub use x86_64::{PhysAddr, VirtAddr};
