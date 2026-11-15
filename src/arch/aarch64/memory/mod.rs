//! VM-facing address and descriptor types. Logical flags retain the shared
//! VM policy representation; only this backend encodes AArch64 hardware bits.
mod address;
mod control;
pub mod paging;
pub use address::{PhysAddr, VirtAddr};
pub use control::{
    activate_kernel_root, activate_user_root, active_kernel_root, active_user_root,
    flush_all_local, flush_page_local, is_root_active,
};
pub(crate) use control::current_guest_physical;
