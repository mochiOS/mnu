//! Retained boot metadata and native CPU startup selection.
pub use crate::arch::smp::*;
use crate::BootInfo;
use core::sync::atomic::{AtomicU64, Ordering};

static BOOT_INFO_PTR: AtomicU64 = AtomicU64::new(0);

pub fn set_boot_info_addr(address: u64) {
    BOOT_INFO_PTR.store(address, Ordering::Release);
}

pub fn boot_info() -> Option<&'static BootInfo> {
    let address = BOOT_INFO_PTR.load(Ordering::Acquire);
    if address == 0 {
        None
    } else {
        // The boot frontend retains its immutable kernel-owned BootInfo.
        Some(unsafe { &*(address as *const BootInfo) })
    }
}
