//! Native address and page-table types exposed at the architecture boundary.
//! Shared VM ownership/backing code uses this surface rather than an ISA crate.
pub use x86_64::structures::paging;
pub use x86_64::{PhysAddr, VirtAddr};

use paging::{PhysFrame, Size4KiB};
use x86_64::registers::control::{Cr3, Cr3Flags};

/// x86 uses one root for both privileged and user translations.
pub fn active_kernel_root() -> PhysFrame<Size4KiB> {
    Cr3::read().0
}

pub fn active_user_root() -> PhysFrame<Size4KiB> {
    Cr3::read().0
}

pub fn is_root_active(physical: u64) -> bool {
    active_user_root().start_address().as_u64() == physical
}

/// # Safety
/// The retained root must map the current code/stack and all required kernel
/// ranges. Its ownership and concurrent use are managed by the VM layer.
pub unsafe fn activate_user_root(frame: PhysFrame<Size4KiB>) {
    unsafe { Cr3::write(frame, Cr3Flags::empty()) };
}

/// # Safety
/// Same mapping/lifetime requirements as `activate_user_root`.
pub unsafe fn activate_kernel_root(frame: PhysFrame<Size4KiB>) {
    unsafe { activate_user_root(frame) };
}

pub fn flush_page_local(address: VirtAddr) {
    x86_64::instructions::tlb::flush(address);
}

/// Includes global mappings and cached PCID contexts. Call with interrupts
/// disabled and the CPU's translation context stable.
pub fn flush_all_local() {
    unsafe {
        let flags: u64;
        core::arch::asm!("mov {}, cr4", out(reg) flags, options(nostack, preserves_flags));
        core::arch::asm!("mov cr4, {}", in(reg) (flags ^ (1u64 << 7)), options(nostack, preserves_flags));
        core::arch::asm!("mov cr4, {}", in(reg) flags, options(nostack, preserves_flags));
    }
}
