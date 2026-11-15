//! EL1 translation registers. TTBR1 retains the privileged upper half while
//! process switches replace only TTBR0; neither register contains VM policy.
use super::{paging::PhysFrame, PhysAddr, VirtAddr};
use core::arch::asm;

const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;

pub fn active_kernel_root() -> PhysFrame {
    let value: u64;
    unsafe { asm!("mrs {}, ttbr1_el1", out(reg) value, options(nomem, nostack, preserves_flags)) };
    PhysFrame::containing_address(PhysAddr::new(value & ADDRESS_MASK))
}

pub fn active_user_root() -> PhysFrame {
    let value: u64;
    unsafe { asm!("mrs {}, ttbr0_el1", out(reg) value, options(nomem, nostack, preserves_flags)) };
    PhysFrame::containing_address(PhysAddr::new(value & ADDRESS_MASK))
}

pub fn is_root_active(physical: u64) -> bool {
    active_user_root().start_address().as_u64() == physical
        || active_kernel_root().start_address().as_u64() == physical
}

/// # Safety
/// EL1 must use the configured 4-KiB/48-bit regime with TCR.A1 == 0. The VM
/// retains a valid lower root within the CPU's PA range and excludes local
/// context changes. Kernel code/stack/vectors remain mapped in TTBR1.
pub unsafe fn activate_user_root(frame: PhysFrame) {
    // The shared scheduler does not yet allocate ASIDs. Use ASID 0 and discard
    // every old local context (including global entries) before returning.
    // Config::switch_lower_root is the separate explicitly owned-ASID API.
    unsafe {
        asm!("dsb ishst", "msr ttbr0_el1, {}", "isb", in(reg) frame.start_address().as_u64(), options(nostack, preserves_flags));
    }
    flush_all_local();
}

/// # Safety
/// The retained root must preserve the executing upper-half code, stack and
/// vectors with suitable permissions. Other CPUs may retain the old root; VM
/// ownership must keep it and its walk frames alive until they are quiescent.
pub unsafe fn activate_kernel_root(frame: PhysFrame) {
    unsafe {
        asm!("dsb ishst", "msr ttbr1_el1, {}", "isb", in(reg) frame.start_address().as_u64(), options(nostack, preserves_flags));
    }
    flush_all_local();
}

/// Invalidate this VA for every local ASID, including global translations.
pub fn flush_page_local(address: VirtAddr) {
    unsafe {
        asm!("dsb ishst", "tlbi vaae1, {}", "dsb ish", "isb",
            in(reg) (address.as_u64() >> 12) & ((1u64 << 44) - 1), options(nostack, preserves_flags));
    }
}

/// Complete local stage-1 invalidation. The caller keeps CPU context stable.
pub fn flush_all_local() {
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}
