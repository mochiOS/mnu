//! EL1 CPU-local state, indexed by admitted logical slots, never raw MPIDR.
use super::{PerCpuState, CPU_STATES, MAX_CPUS};
use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const UNASSIGNED: u64 = u64::MAX;
static HARDWARE_IDS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(UNASSIGNED) }; MAX_CPUS];
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn hardware_id() -> u64 {
    let value: u64;
    // SAFETY: MPIDR_EL1 is read at EL1; retain all four affinity levels.
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value & 0x0000_00ff_00ff_ffff
}

fn bind_current_cpu() {
    let count = CPU_COUNT.load(Ordering::Acquire);
    if count == 0 || count > MAX_CPUS || crate::arch::interrupts::are_enabled() {
        crate::arch::halt();
    }
    let hardware = hardware_id();
    let Some(slot) = HARDWARE_IDS[..count]
        .iter()
        .position(|id| id.load(Ordering::Relaxed) == hardware)
    else {
        // A firmware/guest CPU not admitted by the boot topology gets no slot.
        crate::arch::halt();
    };
    let base = &CPU_STATES[slot] as *const PerCpuState as u64;
    // SAFETY: Static kernel-owned state, selected from validated boot metadata.
    // IRQs remain masked until this CPU's vectors and scheduling state exist.
    unsafe {
        asm!("msr tpidr_el1, {}", "isb", in(reg) base, options(nostack, preserves_flags));
    }
}

pub(crate) fn configure_boot_cpu(info: &crate::BootInfo) {
    if info.validate().is_err()
        || info.bsp_hardware_id != hardware_id()
        || info.cpu_id_count == 0
        || crate::arch::interrupts::are_enabled()
        || CPU_COUNT
            .compare_exchange(0, MAX_CPUS + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        crate::arch::halt();
    }
    for (slot, &id) in info.cpu_hardware_ids[..info.cpu_id_count as usize]
        .iter()
        .enumerate()
    {
        HARDWARE_IDS[slot].store(id, Ordering::Relaxed);
    }
    CPU_COUNT.store(info.cpu_id_count as usize, Ordering::Release);
    bind_current_cpu();
}

/// Secondary entry must bind its own privileged register before using any
/// allocator, logger or scheduling state. Topology is published once by BSP.
pub(crate) fn enable_multiple_cpus() {
    bind_current_cpu();
}

#[inline]
pub fn current_cpu_id() -> usize {
    let base: u64;
    // SAFETY: A userspace thread cannot write TPIDR_EL1. Never dereference its
    // reset/firmware contents before checking the statically owned array.
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) base, options(nomem, nostack, preserves_flags));
    }
    let start = CPU_STATES.as_ptr() as u64;
    let stride = core::mem::size_of::<PerCpuState>() as u64;
    let count = CPU_COUNT.load(Ordering::Acquire);
    let offset = base.wrapping_sub(start);
    if count == 0 || count > MAX_CPUS || offset >= count as u64 * stride || offset % stride != 0 {
        crate::arch::halt();
    }
    (offset / stride) as usize
}

pub fn init_current_cpu(kernel_stack_top: u64) {
    if kernel_stack_top == 0 || kernel_stack_top & 15 != 0 || crate::arch::interrupts::are_enabled()
    {
        crate::arch::halt();
    }
    let state = &CPU_STATES[current_cpu_id()];
    state.kernel_page_table_root.store(
        crate::arch::memory::active_kernel_root()
            .start_address()
            .as_u64(),
        Ordering::SeqCst,
    );
    state
        .syscall_kernel_rsp
        .store(kernel_stack_top, Ordering::SeqCst);
    state.current_thread_id.store(0, Ordering::SeqCst);
    state.switching_from_thread_id.store(0, Ordering::SeqCst);
    state.current_thread_slot.store(u64::MAX, Ordering::SeqCst);
    state.syscall_user_rsp_tmp.store(0, Ordering::SeqCst);
}

pub fn init_boot_cpu(kernel_stack_top: u64) {
    init_current_cpu(kernel_stack_top);
}

pub fn install_current_cpu_state() {
    bind_current_cpu();
}
