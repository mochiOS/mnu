//! CPU-local scheduling state. Hardware identity and exception-entry storage
//! are implemented by the selected architecture, independently of thread TLS.
use core::sync::atomic::{AtomicU64, Ordering};

pub const MAX_CPUS: usize = 64;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/percpu.rs"]
mod selected;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/percpu.rs"]
mod selected;
pub use selected::*;

#[repr(C)]
struct PerCpuState {
    kernel_page_table_root: AtomicU64,
    syscall_kernel_rsp: AtomicU64,
    current_thread_id: AtomicU64,
    switching_from_thread_id: AtomicU64,
    current_thread_slot: AtomicU64,
    syscall_user_rsp_tmp: AtomicU64,
}

impl PerCpuState {
    const fn new() -> Self {
        Self {
            kernel_page_table_root: AtomicU64::new(0),
            syscall_kernel_rsp: AtomicU64::new(0),
            current_thread_id: AtomicU64::new(0),
            switching_from_thread_id: AtomicU64::new(0),
            current_thread_slot: AtomicU64::new(u64::MAX),
            syscall_user_rsp_tmp: AtomicU64::new(0),
        }
    }
}

static CPU_STATES: [PerCpuState; MAX_CPUS] = [const { PerCpuState::new() }; MAX_CPUS];

#[inline]
fn state_for_current_cpu() -> &'static PerCpuState {
    &CPU_STATES[current_cpu_id()]
}

pub fn kernel_page_table_root() -> u64 {
    state_for_current_cpu()
        .kernel_page_table_root
        .load(Ordering::SeqCst)
}

#[cfg(target_arch = "x86_64")]
pub fn kernel_cr3() -> u64 {
    kernel_page_table_root()
}

pub fn set_syscall_kernel_rsp(rsp: u64) {
    state_for_current_cpu()
        .syscall_kernel_rsp
        .store(rsp, Ordering::SeqCst);
    // x86 has a separate KPTI entry page. ARM's trusted EL1 stack is retained
    // by the exception/continuation machinery, independent of userspace TLS.
    #[cfg(target_arch = "x86_64")]
    selected::set_syscall_entry_stack(rsp);
}

pub fn syscall_kernel_rsp() -> u64 {
    state_for_current_cpu()
        .syscall_kernel_rsp
        .load(Ordering::SeqCst)
}

pub fn current_thread_raw_id() -> u64 {
    state_for_current_cpu()
        .current_thread_id
        .load(Ordering::SeqCst)
}

/// Called under the thread-queue lock before publishing the incoming thread.
/// The outgoing context remains in use until assembly has switched stacks.
pub(crate) fn begin_thread_switch(outgoing: u64) -> *mut u64 {
    let marker = &state_for_current_cpu().switching_from_thread_id;
    marker.store(outgoing, Ordering::SeqCst);
    marker.as_ptr()
}

/// Thread-queue ownership serializes incoming-thread publication with removal.
/// A nonzero handoff marker also protects the outgoing stack and context after
/// current_thread_id has already changed to the incoming execution context.
pub(crate) fn thread_is_cpu_referenced(thread_id: u64) -> bool {
    thread_id != 0
        && CPU_STATES.iter().any(|state| {
            state.current_thread_id.load(Ordering::SeqCst) == thread_id
                || state.switching_from_thread_id.load(Ordering::SeqCst) == thread_id
        })
}

pub fn set_current_thread_raw_id(id: u64) {
    let current = current_thread_raw_id();
    if current == 2 || current == 3 || id == 2 || id == 3 {
        crate::debug!("[PERCPU] set_current_thread_raw_id {} -> {}", current, id);
    }
    state_for_current_cpu()
        .current_thread_id
        .store(id, Ordering::SeqCst);
}

pub fn current_thread_slot() -> Option<usize> {
    let raw = state_for_current_cpu()
        .current_thread_slot
        .load(Ordering::SeqCst);
    if raw == u64::MAX {
        None
    } else {
        Some(raw as usize)
    }
}

pub fn set_current_thread_slot(slot: Option<usize>) {
    let raw = slot.map(|value| value as u64).unwrap_or(u64::MAX);
    let current = state_for_current_cpu()
        .current_thread_slot
        .load(Ordering::SeqCst);
    if current == 2 || current == 3 || raw == 2 || raw == 3 || raw > 1024 {
        if current == u64::MAX {
            if raw == u64::MAX {
                crate::debug!("[PERCPU] set_current_thread_slot None -> None");
            } else {
                crate::debug!("[PERCPU] set_current_thread_slot None -> {}", raw);
            }
        } else if raw == u64::MAX {
            crate::debug!("[PERCPU] set_current_thread_slot {} -> None", current);
        } else {
            crate::debug!("[PERCPU] set_current_thread_slot {} -> {}", current, raw);
        }
    }
    state_for_current_cpu()
        .current_thread_slot
        .store(raw, Ordering::SeqCst);
}
