//! Native exception-entry setup. Thread/VM ownership is shared; CPU register
//! transitions are selected here instead of being assumed by every caller.
#[cfg(target_arch = "x86_64")]
#[path = "../arch/x86_64/syscall_entry.rs"]
mod selected;
#[cfg(target_arch = "aarch64")]
#[path = "../arch/aarch64/syscall_entry.rs"]
mod selected;
pub use selected::*;

pub fn current_thread_user_page_table() -> Option<u64> {
    if let Some(slot) = crate::task::current_thread_slot() {
        if let Some(pid) = crate::task::with_thread_at_slot(slot, |t| t.process_id()) {
            if let Some(pt) = crate::task::with_process(pid, |p| p.page_table()).flatten() {
                return Some(pt);
            }
        }
    }

    let tid = crate::task::current_thread_id()?;
    let pid = crate::task::with_thread(tid, |t| t.process_id())?;

    crate::task::with_process(pid, |p| p.page_table()).flatten()
}

pub fn switch_to_current_thread_user_page_table() {
    if let Some(user_pt) = current_thread_user_page_table() {
        crate::mem::paging::switch_page_table(user_pt);
    }
}
