//! Shared native-call lifetime policy, independent of the CPU entry ABI.

pub(super) fn dispatch_from_user(num: u64, args: [u64; 6]) -> u64 {
    let current_tid = crate::task::current_thread_id();
    let current_slot = crate::task::current_thread_slot();

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(true));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(true));
    }

    let ret = super::dispatch(num, args[0], args[1], args[2], args[3], args[4], args[5]);
    if current_tid.is_some_and(|id| {
        crate::task::with_thread(id, |thread| {
            thread.state() == crate::task::ThreadState::Terminated
        })
        .unwrap_or(false)
    }) {
        crate::task::exit_current_task(0);
    }

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(false));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(false));
    }

    ret
}
