//! Native fault adapters share VM-serialized stack growth and admission.

/// ユーザースタックの自動拡張を試みる。
/// fault_addr がスタック下端の直下にある場合、新しいページをマップして true を返す。
/// 最大スタックサイズは 8 MiB。
pub(super) fn try_grow_user_stack(fault_addr: u64) -> bool {
    use crate::mem::user_stack::MAX_INITIAL_STACK_BYTES as MAX_STACK_SIZE;

    let tid = match crate::task::current_thread_id() {
        Some(t) => t,
        None => return false,
    };
    let pid = match crate::task::with_thread(tid, |t| t.process_id()) {
        Some(p) => p,
        None => return false,
    };
    // Capture, admission, PTE edits and metadata publication share the VM
    // writer lock with faults/unmap/resize. A reservation is not stack space,
    // even when its backing is absent and its PTEs are currently unused.
    crate::task::process::with_process_vm(pid, |process, edit| {
        let stack_bottom = process.stack_bottom();
        let stack_top = process.stack_top();
        let Some(_page_table) = process.page_table() else {
            return false;
        };
        if stack_bottom == 0 || stack_top == 0 || fault_addr >= stack_bottom {
            return false;
        }
        // The total limit is relative to the fixed top, not the moving bottom.
        if fault_addr < stack_top.saturating_sub(MAX_STACK_SIZE) {
            return false;
        }
        let new_page = fault_addr & !4095;
        let map_size = stack_bottom - new_page;
        if crate::mem::user_stack::collides(process, new_page, map_size) {
            return false;
        }
        if edit
            .map_segment(new_page, 0, map_size, &[], true, false)
            .is_err()
        {
            return false;
        }
        process.set_stack_bottom(new_page);
        true
    })
    .unwrap_or(false)
}
