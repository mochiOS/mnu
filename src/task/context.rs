use crate::task::ids::ThreadId;
use crate::task::thread::THREAD_QUEUE;

pub(super) use crate::arch::fp::State as FloatingPointState;
pub use crate::arch::context::{switch_context, Context};

/// CPUごとの初回スイッチ用ダミーコンテキスト（保存値は参照されない）。
static mut INITIAL_DUMMY_CONTEXTS: [Context; crate::percpu::MAX_CPUS] =
    [const { Context::new() }; crate::percpu::MAX_CPUS];

fn initial_dummy_context() -> *mut Context {
    let cpu = crate::percpu::current_cpu_id();
    unsafe { core::ptr::addr_of_mut!(INITIAL_DUMMY_CONTEXTS[cpu]) }
}
/// 別スレッドへ切替（通常呼び出し経路）
///
/// # Safety
/// 呼び出し側は `next_id` が有効な実行可能スレッドであることを保証する必要がある。
pub unsafe fn switch_to_thread(current_id: Option<ThreadId>, next_id: ThreadId) {
    let queue = THREAD_QUEUE.lock();
    let next_slot = match queue.slot_index(next_id) {
        Some(slot) => slot,
        None => return,
    };
    drop(queue);
    switch_to_thread_with_slots(current_id, next_id, next_slot);
}

/// 別スレッドへ切替（通常呼び出し経路）
///
/// # Safety
/// 呼び出し側は `next_id` が有効な実行可能スレッドであることを保証する必要がある。
pub unsafe fn switch_to_thread_with_slots(
    current_id: Option<ThreadId>,
    next_id: ThreadId,
    next_slot: usize,
) {
    // コンテキストスイッチ中は割り込みを禁止する
    // ロック解放からコンテキストスイッチまでの間に割り込みが入ると不整合が起きる可能性があるため
    crate::arch::interrupts::disable();
    let mut queue = THREAD_QUEUE.lock();

    let (old_ctx_ptr, current_process_id) = if let Some(id) = current_id {
        let current_thread = queue.get_mut(id);
        if let Some(thread) = current_thread {
            if !thread.is_kernel_stack_guard_intact() {
                let bottom = thread.kernel_stack_bottom();
                let top = thread.kernel_stack_top();
                drop(queue);
                crate::error!(
                    "Kernel stack guard corrupted: tid={:?}, kstack=[{:#x}..{:#x})",
                    id,
                    bottom,
                    top
                );
                crate::audit::log(
                    crate::audit::AuditEventKind::Quarantine,
                    "context switch detected kernel stack corruption",
                );
                crate::task::terminate_thread(id);
                return;
            }
            let ptr = thread.context_mut() as *mut Context;
            let pid = thread.process_id();
            (ptr, Some(pid))
        } else {
            return; // 現在のスレッドが見つからない
        }
    } else {
        // 現在のスレッドがない場合（初回スイッチ）はダミーに書き込む（値は捨てられる）
        (initial_dummy_context(), None)
    };

    // 次のスレッドのコンテキストへのポインタとカーネルスタックトップを取得
    let resolved_next_slot = if queue
        .get_slot(next_slot)
        .is_some_and(|thread| thread.id() == next_id)
    {
        Some(next_slot)
    } else {
        queue.slot_index(next_id)
    };
    let (new_context_ptr, next_kstack_top, next_process_id, next_fs_base, _next_in_syscall) =
        if let Some(thread) = resolved_next_slot.and_then(|slot| queue.get_slot(slot)) {
            if thread.state() == super::ThreadState::Terminated {
                return;
            }
            let ptr = thread.context() as *const Context;
            let kstack = thread.kernel_stack_top();
            let saved_rsp = thread.context().stack_pointer();
            if saved_rsp < thread.kernel_stack_bottom() || saved_rsp >= kstack {
                crate::error!(
                    "Refusing invalid kernel context: tid={:?} pid={:?} thread='{}' rip={:#x} rsp={:#x} kstack=[{:#x}..{:#x}]",
                    next_id,
                    thread.process_id(),
                    thread.name(),
                    thread.context().instruction_pointer(),
                    saved_rsp,
                    thread.kernel_stack_bottom(),
                    kstack,
                );
                drop(queue);
                crate::arch::interrupts::disable();
                loop {
                    crate::arch::wait_for_interrupt();
                }
            }
            let pid = thread.process_id();
            let fs = thread.fs_base();
            let in_syscall = thread.in_syscall();
            (ptr, kstack, pid, fs, in_syscall)
        } else {
            return; // 次のスレッドが見つからない
        };

    let outgoing_marker =
        crate::percpu::begin_thread_switch(current_id.map(|id| id.as_u64()).unwrap_or(0));
    // Publish the incoming CPU reference while the queue still owns both
    // contexts, so remote removal cannot miss the selection/handoff window.
    crate::task::set_current_thread(Some(next_id), resolved_next_slot);
    drop(queue);
    crate::syscall::syscall_entry::switch_to_kernel_page_table();

    // Select the native interrupt/syscall entry stack before publishing CPU state.
    crate::syscall::syscall_entry::install_kernel_stack(next_kstack_top);
    // SYSCALL 入口の swapgs により IA32_KERNEL_GS_BASE がユーザー値へ一時退避されるため、
    // ブロッキング syscall 中に他スレッドへ切り替える前に per-CPU GS ベースへ戻しておく。
    crate::percpu::install_current_cpu_state();
    let predictor_domain_changed = current_process_id != Some(next_process_id);
    if predictor_domain_changed {
        crate::cpu::branch_predictor_barrier();
    }
    crate::cpu::reassert_runtime_hardening();

    // 次のスレッドの FS ベースを復元 (TLS)
    unsafe {
        crate::arch::tls::write_user_base(next_fs_base);
    }

    // switch_context はカーネル管理領域上の Context とカーネルスタックを読む。
    // ユーザー CR3 に切り替えてから実行すると、KPTI で外した kernel heap 参照が
    // kernel-mode page fault になるため、実際の user CR3 への切替は iretq 直前に行う。
    switch_context(old_ctx_ptr, new_context_ptr, outgoing_marker);
}
