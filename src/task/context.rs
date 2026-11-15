use crate::task::ids::ThreadId;
use crate::task::process::with_process;
use crate::task::thread::THREAD_QUEUE;

pub(super) use crate::arch::context::FxSaveArea;
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

    // TSSのRSP0とSYSCALL用カーネルスタックを更新
    crate::mem::tss::set_rsp0(next_kstack_top);
    crate::syscall::syscall_entry::update_kernel_rsp(next_kstack_top);
    // SYSCALL 入口の swapgs により IA32_KERNEL_GS_BASE がユーザー値へ一時退避されるため、
    // ブロッキング syscall 中に他スレッドへ切り替える前に per-CPU GS ベースへ戻しておく。
    crate::percpu::install_current_cpu_gs_base();
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

/// カーネルから直接ユーザーモードに入るためのヘルパ（最初のユーザスレッド用）
///
/// # Safety
/// `ctx` はユーザーモード復帰に必要な有効なレジスタ値/セグメント値を含んでいる必要がある。
pub unsafe fn enter_user_from_kernel(ctx: &Context) -> ! {
    let user_cs = crate::mem::gdt::user_code_selector() as u64 | 3;
    let user_ds = crate::mem::gdt::user_data_selector() as u64 | 3;

    core::arch::asm!(
        "cli",
        "mov rbx, {rbx}",
        "mov r12, {r12}",
        "mov r13, {r13}",
        "mov r14, {r14}",
        "mov r15, {r15}",
        "mov rbp, {rbp}",
        // iretq が CS/RIP/RFLAGS->(RSP/SS) を期待するので順に push
        "push {ss}",
        "push {user_rsp}",
        "push {rflags}",
        "push {cs}",
        "push {rip}",
        // restore user GS base from IA32_KERNEL_GS_BASE
        "swapgs",
        "iretq",
        rbx = in(reg) ctx.rbx,
        r12 = in(reg) ctx.r12,
        r13 = in(reg) ctx.r13,
        r14 = in(reg) ctx.r14,
        r15 = in(reg) ctx.r15,
        rbp = in(reg) ctx.rbp,
        ss = in(reg) user_ds,
        user_rsp = in(reg) ctx.rsp,
        rflags = in(reg) ctx.rflags,
        cs = in(reg) user_cs,
        rip = in(reg) ctx.rip,
        options(noreturn)
    )
}

/// 割込み内からの切替。呼び出し側で割込み時のレジスタを `saved` に収めて渡す。
///
/// # Safety
/// `saved` は現在スレッドの正しい保存コンテキストであり、`next_id` は有効な
/// 実行可能スレッドである必要がある。
pub unsafe fn switch_to_thread_from_isr(
    current_id: Option<ThreadId>,
    next_id: ThreadId,
    saved: Context,
) {
    let mut queue = THREAD_QUEUE.lock();

    let (old_ctx_ptr, current_process_id, current_priv) = if let Some(id) = current_id {
        if let Some(thread) = queue.get_mut(id) {
            if !thread.is_kernel_stack_guard_intact() {
                let bottom = thread.kernel_stack_bottom();
                let top = thread.kernel_stack_top();
                drop(queue);
                crate::error!(
                    "Kernel stack guard corrupted (ISR): tid={:?}, kstack=[{:#x}..{:#x})",
                    id,
                    bottom,
                    top
                );
                crate::audit::log(
                    crate::audit::AuditEventKind::Quarantine,
                    "isr context switch detected kernel stack corruption",
                );
                crate::task::terminate_thread(id);
                return;
            }
            let pid = thread.process_id();
            let priv_level =
                with_process(pid, |p| p.privilege()).unwrap_or(crate::task::PrivilegeLevel::Core);
            (thread.context_mut() as *mut Context, Some(pid), priv_level)
        } else {
            return;
        }
    } else {
        (
            initial_dummy_context(),
            None,
            crate::task::PrivilegeLevel::Core,
        )
    };

    let (
        _new_ctx_ptr,
        next_priv,
        next_kstack_top,
        next_fs_base,
        next_process_id,
        _next_in_syscall,
        next_slot,
    ) = if let Some(thread) = queue.get(next_id) {
        let ptr = thread.context() as *const Context;
        let proc = thread.process_id();
        let priv_level =
            with_process(proc, |p| p.privilege()).unwrap_or(crate::task::PrivilegeLevel::Core);
        let kstack = thread.kernel_stack_top();
        let fs = thread.fs_base();
        let in_syscall = thread.in_syscall();
        let slot = queue.slot_index(next_id).unwrap_or(0);
        (ptr, priv_level, kstack, fs, proc, in_syscall, slot)
    } else {
        return;
    };

    if !old_ctx_ptr.is_null() {
        unsafe {
            *old_ctx_ptr = saved;
        }
    }

    // Keep the outgoing reference conservatively until the next normal stack
    // handoff. This currently unused ISR entry has no assembly completion ack.
    let _ = crate::percpu::begin_thread_switch(current_id.map(|id| id.as_u64()).unwrap_or(0));
    crate::task::set_current_thread(Some(next_id), Some(next_slot));
    drop(queue);
    crate::syscall::syscall_entry::switch_to_kernel_page_table();

    // TSSのRSP0を更新
    crate::mem::tss::set_rsp0(next_kstack_top);

    // SYSCALL用カーネルスタックも更新 (次のスレッドのカーネルスタックを使う)
    crate::syscall::syscall_entry::update_kernel_rsp(next_kstack_top);
    // SYSCALL 入口の swapgs により IA32_KERNEL_GS_BASE がユーザー値へ一時退避されるため、
    // ブロッキング syscall 中に他スレッドへ切り替える前に per-CPU GS ベースへ戻しておく。
    crate::percpu::install_current_cpu_gs_base();
    let predictor_domain_changed =
        current_process_id != Some(next_process_id) || current_priv != next_priv;
    if predictor_domain_changed {
        crate::cpu::branch_predictor_barrier();
    }
    crate::cpu::reassert_runtime_hardening();

    // 次のスレッドの FS ベースを復元 (TLS)
    crate::arch::tls::write_user_base(next_fs_base);

    // ISR 経路でもコンテキスト復元中は必ず kernel CR3 を使う。
    // ユーザー空間への復帰時は trap/syscall の出口または usermode trampoline が
    // 復帰対象スレッドの user CR3 を設定する。
    if current_process_id != Some(next_process_id) {
        let kernel_cr3 = crate::percpu::kernel_cr3();
        if kernel_cr3 != 0 {
            crate::mem::paging::switch_page_table(kernel_cr3);
        }
    }

    if next_priv == crate::task::PrivilegeLevel::Core {
        core::arch::asm!(
            "cli",
            "mov rsp, rax",       // rsp = saved.rsp
            "mov rbp, {rbp_val}", // Restore rbp
            "mov rbx, {rbx_val}", // Restore rbx
            "push rcx",           // push rflags
            "popfq",              // restore rflags
            "jmp rdx",            // jump to rip

            // Fixed registers
            in("rax") saved.rsp,
            in("rcx") saved.rflags,
            in("rdx") saved.rip,

            in("r12") saved.r12,
            in("r13") saved.r13,
            in("r14") saved.r14,
            in("r15") saved.r15,
            in("rdi") saved.rdi,
            in("rsi") saved.rsi,

            // Compiler allocated registers (will use r8-r11)
            rbp_val = in(reg) saved.rbp,
            rbx_val = in(reg) saved.rbx,

            options(noreturn)
        );
    } else {
        // ユーザーモードへ iretq で遷移するための準備
        let user_cs = crate::mem::gdt::user_code_selector() as u64 | 3;
        let user_ds = crate::mem::gdt::user_data_selector() as u64 | 3;

        core::arch::asm!(
            "cli",
            "mov rbx, {rbx}",
            "mov r12, {r12}",
            "mov r13, {r13}",
            "mov r14, {r14}",
            "mov r15, {r15}",
            "mov rbp, {rbp}",
            // iretq が CS/RIP/RFLAGS->(RSP/SS) を期待するので順に push
            "push {ss}",
            "push {user_rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            // restore user GS base from IA32_KERNEL_GS_BASE
            "swapgs",
            "iretq",
            rbx = in(reg) saved.rbx,
            r12 = in(reg) saved.r12,
            r13 = in(reg) saved.r13,
            r14 = in(reg) saved.r14,
            r15 = in(reg) saved.r15,
            rbp = in(reg) saved.rbp,
            ss = in(reg) user_ds,
            user_rsp = in(reg) saved.rsp,
            rflags = in(reg) saved.rflags,
            cs = in(reg) user_cs,
            rip = in(reg) saved.rip,
            options(noreturn)
        );
    }
}
