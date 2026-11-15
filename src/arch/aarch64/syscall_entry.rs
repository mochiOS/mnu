//! AArch64 SVC entry and retained EL1/EL0 address-space selection.
use crate::arch::exception::ExceptionFrame;

/// SVC uses VBAR_EL1 installed by exception initialization, not x86 MSRs.
/// The privileged CPU-local pointer has already been bound from boot metadata.
pub fn init_syscall_current_cpu() {
    crate::percpu::init_current_cpu(crate::arch::stack_pointer());
    verify_kernel_page_table_before_rust();
}

pub fn init_syscall() {
    init_syscall_current_cpu();
}

pub fn update_kernel_rsp(stack: u64) {
    if stack == 0 || stack & 15 != 0 {
        crate::arch::halt();
    }
    crate::percpu::set_syscall_kernel_rsp(stack);
}

/// Retain the owned EL1 exception stack. The final EL0 transition installs it
/// in SP_EL1; a kernel continuation must retain its currently active SP.
pub fn install_kernel_stack(stack: u64) {
    update_kernel_rsp(stack);
}

/// TTBR1 is the retained privileged root, independently of process TTBR0.
/// No CR3-style switch is needed, but an unexpected root must never be accepted.
pub fn verify_kernel_page_table_before_rust() {
    let expected = crate::percpu::kernel_page_table_root();
    let active = crate::arch::memory::active_kernel_root()
        .start_address()
        .as_u64();
    if !crate::percpu::kernel_page_table_ready() || active != expected {
        crate::arch::halt();
    }
}

pub fn switch_to_kernel_page_table() -> u64 {
    verify_kernel_page_table_before_rust();
    0
}

/// Called only with the complete, kernel-owned frame retained on the current
/// thread's EL1 stack. IRQs remain masked until that frame is returned by ERET.
/// A rejected origin/immediate is left for ordinary exception policy.
pub(crate) fn handle_svc(frame: &mut ExceptionFrame) -> bool {
    let Some((number, arguments)) = frame.syscall_request() else {
        return false;
    };
    let Some(id) = retain_user_trap(frame) else {
        return false;
    };
    let result = crate::syscall::entry_dispatch::dispatch_from_user(number, arguments);
    // A blocking call may have switched stacks/TTBR0. Metadata and upcall
    // selection belong to the thread whose saved EL1 stack actually resumed.
    crate::arch::interrupts::disable();
    if !frame.set_syscall_result(result) {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
    crate::syscall::upcall::prepare_syscall_return(frame);
    finish_user_trap(frame, id)
}

/// Retain EL0 registers/TLS before a synchronous trap can block or schedule.
pub(crate) fn retain_user_trap(frame: &ExceptionFrame) -> Option<crate::task::ThreadId> {
    crate::arch::interrupts::disable();
    crate::percpu::install_current_cpu_state();
    verify_kernel_page_table_before_rust();
    let context = frame.user_context()?;
    let tls = unsafe { crate::arch::tls::read_user_base() };
    let id = crate::task::current_thread_id()?;
    if !context.valid() || tls > 0x0000_7fff_ffff_ffff {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
    if crate::task::with_thread_mut(id, |thread| {
        thread.set_syscall_user_context(context);
        thread.set_fs_base(tls);
    })
    .is_none()
    {
        return None;
    }

    Some(id)
}

/// Rejoin the current thread's TTBR0/TLS after a possibly blocking trap.
pub(crate) fn finish_user_trap(frame: &ExceptionFrame, id: crate::task::ThreadId) -> bool {
    crate::arch::interrupts::disable();
    if crate::task::current_thread_id() != Some(id) {
        crate::arch::halt();
    }
    if !frame.user_context().is_some_and(|context| context.valid()) {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
    let Some(root) = crate::syscall::syscall_entry::current_thread_user_page_table() else {
        crate::task::scheduler::exit_current_process(u64::MAX);
    };
    let Some(tls) = crate::task::with_thread(id, |thread| thread.fs_base()) else {
        crate::task::scheduler::exit_current_process(u64::MAX);
    };
    if root == 0 || root & 4095 != 0 || tls > 0x0000_7fff_ffff_ffff {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
    verify_kernel_page_table_before_rust();
    crate::cpu::reassert_runtime_hardening();
    crate::mem::paging::switch_page_table(root);
    unsafe { crate::arch::tls::write_user_base(tls) };
    true
}
