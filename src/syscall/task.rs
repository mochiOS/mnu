//! タスク関連システムコール

use mnu_abi::status::Error;

pub fn yield_now() -> u64 {
    crate::task::yield_now();
    0
}

/// thread_create syscall.
///
/// Creates a new usermode thread in the current process. Returns its native
/// identity or a status::Error; POSIX thread policy remains in userspace.
pub fn thread_create(context_ptr: u64, context_len: u64) -> u64 {
    if context_len != core::mem::size_of::<mnu_abi::ThreadCreateContext>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    if context_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let mut context = mnu_abi::ThreadCreateContext::default();
    let context_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut context as *mut mnu_abi::ThreadCreateContext).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadCreateContext>(),
        )
    };
    if let Err(error) = crate::syscall::copy_from_user_native(context_ptr, context_bytes) {
        return error.into_raw();
    }
    if context.entry == 0
        || context.stack_pointer < 16
        || context.flags != 0
        || context.reserved != [0; 3]
    {
        return Error::InvalidArgument.into_raw();
    }
    if !crate::syscall::validate_user_ptr(context.entry, 1)
        || !crate::syscall::validate_user_ptr(context.stack_pointer - 16, 16)
        || (context.thread_local_base != 0
            && !crate::syscall::validate_user_ptr(context.thread_local_base, 8))
    {
        return Error::InvalidAddress.into_raw();
    }
    let current_tid = match crate::task::current_thread_id() {
        Some(tid) => tid,
        None => return Error::NotReady.into_raw(),
    };
    let pid = match crate::task::with_thread(current_tid, |t| t.process_id()) {
        Some(pid) => pid,
        None => return Error::NotReady.into_raw(),
    };
    let Some(_creation) = crate::task::image_transition::begin_thread_creation(pid) else {
        return Error::NotReady.into_raw();
    };
    let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
    let page_table = crate::task::with_process(pid, |process| process.page_table())
        .flatten()
        .unwrap_or(0);
    let kstack = match crate::task::allocate_kernel_stack_in_table(kstack_size, page_table) {
        Some(a) => a,
        None => return Error::ResourceUnavailable.into_raw(),
    };
    let registers = context.registers;
    let user_context = crate::task::thread::SyscallUserContext {
        rip: context.entry,
        rsp: context.stack_pointer,
        rflags: 0x202,
        rdi: context.argument,
        rsi: registers.rsi,
        rdx: registers.rdx,
        r8: registers.r8,
        r9: registers.r9,
        r10: registers.r10,
        rbp: registers.rbp,
        rbx: registers.rbx,
        r12: registers.r12,
        r13: registers.r13,
        r14: registers.r14,
        r15: registers.r15,
        rcx: registers.rcx,
        r11: registers.r11,
    };
    let thread = crate::task::Thread::new_user_resume(
        pid,
        user_context,
        registers.rax,
        context.thread_local_base,
        kstack,
        kstack_size,
    );
    match crate::task::add_thread(thread) {
        Some(tid) => tid.as_u64(),
        None => {
            crate::task::free_kernel_stack(kstack);
            Error::ResourceUnavailable.into_raw()
        }
    }
}
