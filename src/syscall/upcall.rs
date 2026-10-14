use crate::task::{
    HandleRights, KernelObject, ObjectHandleEntry, ThreadUpcallError, UserUpcallContext,
};

use super::{SavedSyscallFrame, EAGAIN, EBADF, EFAULT, EINVAL, ENOSPC, ESRCH, SUCCESS};

const THREAD_HANDLE_RIGHTS: HandleRights = HandleRights::WAIT
    .union(HandleRights::SIGNAL)
    .union(HandleRights::DUPLICATE)
    .union(HandleRights::TRANSFER);

pub fn install(config_ptr: u64, config_len: u64) -> u64 {
    if config_ptr == 0 || config_len != core::mem::size_of::<mnu_abi::ThreadUpcallConfig>() as u64 {
        return EINVAL;
    }
    let mut config = mnu_abi::ThreadUpcallConfig::default();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut config as *mut mnu_abi::ThreadUpcallConfig).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadUpcallConfig>(),
        )
    };
    if super::copy_from_user(config_ptr, bytes).is_err() {
        return EFAULT;
    }
    if config.entry == 0
        || config.stack_size < 16
        || config.flags != 0
        || config.reserved != [0; 4]
        || !super::validate_user_ptr(config.entry, 1)
        || !super::validate_user_ptr(config.stack_base, config.stack_size)
    {
        return EINVAL;
    }
    let Some(stack_end) = config.stack_base.checked_add(config.stack_size) else {
        return EINVAL;
    };
    let stack_top = (stack_end & !0xf).saturating_sub(8);
    if stack_top < config.stack_base {
        return EINVAL;
    }
    if super::copy_to_user(stack_top, &0u64.to_ne_bytes()).is_err() {
        return EFAULT;
    }
    let Some(thread_id) = crate::task::current_thread_id() else {
        return ESRCH;
    };
    crate::task::with_thread_mut(thread_id, |thread| {
        thread.install_upcall(config.entry, stack_top)
    })
    .map(|result| match result {
        Ok(()) => SUCCESS,
        Err(ThreadUpcallError::Active) => EAGAIN,
        Err(_) => EINVAL,
    })
    .unwrap_or(ESRCH)
}

pub fn create_thread_handle() -> u64 {
    let Some(thread_id) = crate::task::current_thread_id() else {
        return ESRCH;
    };
    let Some(process_id) = crate::task::with_thread(thread_id, |thread| thread.process_id()) else {
        return ESRCH;
    };
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Thread(thread_id),
                THREAD_HANDLE_RIGHTS,
            ))
            .map(|handle| u64::from(handle.raw()))
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(ESRCH)
}

pub fn interrupt(handle: u64, payload: u64) -> u64 {
    let object = match super::handle::object(handle, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error,
    };
    let KernelObject::Thread(thread_id) = object else {
        return EBADF;
    };
    let result = crate::task::with_thread_mut(thread_id, |thread| thread.enqueue_upcall(payload));
    match result {
        Some(Ok(())) => {
            crate::task::wake_registered_waiter(thread_id);
            SUCCESS
        }
        Some(Err(ThreadUpcallError::QueueFull)) => ENOSPC,
        Some(Err(_)) => EINVAL,
        None => ESRCH,
    }
}

pub fn thread_status(handle: u64, output: u64) -> u64 {
    if output == 0 {
        return EINVAL;
    }
    let object = match super::handle::object(handle, HandleRights::WAIT) {
        Ok(object) => object,
        Err(error) => return error,
    };
    let KernelObject::Thread(thread_id) = object else {
        return EBADF;
    };
    let Some(status) = crate::task::with_thread(thread_id, |thread| mnu_abi::ThreadStatus {
        thread_id: thread.id().as_u64(),
        process_id: thread.process_id().as_u64(),
        state: match thread.state() {
            crate::task::ThreadState::Ready => mnu_abi::THREAD_STATE_READY,
            crate::task::ThreadState::Running => mnu_abi::THREAD_STATE_RUNNING,
            crate::task::ThreadState::Blocked => mnu_abi::THREAD_STATE_BLOCKED,
            crate::task::ThreadState::Sleeping => mnu_abi::THREAD_STATE_SLEEPING,
            crate::task::ThreadState::Terminated => mnu_abi::THREAD_STATE_TERMINATED,
        },
        reserved: 0,
    }) else {
        return ESRCH;
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&status as *const mnu_abi::ThreadStatus).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadStatus>(),
        )
    };
    match super::copy_to_user(output, bytes) {
        Ok(()) => SUCCESS,
        Err(error) => error,
    }
}

pub fn return_from(token: u64) -> u64 {
    let Some(thread_id) = crate::task::current_thread_id() else {
        return ESRCH;
    };
    crate::task::with_thread_mut(thread_id, |thread| thread.request_upcall_return(token))
        .map(|result| match result {
            Ok(()) => SUCCESS,
            Err(ThreadUpcallError::InvalidToken) => EINVAL,
            Err(_) => EAGAIN,
        })
        .unwrap_or(ESRCH)
}

pub fn prepare_syscall_return(frame: &mut SavedSyscallFrame) {
    let mut context = read_context(frame);
    if prepare_context(&mut context) {
        resume_context(context);
    }
    write_context(frame, context);
}

/// The assembly interrupt entry owns these 15 GPR and five IRET slots.
/// Unlike SYSCALL, an interrupt does not clobber the user's RCX/R11.
pub fn prepare_interrupt_return(frame: &mut [u64; 20]) {
    if frame[16] & 3 != 3 {
        return;
    }
    let mut context = read_interrupt_context(frame);
    prepare_context(&mut context);
    if !valid_user_return(&context) {
        crate::task::scheduler::exit_current_process(-1);
    }
    write_interrupt_context(frame, context);
}

fn prepare_context(context: &mut UserUpcallContext) -> bool {
    let Some(thread_id) = crate::task::current_thread_id() else {
        return false;
    };
    if let Some(restored) =
        crate::task::with_thread_mut(thread_id, |thread| thread.take_restored_upcall_context())
            .flatten()
    {
        *context = restored;
        return true;
    }
    let Some(delivery) =
        crate::task::with_thread_mut(thread_id, |thread| thread.begin_upcall(*context)).flatten()
    else {
        return false;
    };
    context.user_rip = delivery.entry;
    context.user_rsp = delivery.stack_top;
    context.rdi = delivery.payload;
    context.rsi = delivery.token;
    false
}

fn valid_user_return(context: &UserUpcallContext) -> bool {
    context.user_rip != 0 && context.user_rip >> 47 == 0 && context.user_rsp >> 47 == 0
}

fn resume_context(context: UserUpcallContext) -> ! {
    if !valid_user_return(&context)
        || !super::syscall_entry::current_thread_user_page_table().is_some_and(|root| root != 0)
    {
        crate::task::scheduler::exit_current_process(-1);
    }
    let fs_base = crate::task::current_thread_id()
        .and_then(|id| crate::task::with_thread(id, |thread| thread.fs_base()))
        .unwrap_or(0);
    let registers = crate::task::thread::SyscallUserContext {
        rip: context.user_rip,
        rsp: context.user_rsp,
        rflags: context.user_rflags,
        rdi: context.rdi,
        rsi: context.rsi,
        rdx: context.rdx,
        r8: context.r8,
        r9: context.r9,
        r10: context.r10,
        rbp: context.rbp,
        rbx: context.rbx,
        r12: context.r12,
        r13: context.r13,
        r14: context.r14,
        r15: context.r15,
        rcx: context.rcx,
        r11: context.r11,
    };
    // Only an authenticated, kernel-retained upcall snapshot reaches here.
    // The ordinary syscall path still uses SYSRET; full restoration uses the
    // same validated IRET machinery as native address-space continuation.
    unsafe { crate::task::usermode::resume_usermode(registers, context.rax, fs_base) }
}

fn read_interrupt_context(frame: &[u64; 20]) -> UserUpcallContext {
    UserUpcallContext {
        user_rsp: frame[18],
        r15: frame[0],
        r14: frame[1],
        r13: frame[2],
        r12: frame[3],
        rbx: frame[11],
        rbp: frame[10],
        user_rflags: frame[17],
        user_rip: frame[15],
        r9: frame[6],
        r8: frame[7],
        r10: frame[5],
        rdx: frame[12],
        rsi: frame[9],
        rdi: frame[8],
        rax: frame[14],
        rcx: frame[13],
        r11: frame[4],
    }
}

fn write_interrupt_context(frame: &mut [u64; 20], context: UserUpcallContext) {
    frame[18] = context.user_rsp;
    frame[0] = context.r15;
    frame[1] = context.r14;
    frame[2] = context.r13;
    frame[3] = context.r12;
    frame[11] = context.rbx;
    frame[10] = context.rbp;
    frame[17] = context.user_rflags;
    frame[15] = context.user_rip;
    frame[6] = context.r9;
    frame[7] = context.r8;
    frame[5] = context.r10;
    frame[12] = context.rdx;
    frame[9] = context.rsi;
    frame[8] = context.rdi;
    frame[14] = context.rax;
    frame[13] = context.rcx;
    frame[4] = context.r11;
}

fn read_context(frame: &SavedSyscallFrame) -> UserUpcallContext {
    UserUpcallContext {
        user_rsp: frame.user_rsp,
        r15: frame.r15,
        r14: frame.r14,
        r13: frame.r13,
        r12: frame.r12,
        rbx: frame.rbx,
        rbp: frame.rbp,
        user_rflags: frame.user_rflags,
        user_rip: frame.user_rip,
        r9: frame.arg5,
        r8: frame.arg4,
        r10: frame.arg3,
        rdx: frame.arg2,
        rsi: frame.arg1,
        rdi: frame.arg0,
        rax: frame.num,
        rcx: frame.user_rip,
        r11: frame.user_rflags,
    }
}

fn write_context(frame: &mut SavedSyscallFrame, context: UserUpcallContext) {
    frame.user_rsp = context.user_rsp;
    frame.r15 = context.r15;
    frame.r14 = context.r14;
    frame.r13 = context.r13;
    frame.r12 = context.r12;
    frame.rbx = context.rbx;
    frame.rbp = context.rbp;
    frame.user_rflags = context.user_rflags;
    frame.user_rip = context.user_rip;
    frame.arg5 = context.r9;
    frame.arg4 = context.r8;
    frame.arg3 = context.r10;
    frame.arg2 = context.rdx;
    frame.arg1 = context.rsi;
    frame.arg0 = context.rdi;
    frame.num = context.rax;
}
