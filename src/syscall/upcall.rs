use crate::task::{
    HandleRights, KernelObject, ObjectHandleEntry, ThreadUpcallError, UserUpcallContext,
};

use super::{EAGAIN, EBADF, EFAULT, EINVAL, ENOSPC, ESRCH, SUCCESS, SavedSyscallFrame};

const THREAD_HANDLE_RIGHTS: HandleRights = HandleRights::SIGNAL
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
    let Some(thread_id) = crate::task::current_thread_id() else {
        return;
    };
    if let Some(context) = crate::task::with_thread_mut(thread_id, |thread| {
        thread.take_restored_upcall_context()
    })
    .flatten()
    {
        write_context(frame, context);
        return;
    }

    let context = read_context(frame);
    let Some(delivery) = crate::task::with_thread_mut(thread_id, |thread| {
        thread.begin_upcall(context)
    })
    .flatten()
    else {
        return;
    };
    frame.user_rip = delivery.entry;
    frame.user_rsp = delivery.stack_top;
    frame.arg0 = delivery.payload;
    frame.arg1 = delivery.token;
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
