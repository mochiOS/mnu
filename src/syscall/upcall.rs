use crate::task::{
    HandleRights, KernelObject, ObjectHandleEntry, ThreadUpcallError, UserUpcallContext,
};

use super::{SUCCESS, SavedSyscallFrame};

const THREAD_HANDLE_RIGHTS: HandleRights = HandleRights::WAIT
    .union(HandleRights::SIGNAL)
    .union(HandleRights::DUPLICATE)
    .union(HandleRights::TRANSFER);

pub fn install(config_ptr: u64, config_len: u64) -> u64 {
    use mnu_abi::status::Error;
    if config_len != core::mem::size_of::<mnu_abi::ThreadUpcallConfig>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    if config_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let mut config = mnu_abi::ThreadUpcallConfig::default();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut config as *mut mnu_abi::ThreadUpcallConfig).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadUpcallConfig>(),
        )
    };
    if let Err(error) = super::copy_from_user_native(config_ptr, bytes) {
        return error.into_raw();
    }
    if config.entry == 0
        || config.stack_size < 16
        || config.flags & !mnu_abi::THREAD_UPCALL_EXCEPTIONS != 0
        || config.reserved != [0; 3]
        || !super::validate_user_ptr(config.entry, 1)
        || !super::validate_user_ptr(config.stack_base, config.stack_size)
    {
        return Error::InvalidArgument.into_raw();
    }
    if config.defer_word != 0 {
        if config.defer_word & 3 != 0 || !super::is_canonical_user_range(config.defer_word, 4) {
            return Error::InvalidArgument.into_raw();
        }
        if let Err(error) = super::address_wait::read_upcall_defer_word(config.defer_word) {
            return error;
        }
    }
    let Some(stack_end) = config.stack_base.checked_add(config.stack_size) else {
        return Error::InvalidArgument.into_raw();
    };
    // Exception callbacks have a seventh C argument at RSP+8. Leave another
    // sixteen bytes above the return slot while retaining RSP % 16 == 8.
    let frame_bytes = if config.flags & mnu_abi::THREAD_UPCALL_EXCEPTIONS != 0 {
        24
    } else {
        8
    };
    let stack_top = (stack_end & !0xf).saturating_sub(frame_bytes);
    if stack_top < config.stack_base {
        return Error::InvalidArgument.into_raw();
    }
    if let Err(error) = super::copy_to_user_native(stack_top, &0u64.to_ne_bytes()) {
        return error.into_raw();
    }
    let Some(thread_id) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    crate::task::with_thread_mut(thread_id, |thread| {
        thread.install_upcall(
            config.entry,
            stack_top,
            config.flags & mnu_abi::THREAD_UPCALL_EXCEPTIONS != 0,
            config.defer_word,
        )
    })
    .map(|result| match result {
        Ok(()) => SUCCESS,
        Err(ThreadUpcallError::Active) => Error::NotReady.into_raw(),
        Err(_) => Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

pub fn create_thread_handle() -> u64 {
    use mnu_abi::status::Error;
    let Some(thread_id) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    let Some(process_id) = crate::task::with_thread(thread_id, |thread| thread.process_id()) else {
        return Error::NotReady.into_raw();
    };
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Thread(thread_id),
                THREAD_HANDLE_RIGHTS,
            ))
            .map(|handle| u64::from(handle.raw()))
            .unwrap_or_else(|| Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

pub fn interrupt(handle: u64, payload: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match super::handle::object_native(handle, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Thread(thread_id) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let result = crate::task::with_thread_mut(thread_id, |thread| thread.enqueue_upcall(payload));
    match result {
        Some(Ok(())) => {
            crate::task::wake_registered_waiter(thread_id);
            SUCCESS
        }
        Some(Err(ThreadUpcallError::QueueFull)) => Error::ResourceUnavailable.into_raw(),
        Some(Err(_)) => Error::InvalidArgument.into_raw(),
        None => Error::NotFound.into_raw(),
    }
}

pub fn thread_status(handle: u64, output: u64) -> u64 {
    use mnu_abi::status::Error;
    if output == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let object = match super::handle::object_native(handle, HandleRights::WAIT) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Thread(thread_id) = object else {
        return Error::InvalidArgument.into_raw();
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
        return Error::NotFound.into_raw();
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&status as *const mnu_abi::ThreadStatus).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadStatus>(),
        )
    };
    match super::copy_to_user_native(output, bytes) {
        Ok(()) => SUCCESS,
        Err(error) => error.into_raw(),
    }
}

pub fn return_from_context(token: u64, context_ptr: u64, context_len: u64) -> u64 {
    use mnu_abi::status::Error;
    let Some(thread_id) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    if context_len != core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    if context_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    match crate::task::with_thread(thread_id, |thread| thread.upcall_snapshot(token)) {
        Some(Ok(_)) => {}
        Some(Err(_)) => return Error::InvalidArgument.into_raw(),
        None => return Error::NotReady.into_raw(),
    }
    let mut snapshot = core::mem::MaybeUninit::<mnu_abi::ThreadUpcallSnapshot>::zeroed();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(snapshot.as_mut_ptr().cast::<u8>(), context_len as usize)
    };
    if let Err(error) = super::copy_from_user_native(context_ptr, bytes) {
        return error.into_raw();
    }
    // All fields are integers/byte arrays; every initialized bit pattern
    // is a Rust value. Hardware validity is checked before committing it.
    let snapshot = unsafe { snapshot.assume_init() };
    let Some(context) = return_context(&snapshot) else {
        return Error::InvalidArgument.into_raw();
    };
    crate::task::with_thread_mut(thread_id, |thread| {
        thread.request_upcall_return_context(token, context, snapshot.fx_state)
    })
    .map(|result| match result {
        Ok(()) => SUCCESS,
        Err(_) => Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

pub fn restore_context(context_ptr: u64, context_len: u64) -> u64 {
    use mnu_abi::status::Error;
    let Some(thread_id) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    if context_len != core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    if context_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let mut snapshot = core::mem::MaybeUninit::<mnu_abi::ThreadUpcallSnapshot>::zeroed();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(snapshot.as_mut_ptr().cast::<u8>(), context_len as usize)
    };
    if let Err(error) = super::copy_from_user_native(context_ptr, bytes) {
        return error.into_raw();
    }
    let snapshot = unsafe { snapshot.assume_init() };
    let Some(context) = return_context(&snapshot).filter(|context| context.user_rsp >= 16) else {
        return Error::InvalidArgument.into_raw();
    };
    crate::task::with_thread_mut(thread_id, |thread| {
        thread.request_context_restore(context, snapshot.fx_state)
    })
    .map(|result| match result {
        Ok(()) => SUCCESS,
        Err(ThreadUpcallError::Active) => Error::NotReady.into_raw(),
        Err(_) => Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

pub fn return_from(token: u64) -> u64 {
    use mnu_abi::status::Error;
    let Some(thread_id) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    crate::task::with_thread_mut(thread_id, |thread| thread.request_upcall_return(token))
        .map(|result| match result {
            Ok(()) => SUCCESS,
            Err(ThreadUpcallError::InvalidToken) => Error::InvalidArgument.into_raw(),
            Err(_) => Error::NotReady.into_raw(),
        })
        .unwrap_or_else(|| Error::NotReady.into_raw())
}

fn return_context(snapshot: &mnu_abi::ThreadUpcallSnapshot) -> Option<UserUpcallContext> {
    // Only user-modifiable arithmetic/debug flags are accepted. In particular
    // IOPL, NT, VM and virtual-interrupt flags must never reach IRET/FXRSTOR.
    const REQUIRED: u64 = (1 << 1) | (1 << 9);
    const ALLOWED: u64 = REQUIRED
        | (1 << 0)
        | (1 << 2)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | (1 << 10)
        | (1 << 11)
        | (1 << 16)
        | (1 << 18)
        | (1 << 21);
    if snapshot.rflags & REQUIRED != REQUIRED || snapshot.rflags & !ALLOWED != 0 {
        return None;
    }
    let registers = &snapshot.registers;
    let context = UserUpcallContext {
        user_rip: snapshot.instruction,
        user_rsp: snapshot.stack_pointer,
        user_rflags: snapshot.rflags,
        rdi: snapshot.argument,
        rax: registers.rax,
        rbx: registers.rbx,
        rcx: registers.rcx,
        rdx: registers.rdx,
        rsi: registers.rsi,
        rbp: registers.rbp,
        r8: registers.r8,
        r9: registers.r9,
        r10: registers.r10,
        r11: registers.r11,
        r12: registers.r12,
        r13: registers.r13,
        r14: registers.r14,
        r15: registers.r15,
    };
    valid_user_return(&context).then_some(context)
}

pub fn inspect(token: u64, output: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    if length != core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let Some(id) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    let snapshot = match crate::task::with_thread(id, |thread| thread.upcall_snapshot(token)) {
        Some(Ok((context, fx_state))) => snapshot_context(context, fx_state),
        Some(Err(_)) => return Error::InvalidArgument.into_raw(),
        None => return Error::NotReady.into_raw(),
    };
    // Snapshot under the thread lock, then drop it before faultable usercopy.
    // Neither a failed copy nor edits to the output consume or alter delivery.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&snapshot as *const mnu_abi::ThreadUpcallSnapshot).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>(),
        )
    };
    match super::copy_to_user_native(output, bytes) {
        Ok(()) => SUCCESS,
        Err(error) => error.into_raw(),
    }
}

fn snapshot_context(
    context: UserUpcallContext,
    fx_state: [u8; 512],
) -> mnu_abi::ThreadUpcallSnapshot {
    mnu_abi::ThreadUpcallSnapshot {
        instruction: context.user_rip,
        stack_pointer: context.user_rsp,
        rflags: context.user_rflags,
        argument: context.rdi,
        registers: mnu_abi::ThreadInitialRegisters {
            rax: context.rax,
            rbx: context.rbx,
            rcx: context.rcx,
            rdx: context.rdx,
            rsi: context.rsi,
            rbp: context.rbp,
            r8: context.r8,
            r9: context.r9,
            r10: context.r10,
            r11: context.r11,
            r12: context.r12,
            r13: context.r13,
            r14: context.r14,
            r15: context.r15,
        },
        fx_state,
    }
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
    if !current_has_deliverable_upcall() {
        return false;
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
    // Native C callbacks enter with ordinary direction/debug flags. The
    // original flags remain in the kernel-owned return snapshot.
    context.user_rflags &= !((1 << 10) | (1 << 8) | (1 << 16));
    context.rdx = mnu_abi::THREAD_UPCALL_KIND_INTERRUPT;
    context.r8 = 0;
    context.r9 = 0;
    false
}

/// Only the current thread's own optional user word is consulted. Never hold
/// the thread table across faultable usercopy, and never consume a deferred
/// payload. A user word is scheduling input, not authority over another task.
pub(crate) fn current_has_deliverable_upcall() -> bool {
    let Some(id) = crate::task::current_thread_id() else {
        return false;
    };
    let Some(Some(pointer)) =
        crate::task::with_thread(id, |thread| thread.pending_upcall_defer_word())
    else {
        return false;
    };
    if pointer == 0 {
        return true;
    }
    super::address_wait::read_upcall_defer_word(pointer) == Ok(0)
}

/// A synchronous exception bypasses the asynchronous queue, but may not
/// replace an active delivery. All original registers remain kernel-owned.
pub(crate) fn prepare_user_exception(
    raw: &mut [u64; 21],
    address: u64,
    cause: mnu_abi::MemoryFaultCause,
) -> bool {
    let mut frame = [0; 20];
    frame[..15].copy_from_slice(&raw[..15]);
    frame[15..].copy_from_slice(&raw[16..]);
    if frame[16] & 3 != 3 {
        return false;
    }
    let mut context = read_interrupt_context(&frame);
    if !valid_user_return(&context) {
        return false;
    }
    let Some(id) = crate::task::current_thread_id() else {
        return false;
    };
    let Some(delivery) =
        crate::task::with_thread_mut(id, |thread| thread.begin_exception_upcall(context, 14))
            .flatten()
    else {
        return false;
    };
    // No thread-table lock is held across faultable usercopy. If this stack
    // became inaccessible, the caller retains its native fatal-fault path;
    // never enter the callback with missing or stale exception metadata.
    if super::copy_to_user(delivery.stack_top + 8, &(cause as u64).to_ne_bytes()).is_err() {
        return false;
    }
    context.user_rip = delivery.entry;
    context.user_rsp = delivery.stack_top;
    context.rdi = delivery.payload;
    context.rsi = delivery.token;
    context.user_rflags &= !((1 << 10) | (1 << 8) | (1 << 16));
    context.rdx = mnu_abi::THREAD_UPCALL_KIND_EXCEPTION;
    context.rcx = address;
    context.r8 = raw[15];
    context.r9 = frame[15];
    write_interrupt_context(&mut frame, context);
    raw[..15].copy_from_slice(&frame[..15]);
    raw[16..].copy_from_slice(&frame[15..]);
    true
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
    // Only a kernel-validated, current-thread continuation reaches here.
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
