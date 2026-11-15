use crate::task::{
    HandleRights, KernelObject, ObjectHandleEntry, ThreadUpcallError, UserUpcallContext,
};

use super::{SavedSyscallFrame, SUCCESS};

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
    let stack_top = crate::arch::upcall::callback_stack(
        stack_end,
        config.flags & mnu_abi::THREAD_UPCALL_EXCEPTIONS != 0,
    );
    if stack_top < config.stack_base
        || !crate::arch::upcall::valid_callback(config.entry, stack_top)
    {
        return Error::InvalidArgument.into_raw();
    }
    if let Some(slot) = crate::arch::upcall::return_slot(stack_top) {
        if let Err(error) = super::copy_to_user_native(slot, &0u64.to_ne_bytes()) {
            return error.into_raw();
        }
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

/// Sample a caller-owned thread object, not an ambient TID or service clock.
/// Copy only after releasing the thread queue, since user memory may fault.
pub fn thread_clock_read(handle: u64, output: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    if length != core::mem::size_of::<mnu_abi::ClockInstant>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let object = match super::handle::object_native(handle, HandleRights::WAIT) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Thread(thread_id) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let rate = crate::interrupt::timer::ticks_per_second();
    if rate == 0 {
        return Error::NotReady.into_raw();
    }
    let Some(ticks) = crate::task::with_thread(thread_id, |thread| thread.cpu_ticks()) else {
        return Error::NotFound.into_raw();
    };
    let seconds = ticks / rate;
    let nanoseconds = (u128::from(ticks % rate) * 1_000_000_000 / u128::from(rate)) as u32;
    let mut bytes = [0; core::mem::size_of::<mnu_abi::ClockInstant>()];
    bytes[..8].copy_from_slice(&seconds.to_le_bytes());
    bytes[8..12].copy_from_slice(&nanoseconds.to_le_bytes());
    super::copy_to_user_native(output, &bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(Error::into_raw)
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
        thread.request_upcall_return_context(
            token,
            context,
            crate::arch::upcall::extension(&snapshot),
        )
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
    let Some(context) = return_context(&snapshot)
        .filter(|context| crate::arch::upcall::stack_pointer(context) >= 16)
    else {
        return Error::InvalidArgument.into_raw();
    };
    crate::task::with_thread_mut(thread_id, |thread| {
        thread.request_context_restore(context, crate::arch::upcall::extension(&snapshot))
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
    crate::arch::upcall::decode(snapshot)
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
    crate::arch::upcall::snapshot(context, fx_state)
}

pub fn prepare_syscall_return(frame: &mut SavedSyscallFrame) {
    let Some(mut context) = read_context(frame) else {
        return;
    };
    if prepare_context(&mut context) {
        resume_context(context);
    }
    if !valid_user_return(&context) || !write_context(frame, context) {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
}

/// Prepare the current thread's pending upcall on a native user frame.
/// Kernel-mode interrupt frames remain unchanged.
pub fn prepare_interrupt_return(frame: &mut crate::cpu::context::InterruptFrame) {
    let Some(mut context) = read_interrupt_context(frame) else {
        return;
    };
    prepare_context(&mut context);
    if !valid_user_return(&context) || !write_interrupt_context(frame, context) {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
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
    crate::arch::upcall::callback(
        context,
        delivery.entry,
        delivery.stack_top,
        [
            delivery.payload,
            delivery.token,
            mnu_abi::THREAD_UPCALL_KIND_INTERRUPT,
            0,
            0,
            0,
            0,
        ],
    );
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
#[cfg(target_arch = "x86_64")]
pub(crate) fn prepare_user_exception(
    raw: &mut crate::cpu::context::PageFaultFrame,
    address: u64,
    cause: mnu_abi::MemoryFaultCause,
) -> bool {
    let mut frame = crate::cpu::context::InterruptFrame {
        gprs: raw.gprs,
        iret: raw.iret,
    };
    if frame.iret.cs & 3 != 3 {
        return false;
    }
    let Some(mut context) = read_interrupt_context(&frame) else {
        return false;
    };
    if !prepare_fault_delivery(&mut context, 14, raw.error_code, address, cause) {
        return false;
    }
    if !write_interrupt_context(&mut frame, context) {
        return false;
    }
    raw.gprs = frame.gprs;
    raw.iret = frame.iret;
    true
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn prepare_user_exception(
    raw: &mut crate::arch::exception::ExceptionFrame,
    address: u64,
    cause: mnu_abi::MemoryFaultCause,
) -> bool {
    let Some(mut context) = raw.user_context() else {
        return false;
    };
    let vector = u32::from(raw.exception_class());
    if !matches!(vector, 0x20 | 0x24)
        || !prepare_fault_delivery(&mut context, vector, raw.syndrome(), address, cause)
    {
        return false;
    }
    raw.restore_user_context(&context)
}

// One delivery/token/diagnostic policy for both CPU frame adapters. The owner
// never holds a thread-table lock across faultable callback-stack usercopy.
fn prepare_fault_delivery(
    context: &mut UserUpcallContext,
    vector: u32,
    error_code: u64,
    address: u64,
    cause: mnu_abi::MemoryFaultCause,
) -> bool {
    if !valid_user_return(context) {
        return false;
    }
    let Some(id) = crate::task::current_thread_id() else {
        return false;
    };
    let Some(delivery) = crate::task::with_thread_mut(id, |thread| {
        thread.begin_exception_upcall(*context, u64::from(vector))
    })
    .flatten() else {
        return false;
    };
    // If the reserved callback stack is no longer writable, retain the native
    // fatal-fault path rather than enter with incomplete exception metadata.
    if let Some(slot) = crate::arch::upcall::exception_argument_slot(delivery.stack_top) {
        if super::copy_to_user_native(slot, &(cause as u64).to_ne_bytes()).is_err() {
            return false;
        }
    }
    let instruction = crate::arch::upcall::instruction_pointer(context);
    let stack_pointer = crate::arch::upcall::stack_pointer(context);
    crate::task::with_thread_mut(id, |thread| {
        thread.note_exception(crate::util::process_diagnostics::Exception {
            timestamp_ns: super::time::monotonic_nanoseconds(),
            vector,
            cause: cause as u32,
            error_code,
            instruction,
            stack_pointer,
            address,
        })
    });
    crate::arch::upcall::callback(
        context,
        delivery.entry,
        delivery.stack_top,
        [
            delivery.payload,
            delivery.token,
            mnu_abi::THREAD_UPCALL_KIND_EXCEPTION,
            address,
            error_code,
            instruction,
            cause as u64,
        ],
    );
    true
}

fn valid_user_return(context: &UserUpcallContext) -> bool {
    crate::arch::upcall::valid_return(context)
}

fn resume_context(context: UserUpcallContext) -> ! {
    if !valid_user_return(&context)
        || !super::syscall_entry::current_thread_user_page_table().is_some_and(|root| root != 0)
    {
        crate::task::scheduler::exit_current_process(u64::MAX);
    }
    let fs_base = crate::task::current_thread_id()
        .and_then(|id| crate::task::with_thread(id, |thread| thread.fs_base()))
        .unwrap_or(0);
    let registers = context.syscall_registers();
    // Only a kernel-validated, current-thread continuation reaches here.
    // The ordinary syscall path still uses SYSRET; full restoration uses the
    // same validated IRET machinery as native address-space continuation.
    unsafe {
        crate::task::usermode::resume_usermode(
            registers,
            crate::arch::upcall::result(&context),
            fs_base,
        )
    }
}

#[cfg(target_arch = "x86_64")]
fn read_interrupt_context(
    frame: &crate::cpu::context::InterruptFrame,
) -> Option<UserUpcallContext> {
    (frame.iret.cs & 3 == 3).then(|| frame.context())
}
#[cfg(target_arch = "x86_64")]
fn write_interrupt_context(
    frame: &mut crate::cpu::context::InterruptFrame,
    context: UserUpcallContext,
) -> bool {
    frame.set_context(context);
    true
}
#[cfg(target_arch = "x86_64")]
fn read_context(frame: &SavedSyscallFrame) -> Option<UserUpcallContext> {
    Some(frame.context())
}
#[cfg(target_arch = "x86_64")]
fn write_context(frame: &mut SavedSyscallFrame, context: UserUpcallContext) -> bool {
    frame.set_context(context);
    true
}

#[cfg(target_arch = "aarch64")]
fn read_interrupt_context(
    frame: &crate::arch::exception::ExceptionFrame,
) -> Option<UserUpcallContext> {
    frame.user_context()
}
#[cfg(target_arch = "aarch64")]
fn write_interrupt_context(
    frame: &mut crate::arch::exception::ExceptionFrame,
    context: UserUpcallContext,
) -> bool {
    frame.restore_user_context(&context)
}
#[cfg(target_arch = "aarch64")]
fn read_context(frame: &SavedSyscallFrame) -> Option<UserUpcallContext> {
    frame.user_context()
}
#[cfg(target_arch = "aarch64")]
fn write_context(frame: &mut SavedSyscallFrame, context: UserUpcallContext) -> bool {
    frame.restore_user_context(&context)
}
