//! Process observation and lifecycle Handle adapters.
use super::*;

const PROCESS_HANDLE_RIGHTS: HandleRights = HandleRights::WAIT
    .union(HandleRights::DUPLICATE)
    .union(HandleRights::TRANSFER);

const PROCESS_ADMIN_HANDLE_RIGHTS: HandleRights = PROCESS_HANDLE_RIGHTS.union(HandleRights::SIGNAL);

/// Retain an object created by this caller before its first thread is published.
/// This is not a lookup API: only the authorized creation path calls it.
pub(crate) fn retain_created_process(
    target: &crate::task::Process,
) -> Result<u64, mnu_abi::status::Error> {
    use mnu_abi::status::Error;
    let owner = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
    let object = target.process_object();
    crate::task::with_process_mut(owner, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Process(object),
                PROCESS_ADMIN_HANDLE_RIGHTS,
            ))
            .map(|handle| handle.raw() as u64)
            .ok_or(Error::ResourceUnavailable)
    })
    .ok_or(Error::NotReady)?
}

pub(super) fn insert_process_handle(target: crate::task::ProcessId, rights: HandleRights) -> u64 {
    use mnu_abi::status::Error;
    let Some(target_object) = crate::task::with_process(target, |process| process.process_object())
    else {
        return Error::NotFound.into_raw();
    };
    let Some(process_id) = crate::syscall::security::current_process_id() else {
        return Error::NotReady.into_raw();
    };
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Process(target_object),
                rights,
            ))
            .map(|handle| handle.raw() as u64)
            .unwrap_or_else(|| Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

/// Creates a process handle for the process owning an authenticated IPC
/// endpoint. No caller-supplied process identifier is accepted.
pub fn process_open(endpoint: u64, requested_rights: u64) -> u64 {
    use mnu_abi::status::Error;
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return Error::AccessDenied.into_raw();
    }
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) if PROCESS_ADMIN_HANDLE_RIGHTS.contains(rights) => rights,
        _ => return Error::InvalidArgument.into_raw(),
    };
    if rights.contains(HandleRights::SIGNAL)
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::ProcessKill,
        ])
    {
        return Error::AccessDenied.into_raw();
    }
    let Some(thread_id) = crate::ipc::resolve_endpoint_handle(endpoint) else {
        return Error::InvalidArgument.into_raw();
    };
    let Some(target) = crate::task::thread_to_process_id(thread_id) else {
        return Error::NotFound.into_raw();
    };
    insert_process_handle(target, rights)
}

/// Creates a native handle for a process identifier. Process identifiers are
/// generic kernel identities; requested control rights are capability-gated.
pub fn process_open_by_id(process_id: u64, requested_rights: u64) -> u64 {
    use mnu_abi::status::Error;
    if process_id == 0 {
        return Error::InvalidArgument.into_raw();
    }
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return Error::AccessDenied.into_raw();
    }
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) if PROCESS_ADMIN_HANDLE_RIGHTS.contains(rights) => rights,
        _ => return Error::InvalidArgument.into_raw(),
    };
    if rights.contains(HandleRights::SIGNAL)
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::ProcessKill,
        ])
    {
        return Error::AccessDenied.into_raw();
    }
    insert_process_handle(crate::task::ProcessId::from_u64(process_id), rights)
}

pub fn process_memory_read(raw: u64, output: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    if length != core::mem::size_of::<mnu_abi::ProcessMemoryUsage>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let result = (|| {
        let process = if raw == 0 {
            let caller = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
            crate::task::with_process(caller, |process| process.process_object())
                .ok_or(Error::NotReady)?
        } else {
            let KernelObject::Process(process) = object_native(raw, HandleRights::WAIT)? else {
                return Err(Error::InvalidArgument);
            };
            process
        };
        let snapshot = process.memory_usage().ok_or(Error::NotReady)?;
        let usage = mnu_abi::ProcessMemoryUsage {
            current_bytes: snapshot.current_bytes,
            peak_bytes: snapshot.peak_bytes,
        };
        let bytes = usage.encode();
        crate::syscall::copy_to_user_native(output, &bytes)
    })();
    result.map(|_| SUCCESS).unwrap_or_else(Error::into_raw)
}

pub(super) fn process_status_for(raw: u64) -> Result<mnu_abi::ProcessStatus, u64> {
    use mnu_abi::status::Error;
    let object = object_native(raw, HandleRights::WAIT).map_err(Error::into_raw)?;
    let KernelObject::Process(process) = object else {
        return Err(Error::InvalidArgument.into_raw());
    };
    // Image replacement may release old Handles before publishing its final
    // revision. Serialize live metadata with that existing commit lock so an
    // observer woken by those releases cannot read a partial transition.
    // A reclaimed process remains observable through its retained object.
    Ok(
        crate::task::with_process(process.id(), |_| process_status_of(&process))
            .unwrap_or_else(|| process_status_of(&process)),
    )
}

pub(super) fn process_status_of(
    process: &crate::task::process::ProcessObject,
) -> mnu_abi::ProcessStatus {
    let exited = process.is_exited();
    mnu_abi::ProcessStatus {
        process_id: process.id().as_u64(),
        state: if exited {
            mnu_abi::PROCESS_STATE_EXITED
        } else {
            mnu_abi::PROCESS_STATE_RUNNING
        },
        reserved: 0,
        exit_code: process.exit_code(),
        image_revision: process.image_revision(),
    }
}

pub(super) fn write_process_status(output: u64, status: mnu_abi::ProcessStatus) -> u64 {
    use mnu_abi::status::Error;
    if output == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let bytes = status.encode();
    crate::syscall::copy_to_user_native(output, &bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(Error::into_raw)
}

pub fn process_status(raw: u64, output: u64) -> u64 {
    match process_status_for(raw) {
        Ok(status) => write_process_status(output, status),
        Err(error) => error,
    }
}

pub(super) fn process_execution_usage_for(raw: u64) -> Result<mnu_abi::ProcessExecutionUsage, u64> {
    use mnu_abi::status::Error;
    let process = if raw == 0 {
        let caller = crate::syscall::security::current_process_id()
            .ok_or_else(|| Error::NotReady.into_raw())?;
        crate::task::with_process(caller, |process| process.process_object())
            .ok_or_else(|| Error::NotReady.into_raw())?
    } else {
        let KernelObject::Process(process) =
            object_native(raw, HandleRights::WAIT).map_err(Error::into_raw)?
        else {
            return Err(Error::InvalidArgument.into_raw());
        };
        process
    };
    let ticks_per_second = crate::interrupt::timer::ticks_per_second();
    if ticks_per_second == 0 {
        return Err(Error::NotReady.into_raw());
    }
    let (user_ticks, kernel_ticks) = crate::task::thread::process_execution_ticks(&process);
    Ok(mnu_abi::ProcessExecutionUsage {
        user_ticks,
        kernel_ticks,
        ticks_per_second,
        reserved: 0,
    })
}

pub fn process_execution_read(raw: u64, output: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    if length != core::mem::size_of::<mnu_abi::ProcessExecutionUsage>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let usage = match process_execution_usage_for(raw) {
        Ok(usage) => usage,
        Err(error) => return error,
    };
    let bytes = usage.encode();
    crate::syscall::copy_to_user_native(output, &bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(Error::into_raw)
}

/// Waits until the process exits. `deadline_nanoseconds` is an absolute
/// monotonic-clock value; zero polls and `u64::MAX` waits indefinitely.
pub fn process_wait(raw: u64, deadline_nanoseconds: u64, output: u64) -> u64 {
    use mnu_abi::status::Error;
    // Retain the target once: concurrent close/reuse of the caller's selector
    // must not redirect a pending wait to a different lifecycle object.
    let process = match object_native(raw, HandleRights::WAIT) {
        Ok(KernelObject::Process(process)) => process,
        Ok(_) => return Error::InvalidArgument.into_raw(),
        Err(error) => return error.into_raw(),
    };
    let process_id = process.id();
    let current = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return Error::NotReady.into_raw(),
    };
    struct Registration {
        thread: crate::task::ThreadId,
        process: crate::task::ProcessId,
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            crate::task::remove_process_exit_waiter(self.thread, self.process);
            crate::syscall::time::disarm_thread_deadline(self.thread);
        }
    }
    let deadline_tick = if matches!(
        deadline_nanoseconds,
        mnu_abi::PROCESS_WAIT_POLL | mnu_abi::PROCESS_WAIT_INFINITE
    ) {
        deadline_nanoseconds
    } else {
        crate::syscall::time::monotonic_deadline_tick(deadline_nanoseconds)
    };
    loop {
        crate::syscall::time::disarm_thread_deadline(current);
        let registration = Registration {
            thread: current,
            process: process_id,
        };
        let status = process_status_of(&process);
        if status.state == mnu_abi::PROCESS_STATE_EXITED {
            drop(registration);
            return write_process_status(output, status);
        }
        if deadline_nanoseconds == mnu_abi::PROCESS_WAIT_POLL
            || (deadline_nanoseconds != mnu_abi::PROCESS_WAIT_INFINITE
                && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds)
        {
            return Error::NotReady.into_raw();
        }
        if crate::syscall::upcall::current_has_deliverable_upcall() {
            return Error::NotReady.into_raw();
        }
        if !crate::task::register_process_exit_waiter(current, process_id) {
            return Error::ResourceUnavailable.into_raw();
        }

        // Recheck after registration so an exit racing with registration
        // cannot be missed.
        let status = process_status_of(&process);
        if status.state == mnu_abi::PROCESS_STATE_EXITED {
            drop(registration);
            return write_process_status(output, status);
        }

        if deadline_nanoseconds != mnu_abi::PROCESS_WAIT_INFINITE
            && !crate::syscall::time::arm_thread_deadline(current, deadline_tick)
        {
            return Error::ResourceUnavailable.into_raw();
        }
        let _ = crate::task::sleep_thread_unless_woken(current);
        crate::task::yield_now();
    }
}
