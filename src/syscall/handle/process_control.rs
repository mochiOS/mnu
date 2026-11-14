//! Process control through retained Handle authority.
use super::*;

pub fn process_resume(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Process(process) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let process_id = process.id();
    if process.is_exited() || crate::task::with_process(process_id, |_| ()).is_none() {
        return Error::NotFound.into_raw();
    }
    if crate::task::resume_process_threads(process_id).is_none() {
        return Error::NotFound.into_raw();
    }
    SUCCESS
}

/// Suspends every thread belonging to the process referenced by `raw`.
/// This is a policy-free lifecycle operation; callers assign their own
/// meaning to the scheduling state.
pub fn process_suspend(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Process(process) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let process_id = process.id();
    if process.is_exited() || crate::task::with_process(process_id, |_| ()).is_none() {
        return Error::NotFound.into_raw();
    }
    if crate::task::suspend_process_threads(process_id) == 0 {
        return Error::NotReady.into_raw();
    }
    SUCCESS
}

pub fn process_terminate(raw: u64, exit_code: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Process(process) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let process_id = process.id();
    if process.is_exited() || crate::task::with_process(process_id, |_| ()).is_none() {
        return Error::NotFound.into_raw();
    }
    if crate::syscall::security::current_process_id() == Some(process_id) {
        crate::task::scheduler::exit_current_process(exit_code);
    }
    if !process.begin_termination() {
        return if process.is_exited() {
            Error::NotFound.into_raw()
        } else {
            Error::NotReady.into_raw()
        };
    }
    crate::task::scheduler::retire_process_threads(process_id, None);
    let cleanup = crate::task::release_process_borrowed_mappings(process_id);
    if !crate::task::mark_process_exited(process_id, exit_code) {
        return Error::NotFound.into_raw();
    }
    // Terminal publication succeeded. Reporting cleanup failure as termination
    // failure would make callers lose the winning termination cause. Deferred
    // process reclaim retains the address space and retries mapping revocation.
    if let Err(error) = cleanup {
        crate::warn!(
            "Borrowed mapping cleanup deferred for {:?}: {:#x}",
            process_id,
            error
        );
    }
    SUCCESS
}
