//! Explicit launch context values and Handle delegation.
use super::*;

pub fn launch_get(key: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process(process_id, |process| {
        let Some(handle) = process.launch_context().get(key) else {
            return Error::NotFound.into_raw();
        };
        if process.object_handles().get(handle).is_none() {
            return Error::InvalidArgument.into_raw();
        }
        handle.raw() as u64
    })
    .unwrap_or(Error::NotReady.into_raw())
}

/// Associates one of the caller's existing object handles with an opaque
/// process-context key, replacing the previous association for that key. The
/// kernel assigns no meaning to either the key or the object.
pub fn context_handle_set(key: u64, raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let handle = match u32::try_from(raw).ok().and_then(ObjectHandle::from_raw) {
        Some(handle) => handle,
        None => return Error::InvalidArgument.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        if process.object_handles().get(handle).is_none() {
            return Error::InvalidArgument.into_raw();
        }
        if !process.launch_context_mut().set(key, handle) {
            return Error::ResourceUnavailable.into_raw();
        }
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn context_handle_remove(key: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        process.launch_context_mut().take(key);
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn context_value_set(key: u64, value: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        if !process.launch_context_mut().set_value(key, value) {
            return Error::ResourceUnavailable.into_raw();
        }
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn context_value_remove(key: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        process.launch_context_mut().remove_value(key);
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}
