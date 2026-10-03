use crate::task::{HandleRights, ObjectHandle};

use super::{EACCES, EBADF, EINVAL, ENOSPC, SUCCESS};

fn current_process() -> Result<crate::task::ProcessId, u64> {
    crate::syscall::security::current_process_id().ok_or(EINVAL)
}

fn decode_handle(raw: u64) -> Result<ObjectHandle, u64> {
    let raw = u32::try_from(raw).map_err(|_| EBADF)?;
    ObjectHandle::from_raw(raw).ok_or(EBADF)
}

pub fn close(raw: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        if !process.object_handles_mut().close(handle) {
            return EBADF;
        }
        process.launch_context_mut().remove_handle(handle);
        SUCCESS
    })
    .unwrap_or(EINVAL)
}

pub fn duplicate(raw: u64, requested_rights: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) => rights,
        None => return EINVAL,
    };
    crate::task::with_process_mut(process_id, |process| {
        let Some(source) = process.object_handles().get(handle) else {
            return EBADF;
        };
        if !source.rights().contains(HandleRights::DUPLICATE)
            || !source.rights().contains(rights)
        {
            return EACCES;
        }
        match process.object_handles_mut().duplicate_restricted(handle, rights) {
            Some(duplicate) => duplicate.raw() as u64,
            None => ENOSPC,
        }
    })
    .unwrap_or(EINVAL)
}

pub fn launch_get(key: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    crate::task::with_process(process_id, |process| {
        let Some(handle) = process.launch_context().get(key) else {
            return EBADF;
        };
        if process.object_handles().get(handle).is_none() {
            return EBADF;
        }
        handle.raw() as u64
    })
    .unwrap_or(EINVAL)
}
