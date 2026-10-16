//! Identification of native caller or IPC endpoint execution, without policy.
use mnu_abi::status::Error;

pub fn identity_read(output: u64, length: u64) -> u64 {
    read_selected_identity(output, length, 0)
}

pub fn endpoint_identity_read(output: u64, length: u64, endpoint: u64) -> u64 {
    if endpoint == 0 {
        return Error::InvalidArgument.into_raw();
    }
    read_selected_identity(output, length, endpoint)
}

fn read_selected_identity(output: u64, length: u64, endpoint: u64) -> u64 {
    if length != core::mem::size_of::<mnu_abi::ExecutionIdentity>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let (process, thread) = if endpoint == 0 {
        let Some(thread) = crate::task::current_thread_id() else {
            return Error::NotReady.into_raw();
        };
        let Some(process) = crate::task::with_thread(thread, |thread| thread.process_id()) else {
            return Error::NotReady.into_raw();
        };
        (process.as_u64(), thread.as_u64())
    } else {
        match super::ipc::endpoint_execution_identity(endpoint) {
            Ok(identity) => (identity.process_id, identity.thread_id),
            Err(error) => return error.into_raw(),
        }
    };
    // Explicit byte encoding avoids exposing padding or reading any policy
    // state. A nonzero target is an authenticated IPC endpoint, not a PID/TID.
    let mut bytes = [0; core::mem::size_of::<mnu_abi::ExecutionIdentity>()];
    bytes[..8].copy_from_slice(&process.to_ne_bytes());
    bytes[8..].copy_from_slice(&thread.to_ne_bytes());
    super::copy_to_user_native(output, &bytes)
        .map(|_| mnu_abi::SUCCESS)
        .unwrap_or_else(|error| error.into_raw())
}
