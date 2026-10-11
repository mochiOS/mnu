//! Identification of native caller or IPC endpoint execution, without policy.

pub fn identity_read(output: u64, length: u64, endpoint: u64) -> u64 {
    if length != core::mem::size_of::<mnu_abi::ExecutionIdentity>() as u64 {
        return super::EINVAL;
    }
    let (process, thread) = if endpoint == 0 {
        let Some(thread) = crate::task::current_thread_id() else {
            return super::ESRCH;
        };
        let Some(process) = crate::task::with_thread(thread, |thread| thread.process_id()) else {
            return super::ESRCH;
        };
        (process.as_u64(), thread.as_u64())
    } else {
        match super::ipc::endpoint_execution_identity(endpoint) {
            Ok(identity) => (identity.process_id, identity.thread_id),
            Err(error) => return error,
        }
    };
    // Explicit byte encoding avoids exposing padding or reading any policy
    // state. A nonzero target is an authenticated IPC endpoint, not a PID/TID.
    let mut bytes = [0; core::mem::size_of::<mnu_abi::ExecutionIdentity>()];
    bytes[..8].copy_from_slice(&process.to_ne_bytes());
    bytes[8..].copy_from_slice(&thread.to_ne_bytes());
    super::copy_to_user(output, &bytes)
        .map(|_| mnu_abi::SUCCESS)
        .unwrap_or_else(|error| error)
}
