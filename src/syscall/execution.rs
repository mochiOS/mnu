//! Identification of the current native execution context, without policy.

pub fn identity_read(output: u64, length: u64) -> u64 {
    if length != core::mem::size_of::<mnu_abi::ExecutionIdentity>() as u64 {
        return super::EINVAL;
    }
    let Some(thread) = crate::task::current_thread_id() else {
        return super::ESRCH;
    };
    let Some(process) = crate::task::with_thread(thread, |thread| thread.process_id()) else {
        return super::ESRCH;
    };
    // Explicit byte encoding avoids exposing padding or reading any policy
    // state. There is no target identifier: only the caller can be queried.
    let mut bytes = [0; core::mem::size_of::<mnu_abi::ExecutionIdentity>()];
    bytes[..8].copy_from_slice(&process.as_u64().to_ne_bytes());
    bytes[8..].copy_from_slice(&thread.as_u64().to_ne_bytes());
    super::copy_to_user(output, &bytes)
        .map(|_| mnu_abi::SUCCESS)
        .unwrap_or_else(|error| error)
}
