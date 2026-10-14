//! Provider-owner lifetime observation. No client identity, FD, resource policy
//! or reference graph is interpreted by this native mechanism.
use crate::syscall::{EBADF, EINVAL};
use alloc::sync::Arc;

pub fn count(object_id: u64) -> u64 {
    if object_id > i64::MAX as u64 {
        return EINVAL;
    }
    let current = match crate::task::current_thread_id()
        .and_then(|thread| crate::syscall::ipc::endpoint_for_thread(thread.as_u64()))
    {
        Some(endpoint) => endpoint,
        None => return EINVAL,
    };
    let Some(provider) = crate::task::handle_table::provider_object(
        current.thread_id,
        current.slot,
        current.generation,
        object_id,
    ) else {
        return EBADF;
    };
    // Registry entries are Weak. provider_object acquired exactly one local
    // strong reference; remove that observation from the conservative sample.
    (Arc::strong_count(&provider) - 1) as u64
}
