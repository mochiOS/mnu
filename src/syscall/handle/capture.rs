use crate::syscall::{EINVAL, ENOMEM, ENOSPC};
use crate::task::{HandleRights, KernelObject, ObjectHandleEntry};
use alloc::sync::Arc;

pub fn table_capture() -> u64 {
    let owner = match super::current_process() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    crate::task::with_process_mut(owner, |process| {
        let snapshot = match process.object_handles().capture() {
            Ok(snapshot) => snapshot,
            Err(()) => return ENOMEM,
        };
        let snapshot = match Arc::try_new(snapshot) {
            Ok(snapshot) => snapshot,
            Err(_) => return ENOMEM,
        };
        // The container is caller-local. Capturing a container later records
        // its metadata only, preventing recursive object-retention chains.
        let rights = HandleRights::READ
            .union(HandleRights::CONTROL)
            .union(HandleRights::DUPLICATE);
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::HandleSnapshot(snapshot),
                rights,
            ))
            .map(|handle| u64::from(handle.raw()))
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(EINVAL)
}
