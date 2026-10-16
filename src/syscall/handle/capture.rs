use crate::task::{HandleRights, KernelObject, ObjectHandleEntry};
use alloc::sync::Arc;
use mnu_abi::status::Error;

pub fn table_capture() -> u64 {
    let owner = match crate::syscall::security::current_process_id() {
        Some(owner) => owner,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(owner, |process| {
        let snapshot = match process.object_handles().capture() {
            Ok(snapshot) => snapshot,
            Err(()) => return Error::ResourceUnavailable.into_raw(),
        };
        let snapshot = match Arc::try_new(snapshot) {
            Ok(snapshot) => snapshot,
            Err(_) => return Error::ResourceUnavailable.into_raw(),
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
            .unwrap_or(Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or(Error::NotReady.into_raw())
}
