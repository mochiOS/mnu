//! Read-only committed-image metadata through an existing observation Handle.
use alloc::sync::Arc;
use mnu_abi::status::Error;

use super::{HandleRights, KernelObject, object_native};

pub fn read(raw: u64, output: u64, length: u64) -> u64 {
    if length != core::mem::size_of::<mnu_abi::ProcessImageInfo>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let result = (|| {
        let object = if raw == 0 {
            let caller = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
            crate::task::with_process(caller, |process| process.process_object())
                .ok_or(Error::NotReady)?
        } else {
            let KernelObject::Process(object) = object_native(raw, HandleRights::WAIT)? else {
                return Err(Error::InvalidArgument);
            };
            object
        };
        // The process table lock also encloses digest/revision publication at
        // image commit. Never combine a new digest with the previous revision.
        let info = crate::task::with_process(object.id(), |process| {
            if !Arc::ptr_eq(&object, &process.process_object()) || !object.accepts_threads() {
                return Err(Error::NotFound);
            }
            let (digest_kind, digest) = match process.image_digest() {
                Some(digest) => (mnu_abi::PROCESS_IMAGE_DIGEST_SHA256, digest),
                None => (mnu_abi::PROCESS_IMAGE_DIGEST_NONE, [0; 32]),
            };
            Ok(mnu_abi::ProcessImageInfo {
                process_id: object.id().as_u64(),
                image_revision: object.image_revision(),
                digest_kind,
                reserved: 0,
                digest,
            })
        })
        .ok_or(Error::NotFound)??;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&info as *const mnu_abi::ProcessImageInfo).cast::<u8>(),
                core::mem::size_of::<mnu_abi::ProcessImageInfo>(),
            )
        };
        crate::syscall::copy_to_user_native(output, bytes)
    })();
    result
        .map(|_| mnu_abi::SUCCESS)
        .unwrap_or_else(Error::into_raw)
}
