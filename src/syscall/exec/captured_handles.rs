use super::{InheritedHandleGrant, InheritedHandleSpec};
use crate::task::handle_snapshot::ExportError;
use crate::task::{HandleRights, KernelObject};
use alloc::vec::Vec;
use mnu_abi::status::Error;

pub(super) fn export(
    capture: u64,
    specs: &[InheritedHandleSpec],
) -> Result<Vec<InheritedHandleGrant>, Error> {
    let snapshot = match crate::syscall::handle::object_native(capture, HandleRights::CONTROL)? {
        KernelObject::HandleSnapshot(snapshot) => snapshot,
        _ => return Err(Error::InvalidArgument),
    };
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(specs.len())
        .map_err(|_| Error::ResourceUnavailable)?;
    for spec in specs {
        let entry = snapshot
            .export_restricted(spec.source, spec.rights)
            .map_err(|error| match error {
                ExportError::Missing => Error::InvalidArgument,
                ExportError::Denied => Error::AccessDenied,
            })?;
        grants.push(InheritedHandleGrant {
            key: spec.key,
            target: spec.target,
            entry,
        });
    }
    Ok(grants)
}
