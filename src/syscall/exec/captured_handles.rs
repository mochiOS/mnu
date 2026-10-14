use super::{InheritedHandleGrant, InheritedHandleSpec};
use crate::syscall::{EACCES, EBADF, EINVAL, ENOMEM};
use crate::task::handle_snapshot::ExportError;
use crate::task::{HandleRights, KernelObject};
use alloc::vec::Vec;

pub(super) fn export(
    capture: u64,
    specs: &[InheritedHandleSpec],
) -> Result<Vec<InheritedHandleGrant>, u64> {
    let snapshot = match crate::syscall::handle::object(capture, HandleRights::CONTROL)? {
        KernelObject::HandleSnapshot(snapshot) => snapshot,
        _ => return Err(EINVAL),
    };
    let mut grants = Vec::new();
    grants.try_reserve_exact(specs.len()).map_err(|_| ENOMEM)?;
    for spec in specs {
        let entry = snapshot
            .export_restricted(spec.source, spec.rights)
            .map_err(|error| match error {
                ExportError::Missing => EBADF,
                ExportError::Denied => EACCES,
            })?;
        grants.push(InheritedHandleGrant {
            key: spec.key,
            target: spec.target,
            entry,
        });
    }
    Ok(grants)
}
