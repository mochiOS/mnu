//! Immutable execution-image origin and native authority ceilings.
//! This records provenance; possessing it does not grant any authority.

use super::process::{ApplicationIdentity, PendingExecKind, PendingExecSecurity};
use super::{PrivilegeLevel, Process};
use crate::capability::{CapabilitySet, KernelAuthoritySet};

#[derive(Clone)]
pub struct ImageOrigin {
    identity: ApplicationIdentity,
    digest: [u8; 32],
    capabilities: CapabilitySet,
    kernel_authorities: KernelAuthoritySet,
    privilege: PrivilegeLevel,
}

impl ImageOrigin {
    /// Missing measurement/identity is distinct from a failed owned copy.
    /// Callers must not turn allocation failure into an unmeasured image.
    pub fn capture(process: &Process) -> Result<Option<Self>, mnu_abi::status::Error> {
        let Some(identity) = process.application_identity() else {
            return Ok(None);
        };
        let Some(digest) = process.image_digest() else {
            return Ok(None);
        };
        Ok(Some(Self {
            identity: identity.try_clone()?,
            digest,
            capabilities: process.capabilities().try_clone()?,
            kernel_authorities: process.kernel_authorities().try_clone()?,
            privilege: process.privilege(),
        }))
    }

    /// A mutable runtime image must never gain authority by being presented as
    /// a fresh, signed executable. Require both original measurement/identity
    /// and attenuation of the source's actual authority at capture time.
    pub fn permits(&self, authorization: &PendingExecSecurity) -> bool {
        matches!(
            authorization.kind,
            PendingExecKind::Spawn | PendingExecKind::SpawnInherit
        ) && authorization.identity == self.identity
            && authorization.executable_digest == self.digest
            && authorization.capabilities.is_subset_of(&self.capabilities)
            && authorization
                .kernel_authorities
                .is_subset_of(&self.kernel_authorities)
            && (authorization.execution_class == mnu_abi::exec::ExecutionClass::Unprivileged
                || self.privilege != PrivilegeLevel::User)
    }
}
