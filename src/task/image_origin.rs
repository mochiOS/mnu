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
    pub fn capture(process: &Process) -> Option<Self> {
        Some(Self {
            identity: process.application_identity()?.clone(),
            digest: process.image_digest()?,
            capabilities: process.capabilities().clone(),
            kernel_authorities: process.kernel_authorities().clone(),
            privilege: process.privilege(),
        })
    }

    /// A mutable runtime image must never gain authority by being presented as
    /// a fresh, signed executable. Require both original measurement/identity
    /// and attenuation of the source's actual authority at capture time.
    pub fn permits(&self, authorization: &PendingExecSecurity) -> bool {
        authorization.kind == PendingExecKind::Spawn
            && authorization.identity == self.identity
            && authorization.executable_digest == self.digest
            && authorization.capabilities.is_subset_of(&self.capabilities)
            && authorization
                .kernel_authorities
                .is_subset_of(&self.kernel_authorities)
            && (authorization.execution_class == mnu_abi::exec::ExecutionClass::Unprivileged
                || self.privilege != PrivilegeLevel::User)
    }
}
