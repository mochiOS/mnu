//! Validate execution-approval metadata once before it can reach publication.
use super::*;
use mnu_abi::status::Error;

pub(super) struct Explicit<'a> {
    pub package: &'a str,
    pub developer: &'a str,
    pub subject_key: [u8; 32],
    pub provenance: crate::task::process::ApplicationProvenance,
    pub executable_digest: [u8; 32],
    pub authorization_kind: crate::task::process::PendingExecKind,
    pub execution_class: ExecutionClass,
}

pub(super) enum Request<'a> {
    InheritSpawn,
    InheritReplace { digest: [u8; 32] },
    Explicit(Explicit<'a>),
}

pub(super) fn parse(identity_items: &[String], caps_total_len: u64) -> Result<Request<'_>, Error> {
    let mut package = None;
    let mut developer = None;
    let mut subject_key = None;
    let mut provenance = None;
    let mut executable_digest = None;
    let mut authorization_kind = None;
    let mut inherit_security = false;
    let mut execution_class = None;
    let mut image_revision = None;
    for item in identity_items {
        if let Some(value) = item.strip_prefix(APPLICATION_PACKAGE_ID_PREFIX) {
            if package.is_some() {
                return Err(Error::InvalidArgument);
            }
            package = Some(value);
        } else if let Some(value) = item.strip_prefix(APPLICATION_DEVELOPER_ID_PREFIX) {
            if developer.is_some() {
                return Err(Error::InvalidArgument);
            }
            developer = Some(value);
        } else if let Some(value) = item.strip_prefix(APPLICATION_SUBJECT_KEY_ID_PREFIX) {
            if subject_key.is_some() {
                return Err(Error::InvalidArgument);
            }
            subject_key = decode_subject_key_id(value);
            if subject_key.is_none() {
                return Err(Error::InvalidArgument);
            }
        } else if let Some(value) = item.strip_prefix(APPLICATION_PROVENANCE_PREFIX) {
            if provenance.is_some() {
                return Err(Error::InvalidArgument);
            }
            provenance = match value {
                "built-in" => Some(crate::task::process::ApplicationProvenance::BuiltIn),
                "verified-package" => {
                    Some(crate::task::process::ApplicationProvenance::VerifiedPackage)
                }
                "development" => Some(crate::task::process::ApplicationProvenance::Development),
                _ => None,
            };
            if provenance.is_none() {
                return Err(Error::InvalidArgument);
            }
        } else if let Some(value) = item.strip_prefix(EXECUTABLE_DIGEST_PREFIX) {
            if executable_digest.is_some() {
                return Err(Error::InvalidArgument);
            }
            executable_digest = decode_subject_key_id(value);
            if executable_digest.is_none() {
                return Err(Error::InvalidArgument);
            }
        } else if let Some(value) = item.strip_prefix(EXEC_AUTHORIZATION_KIND_PREFIX) {
            if authorization_kind.is_some() {
                return Err(Error::InvalidArgument);
            }
            authorization_kind = match value {
                EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE => {
                    Some(crate::task::process::PendingExecKind::ImageReplace)
                }
                EXEC_AUTHORIZATION_KIND_IMAGE_INSTALL => {
                    Some(crate::task::process::PendingExecKind::ImageInstall { image_revision: 0 })
                }
                EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT => {
                    inherit_security = true;
                    Some(crate::task::process::PendingExecKind::ImageReplace)
                }
                EXEC_AUTHORIZATION_KIND_SPAWN_INHERIT => {
                    inherit_security = true;
                    Some(crate::task::process::PendingExecKind::SpawnInherit)
                }
                EXEC_AUTHORIZATION_KIND_SPAWN => Some(crate::task::process::PendingExecKind::Spawn),
                _ => None,
            };
            if authorization_kind.is_none() {
                return Err(Error::InvalidArgument);
            }
        } else if let Some(value) = item.strip_prefix(EXEC_AUTHORIZATION_IMAGE_REVISION_PREFIX) {
            if image_revision.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Error::InvalidArgument);
            }
            image_revision = value.parse::<u64>().ok();
            if image_revision.is_none() {
                return Err(Error::InvalidArgument);
            }
        } else if let Some(value) = item.strip_prefix(EXEC_AUTHORIZATION_CLASS_PREFIX) {
            if execution_class.is_some() {
                return Err(Error::InvalidArgument);
            }
            execution_class = match value {
                "privileged" => Some(ExecutionClass::Privileged),
                "unprivileged" => Some(ExecutionClass::Unprivileged),
                _ => None,
            };
            if execution_class.is_none() {
                return Err(Error::InvalidArgument);
            }
        } else {
            return Err(Error::InvalidArgument);
        }
    }
    if inherit_security {
        let inherited_spawn =
            authorization_kind == Some(crate::task::process::PendingExecKind::SpawnInherit);
        if identity_items.len() != if inherited_spawn { 2 } else { 3 }
            || caps_total_len != 0
            || execution_class != Some(ExecutionClass::Unprivileged)
        {
            return Err(Error::InvalidArgument);
        }
        if inherited_spawn == executable_digest.is_some() {
            return Err(Error::InvalidArgument);
        }
        return match executable_digest {
            Some(digest) => Ok(Request::InheritReplace { digest }),
            None => Ok(Request::InheritSpawn),
        };
    }
    let (
        Some(package),
        Some(developer),
        Some(subject_key),
        Some(provenance),
        Some(executable_digest),
        Some(authorization_kind),
        Some(execution_class),
    ) = (
        package,
        developer,
        subject_key,
        provenance,
        executable_digest,
        authorization_kind,
        execution_class,
    )
    else {
        return Err(Error::InvalidArgument);
    };
    if !valid_security_identity(package) || !valid_security_identity(developer) {
        return Err(Error::InvalidArgument);
    }
    let authorization_kind = match (authorization_kind, image_revision) {
        (crate::task::process::PendingExecKind::ImageInstall { .. }, Some(image_revision))
            if execution_class == ExecutionClass::Unprivileged =>
        {
            crate::task::process::PendingExecKind::ImageInstall { image_revision }
        }
        (crate::task::process::PendingExecKind::ImageInstall { .. }, _) | (_, Some(_)) => {
            return Err(Error::InvalidArgument);
        }
        (kind, None) => kind,
    };
    Ok(Request::Explicit(Explicit {
        package,
        developer,
        subject_key,
        provenance,
        executable_digest,
        authorization_kind,
        execution_class,
    }))
}
