//! Legacy process-scoped path grants; filesystem authority is managed in userspace.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

pub const PATH_READ: u32 = 1 << 0;
pub const PATH_WRITE: u32 = 1 << 1;
pub const PATH_EXEC: u32 = 1 << 2;
pub const PATH_CREATE: u32 = 1 << 3;
pub const PATH_DELETE: u32 = 1 << 4;
pub const PATH_LIST: u32 = 1 << 5;
pub const PATH_MOUNT: u32 = 1 << 6;
pub const PATH_MANAGE: u32 = 1 << 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRights {
    pub bits: u32,
}

impl PathRights {
    pub const fn new(bits: u32) -> Self {
        Self { bits }
    }

    pub const fn contains(self, rights: u32) -> bool {
        (self.bits & rights) == rights
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRegistryError {
    InvalidPath,
}

static SCOPED_PATH_GRANTS: Mutex<Option<BTreeMap<(u64, String), PathRights>>> = Mutex::new(None);

fn with_scoped_grants<R>(
    f: impl FnOnce(&mut Option<BTreeMap<(u64, String), PathRights>>) -> R,
) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut grants = SCOPED_PATH_GRANTS.lock();
        f(&mut grants)
    })
}

/// Grants one process access to exactly one normalized filesystem path.
///
/// This is used by trusted file-panel and capability brokers. It deliberately
/// does not imply access to siblings or descendants.
pub fn grant_scoped_path(
    pid: u64,
    path: &str,
    rights: PathRights,
) -> Result<(), PathRegistryError> {
    let Some(normalized) = normalize_path(path) else {
        return Err(PathRegistryError::InvalidPath);
    };
    if pid == 0 || normalized == "/" || rights.bits == 0 {
        return Err(PathRegistryError::InvalidPath);
    }
    with_scoped_grants(|grants| {
        let grants = grants.get_or_insert_with(BTreeMap::new);
        grants
            .entry((pid, normalized))
            .and_modify(|current| current.bits |= rights.bits)
            .or_insert(rights);
    });
    Ok(())
}

pub fn scoped_path_allows(pid: u64, path: &str, needed_rights: u32) -> bool {
    let Some(normalized) = normalize_path(path) else {
        return false;
    };
    with_scoped_grants(|grants| {
        grants
            .as_ref()
            .and_then(|grants| grants.get(&(pid, normalized)))
            .is_some_and(|rights| rights.contains(needed_rights))
    })
}

pub fn revoke_scoped_paths(pid: u64) {
    with_scoped_grants(|grants| {
        if let Some(grants) = grants.as_mut() {
            grants.retain(|(owner, _), _| *owner != pid);
        }
    });
}

fn normalize_path(path: &str) -> Option<String> {
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let normalized = if parts.is_empty() {
        "/".to_string()
    } else {
        alloc::format!("/{}", parts.join("/"))
    };
    Some(normalized)
}
