//! Capability のパスレベルのパーミッションと registry

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

use super::Capability;

pub const PATH_READ: u32 = 1 << 0;
pub const PATH_WRITE: u32 = 1 << 1;
pub const PATH_EXEC: u32 = 1 << 2;
pub const PATH_CREATE: u32 = 1 << 3;
pub const PATH_DELETE: u32 = 1 << 4;
pub const PATH_LIST: u32 = 1 << 5;
pub const PATH_MOUNT: u32 = 1 << 6;
pub const PATH_MANAGE: u32 = 1 << 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCapability {
    pub path: String,
    pub owner: PathOwner,
    pub rights: PathRights,
    pub read_capability: Capability,
    pub write_capability: Capability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOwner {
    System,
    User(u64),
    Service(u64),
    Application(u64),
    Any,
}

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
    AlreadyRegistered,
    InvalidPath,
    InvalidCapability,
}

static PATH_REGISTRY: Mutex<Option<BTreeMap<String, PathCapability>>> = Mutex::new(None);

fn with_registry<R>(f: impl FnOnce(&mut Option<BTreeMap<String, PathCapability>>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut registry = PATH_REGISTRY.lock();
        f(&mut registry)
    })
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

pub fn path_owner_for_current_process(
    pid: u64,
    privilege: crate::task::PrivilegeLevel,
) -> PathOwner {
    match privilege {
        crate::task::PrivilegeLevel::Core => PathOwner::System,
        crate::task::PrivilegeLevel::Service => PathOwner::Service(pid),
        crate::task::PrivilegeLevel::User => PathOwner::Application(pid),
    }
}

pub fn register_path(
    path: &str,
    owner: PathOwner,
    rights: PathRights,
) -> Result<(), PathRegistryError> {
    let Some(normalized) = normalize_path(path) else {
        return Err(PathRegistryError::InvalidPath);
    };
    register_path_with_capabilities(
        normalized,
        owner,
        rights,
        Capability::FsReadAll,
        Capability::FsWriteAll,
    )
}

fn register_path_with_capabilities(
    normalized: String,
    owner: PathOwner,
    rights: PathRights,
    read_capability: Capability,
    write_capability: Capability,
) -> Result<(), PathRegistryError> {
    with_registry(|registry| {
        let map = registry.get_or_insert_with(BTreeMap::new);
        if let Some(existing) = map.get(&normalized) {
            if existing.owner == owner
                && existing.rights == rights
                && existing.read_capability == read_capability
                && existing.write_capability == write_capability
            {
                return Ok(());
            }
            return Err(PathRegistryError::AlreadyRegistered);
        }
        map.insert(
            normalized.clone(),
            PathCapability {
                path: normalized,
                owner,
                rights,
                read_capability,
                write_capability,
            },
        );
        Ok(())
    })
}

fn register_configured_path(
    path: &str,
    read_capability: &str,
    write_capability: &str,
    rights: PathRights,
) -> Result<(), PathRegistryError> {
    let Some(normalized) = normalize_path(path) else {
        return Err(PathRegistryError::InvalidPath);
    };
    let Some(read_capability) = Capability::intern(read_capability) else {
        return Err(PathRegistryError::InvalidCapability);
    };
    let Some(write_capability) = Capability::intern(write_capability) else {
        return Err(PathRegistryError::InvalidCapability);
    };
    register_path_with_capabilities(
        normalized,
        PathOwner::Any,
        rights,
        read_capability,
        write_capability,
    )
}

pub fn register_service_paths(service_pid: u64, paths: &[(&str, PathRights)]) -> usize {
    let mut registered = 0usize;
    for (path, rights) in paths.iter().copied() {
        if register_path(path, PathOwner::Service(service_pid), rights).is_ok() {
            registered += 1;
        }
    }
    registered
}

pub fn init_from_kernel_config() {
    let Some(bytes) = crate::init::fs::kernel_read_initfs("/config/kernel.conf") else {
        return;
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return;
    };
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "capability.path" {
            continue;
        }
        let Some(rule) = parse_configured_path(value) else {
            continue;
        };
        let _ = register_configured_path(
            rule.path,
            rule.read_capability,
            rule.write_capability,
            rule.rights,
        );
    }
}

struct ConfiguredPath<'a> {
    path: &'a str,
    read_capability: &'a str,
    write_capability: &'a str,
    rights: PathRights,
}

fn parse_configured_path(value: &str) -> Option<ConfiguredPath<'_>> {
    let mut fields = value.split(';');
    let path = fields.next()?.trim();
    let read_capability = fields.next()?.trim();
    let write_capability = fields.next()?.trim();
    let rights = parse_rights(fields.next()?.trim())?;
    if fields.next().is_some() {
        return None;
    }
    Some(ConfiguredPath {
        path,
        read_capability,
        write_capability,
        rights,
    })
}

fn parse_rights(value: &str) -> Option<PathRights> {
    let mut bits = 0;
    for right in value.split(',').map(str::trim) {
        bits |= match right {
            "read" => PATH_READ,
            "write" => PATH_WRITE,
            "exec" => PATH_EXEC,
            "create" => PATH_CREATE,
            "delete" => PATH_DELETE,
            "list" => PATH_LIST,
            "mount" => PATH_MOUNT,
            "manage" => PATH_MANAGE,
            _ => return None,
        };
    }
    Some(PathRights::new(bits))
}

pub fn lookup_path(path: &str) -> Option<PathCapability> {
    let normalized = normalize_path(path)?;
    with_registry(|registry| {
        let map = registry.as_ref()?;
        let mut best: Option<&PathCapability> = None;
        for (registered_path, capability) in map.iter() {
            let is_match = if registered_path == "/" {
                true
            } else {
                normalized == *registered_path
                    || normalized.starts_with(registered_path)
                        && normalized
                            .as_bytes()
                            .get(registered_path.len())
                            .map(|b| *b == b'/')
                            .unwrap_or(false)
            };
            if is_match {
                best = match best {
                    Some(current) if current.path.len() >= capability.path.len() => Some(current),
                    _ => Some(capability),
                };
            }
        }
        best.cloned()
    })
}

pub fn list_paths() -> Vec<PathCapability> {
    with_registry(|registry| {
        registry
            .as_ref()
            .map(|map| map.values().cloned().collect())
            .unwrap_or_default()
    })
}

pub fn rights_to_string(rights: PathRights) -> String {
    let mut parts = Vec::new();
    if rights.contains(PATH_READ) {
        parts.push("read");
    }
    if rights.contains(PATH_WRITE) {
        parts.push("write");
    }
    if rights.contains(PATH_EXEC) {
        parts.push("exec");
    }
    if rights.contains(PATH_CREATE) {
        parts.push("create");
    }
    if rights.contains(PATH_DELETE) {
        parts.push("delete");
    }
    if rights.contains(PATH_LIST) {
        parts.push("list");
    }
    if rights.contains(PATH_MOUNT) {
        parts.push("mount");
    }
    if rights.contains(PATH_MANAGE) {
        parts.push("manage");
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("|")
    }
}

pub fn owner_to_string(owner: PathOwner) -> String {
    match owner {
        PathOwner::System => "system".to_string(),
        PathOwner::User(uid) => alloc::format!("user:{uid}"),
        PathOwner::Service(pid) => alloc::format!("service:{pid:#x}"),
        PathOwner::Application(pid) => alloc::format!("application:{pid:#x}"),
        PathOwner::Any => "any".to_string(),
    }
}
