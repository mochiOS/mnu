//! Capability のパスレベルのパーミッションと registry

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCapability {
    pub path: String,
    pub path_type: PathType,
    pub owner: PathOwner,
    pub rights: PathRights,
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

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathType {
    Root,
    User(UserPath),
    Binary,
    Libraries(LibraryPath),
    Temporary,
    System(SystemPath),
    Config,
    Mount(MountPath),
    Var(VarPath),
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UserPath {
    HomeRoot,
    Home,
    Documents,
    Movies,
    Develop,
    Desktop,
    Download,
    Musics,
    Images,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SystemPath {
    Root,
    Kernel,
    Boot,
    Services,
    Log,
    State,
    Cache,
    Drivers,
    Devices,
    Runtime,
    Security,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LibraryPath {
    Root,
    Shared,
    Static,
    Runtime,
    Frameworks,
    PlugKit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MountPath {
    Root,
    Disk,
    Device,
    Network,
    External,
    Temporary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarPath {
    Root,
    Log,
    Cache,
    State,
    Spool,
    Lock,
    Runtime,
    Temporary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRegistryError {
    AlreadyRegistered,
    InvalidPath,
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

pub fn classify_path(path: &str) -> PathType {
    let Some(normalized) = normalize_path(path) else {
        return PathType::Custom;
    };
    if normalized == "/" {
        return PathType::Root;
    }

    if let Some(registered) = lookup_path(&normalized) {
        return registered.path_type;
    }

    PathType::Custom
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
    let path_type = classify_path(&normalized);
    with_registry(|registry| {
        let map = registry.get_or_insert_with(BTreeMap::new);
        if let Some(existing) = map.get(&normalized) {
            if existing.owner == owner
                && existing.rights == rights
                && existing.path_type == path_type
            {
                return Ok(());
            }
            return Err(PathRegistryError::AlreadyRegistered);
        }
        map.insert(
            normalized.clone(),
            PathCapability {
                path: normalized,
                path_type,
                owner,
                rights,
            },
        );
        Ok(())
    })
}

pub fn register_typed_path(
    path: &str,
    path_type: PathType,
    owner: PathOwner,
    rights: PathRights,
) -> Result<(), PathRegistryError> {
    let Some(normalized) = normalize_path(path) else {
        return Err(PathRegistryError::InvalidPath);
    };
    with_registry(|registry| {
        let map = registry.get_or_insert_with(BTreeMap::new);
        if let Some(existing) = map.get(&normalized) {
            if existing.owner == owner
                && existing.rights == rights
                && existing.path_type == path_type
            {
                return Ok(());
            }
            return Err(PathRegistryError::AlreadyRegistered);
        }
        map.insert(
            normalized.clone(),
            PathCapability {
                path: normalized,
                path_type,
                owner,
                rights,
            },
        );
        Ok(())
    })
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
        let Some(path_type) = parse_config_path_type(key.trim()) else {
            continue;
        };
        let path = value.trim();
        let rights = PathRights::new(PATH_READ | PATH_EXEC | PATH_LIST);
        let _ = register_typed_path(path, path_type, PathOwner::Any, rights);
    }
}

fn parse_config_path_type(key: &str) -> Option<PathType> {
    let kind = key.strip_prefix("capability.path.")?;
    match kind {
        "binary" => Some(PathType::Binary),
        "tmp" | "temporary" => Some(PathType::Temporary),
        "config" => Some(PathType::Config),
        "mount" => Some(PathType::Mount(MountPath::Root)),
        "var" => Some(PathType::Var(VarPath::Root)),
        "system" => Some(PathType::System(SystemPath::Root)),
        "system.kernel" => Some(PathType::System(SystemPath::Kernel)),
        "system.boot" => Some(PathType::System(SystemPath::Boot)),
        "system.services" => Some(PathType::System(SystemPath::Services)),
        "system.log" => Some(PathType::System(SystemPath::Log)),
        "system.state" => Some(PathType::System(SystemPath::State)),
        "system.cache" => Some(PathType::System(SystemPath::Cache)),
        "system.drivers" => Some(PathType::System(SystemPath::Drivers)),
        "system.devices" => Some(PathType::System(SystemPath::Devices)),
        "system.runtime" => Some(PathType::System(SystemPath::Runtime)),
        "system.security" => Some(PathType::System(SystemPath::Security)),
        "system.policy" => Some(PathType::System(SystemPath::Policy)),
        "libraries" => Some(PathType::Libraries(LibraryPath::Shared)),
        "libraries.shared" => Some(PathType::Libraries(LibraryPath::Shared)),
        "libraries.static" => Some(PathType::Libraries(LibraryPath::Static)),
        "libraries.runtime" => Some(PathType::Libraries(LibraryPath::Runtime)),
        "libraries.frameworks" => Some(PathType::Libraries(LibraryPath::Frameworks)),
        "libraries.plugkit" => Some(PathType::Libraries(LibraryPath::PlugKit)),
        "user" => Some(PathType::User(UserPath::HomeRoot)),
        "user.home" => Some(PathType::User(UserPath::Home)),
        "user.documents" => Some(PathType::User(UserPath::Documents)),
        "user.movies" => Some(PathType::User(UserPath::Movies)),
        "user.develop" => Some(PathType::User(UserPath::Develop)),
        "user.desktop" => Some(PathType::User(UserPath::Desktop)),
        "user.downloads" => Some(PathType::User(UserPath::Download)),
        "user.music" => Some(PathType::User(UserPath::Musics)),
        "user.images" => Some(PathType::User(UserPath::Images)),
        _ => None,
    }
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
