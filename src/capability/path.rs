//! Capabiltyのパスレベルのパーミッション用の定義

pub const PATH_READ: u32 = 1 << 0;
pub const PATH_WRITE: u32 = 1 << 1;
pub const PATH_EXEC: u32 = 1 << 2;
pub const PATH_CREATE: u32 = 1 << 3;
pub const PATH_DELETE: u32 = 1 << 4;
pub const PATH_LIST: u32 = 1 << 5;
pub const PATH_MOUNT: u32 = 1 << 6;
pub const PATH_MANAGE: u32 = 1 << 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCapability {
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
    Applications(ApplicationPath),
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
pub enum ApplicationPath {
    Root,
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
