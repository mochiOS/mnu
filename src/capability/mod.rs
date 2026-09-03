//! capability（権限）定義と集合型
//!
//! 外部表現は文字列（manifest 等）で扱い、カーネル内部では enum として保持する。
//! 文字列のまま全処理すると typo や比較の取り違えが起きやすく、また高速化もしづらいため、
//! ここで変換を集中管理する。

extern crate alloc;
pub mod path;

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// kernel が直接強制する低レベル権限
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KernelCapability {
    ProcessKill,
    ProcessSpawn,
    IpcEndpointCreate,
    IpcEndpointSend,
    IpcEndpointRecv,
    VmMap,
    VmUnmap,
    MmioMap,
    DmaAllocate,
    PhysMap,
    PhysTranslate,
    IrqBind,
    CextLoad,
    CextStop,
    DeviceClaim,
    KernelDebug,
    SignatureWrite,
    SignatureRead,
}

/// kernel が権限を結びつける対象オブジェクト
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KernelObjectRef {
    Process(u64),
    Thread(u64),
    IpcEndpoint(u64),
    VmObject(u64),
    MmioRegion { base: u64, size: u64 },
    IrqLine(u32),
    CextInstance(u64),
    DeviceHandle(u64),
}

/// kernel capability と対象オブジェクトの組
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KernelAuthority {
    pub capability: KernelCapability,
    pub object: KernelObjectRef,
}

impl KernelAuthority {
    pub const fn new(capability: KernelCapability, object: KernelObjectRef) -> Self {
        Self { capability, object }
    }
}

fn parse_u64_component(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

pub fn parse_kernel_authority_spec(spec: &str) -> Option<KernelAuthority> {
    let phys = spec.strip_prefix("memory.phys.map@")?;
    let (base_raw, size_raw) = phys.split_once(':')?;
    let base = parse_u64_component(base_raw)?;
    let size = parse_u64_component(size_raw)?;
    if size == 0 {
        return None;
    }
    Some(KernelAuthority::new(
        KernelCapability::PhysMap,
        KernelObjectRef::MmioRegion { base, size },
    ))
}

pub fn kernel_authority_implies(parent: &KernelAuthority, child: &KernelAuthority) -> bool {
    if parent.capability != child.capability {
        return false;
    }

    match (parent.object, child.object) {
        (
            KernelObjectRef::MmioRegion {
                base: parent_base,
                size: parent_size,
            },
            KernelObjectRef::MmioRegion {
                base: child_base,
                size: child_size,
            },
        ) => {
            let Some(parent_end) = parent_base.checked_add(parent_size) else {
                return false;
            };
            let Some(child_end) = child_base.checked_add(child_size) else {
                return false;
            };
            child_base >= parent_base && child_end <= parent_end
        }
        _ => parent.object == child.object,
    }
}

impl KernelCapability {
    pub fn as_str(&self) -> &'static str {
        use KernelCapability::*;
        match self {
            ProcessKill => "process.kill",
            ProcessSpawn => "process.spawn",
            IpcEndpointCreate => "ipc.endpoint.create",
            IpcEndpointSend => "ipc.endpoint.send",
            IpcEndpointRecv => "ipc.endpoint.recv",
            VmMap => "vm.map",
            VmUnmap => "vm.unmap",
            MmioMap => "mmio.map",
            DmaAllocate => "dma.allocate",
            PhysMap => "memory.phys.map",
            PhysTranslate => "memory.phys.translate",
            IrqBind => "irq.bind",
            CextLoad => "cext.load",
            CextStop => "cext.stop",
            DeviceClaim => "device.claim",
            KernelDebug => "kernel.debug",
            SignatureWrite => "signature.db.write",
            SignatureRead => "signature.db.read",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        use KernelCapability::*;
        match s {
            "process.kill" => Some(ProcessKill),
            "process.spawn" => Some(ProcessSpawn),
            "ipc.endpoint.create" => Some(IpcEndpointCreate),
            "ipc.endpoint.send" => Some(IpcEndpointSend),
            "ipc.endpoint.recv" => Some(IpcEndpointRecv),
            "vm.map" => Some(VmMap),
            "vm.unmap" => Some(VmUnmap),
            "mmio.map" => Some(MmioMap),
            "dma.allocate" => Some(DmaAllocate),
            "memory.phys.map" => Some(PhysMap),
            "memory.phys.translate" => Some(PhysTranslate),
            "irq.bind" => Some(IrqBind),
            "cext.load" => Some(CextLoad),
            "cext.stop" => Some(CextStop),
            "device.claim" => Some(DeviceClaim),
            "kernel.debug" => Some(KernelDebug),
            _ => None,
        }
    }
}

/// mnu が直接強制する権限と、上位層が定義する不透明な権限です。
///
/// `Dynamic` の値は起動中だけ有効な内部IDです。外部ABIでは引き続き名前を使い、
/// mnuはその意味や許可UIの分類を解釈しません。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    FsReadUserDocuments,
    FsWriteUserDocuments,
    FsReadUserDownloads,
    FsWriteUserDownloads,
    FsReadUserDesktop,
    FsWriteUserDesktop,
    FsReadUserPictures,
    FsWriteUserPictures,
    FsReadUserMusic,
    FsWriteUserMusic,
    FsReadUserVideos,
    FsWriteUserVideos,
    FsReadUser,
    FsWriteUser,
    FsReadTmp,
    FsWriteTmp,
    FsReadRemovable,
    FsWriteRemovable,
    FsReadAll,
    FsWriteAll,

    IpcClient,
    IpcServer,

    ProcessSpawn,
    ProcessInspect,
    ProcessKill,

    DisplayRead,
    UsbAccess,
    SerialAccess,
    SystemTimeRead,
    SystemRandomRead,
    ServiceRegister,
    DmaAllocate,
    MemoryPhysMap,
    MemoryPhysTranslate,
    KernelDebug,
    DeviceGpu,
    DeviceInput,
    DeviceStorage,
    DeviceNet,
    SettingsRead,
    SettingsWrite,
    CapabilitiesManage,
    Unsandboxed,
    DeveloperProfile,
    SignatureRead,
    SignatureWrite,
    Dynamic(u32),
}

impl Capability {
    fn builtin_name(self) -> Option<&'static str> {
        use Capability::*;
        Some(match self {
            FsReadUserDocuments => "fs.read.user.documents",
            FsWriteUserDocuments => "fs.write.user.documents",
            FsReadUserDownloads => "fs.read.user.downloads",
            FsWriteUserDownloads => "fs.write.user.downloads",
            FsReadUserDesktop => "fs.read.user.desktop",
            FsWriteUserDesktop => "fs.write.user.desktop",
            FsReadUserPictures => "fs.read.user.pictures",
            FsWriteUserPictures => "fs.write.user.pictures",
            FsReadUserMusic => "fs.read.user.music",
            FsWriteUserMusic => "fs.write.user.music",
            FsReadUserVideos => "fs.read.user.videos",
            FsWriteUserVideos => "fs.write.user.videos",
            FsReadUser => "fs.read.user",
            FsWriteUser => "fs.write.user",
            FsReadTmp => "fs.read.tmp",
            FsWriteTmp => "fs.write.tmp",
            FsReadRemovable => "fs.read.removable",
            FsWriteRemovable => "fs.write.removable",
            FsReadAll => "fs.read.all",
            FsWriteAll => "fs.write.all",
            IpcClient => "ipc.client",
            IpcServer => "ipc.server",
            ProcessSpawn => "process.spawn",
            ProcessInspect => "process.inspect",
            ProcessKill => "process.kill",
            DisplayRead => "display.read",
            UsbAccess => "usb.access",
            SerialAccess => "serial.access",
            SystemTimeRead => "system.time.read",
            SystemRandomRead => "system.random.read",
            ServiceRegister => "service.register",
            DmaAllocate => "dma.allocate",
            MemoryPhysMap => "memory.phys.map",
            MemoryPhysTranslate => "memory.phys.translate",
            KernelDebug => "kernel.debug",
            DeviceGpu => "device.gpu",
            DeviceInput => "device.input",
            DeviceStorage => "device.storage",
            DeviceNet => "device.net",
            SettingsRead => "settings.read",
            SettingsWrite => "settings.write",
            CapabilitiesManage => "capabilities.manage",
            Unsandboxed => "unsandboxed",
            DeveloperProfile => "developer.profile",
            SignatureRead => "signature.db.read",
            SignatureWrite => "signature.db.write",
            Dynamic(_) => return None,
        })
    }

    pub fn from_str(s: &str) -> Option<Self> {
        builtin_capability(s).or_else(|| lookup_dynamic_capability(s))
    }

    pub fn intern(s: &str) -> Option<Self> {
        if !valid_capability_name(s) {
            return None;
        }
        builtin_capability(s).or_else(|| intern_dynamic_capability(s))
    }

    pub fn is_delegable(&self) -> bool {
        matches!(
            self,
            Capability::FsReadUserDocuments
                | Capability::FsWriteUserDocuments
                | Capability::FsReadUserDownloads
                | Capability::FsWriteUserDownloads
                | Capability::FsReadUserDesktop
                | Capability::FsWriteUserDesktop
                | Capability::FsReadUserPictures
                | Capability::FsWriteUserPictures
                | Capability::FsReadUserMusic
                | Capability::FsWriteUserMusic
                | Capability::FsReadUserVideos
                | Capability::FsWriteUserVideos
                | Capability::FsReadUser
                | Capability::FsWriteUser
                | Capability::FsReadTmp
                | Capability::FsWriteTmp
                | Capability::FsReadRemovable
                | Capability::FsWriteRemovable
                | Capability::DisplayRead
                | Capability::SystemTimeRead
                | Capability::SettingsRead
                | Capability::Dynamic(_)
        )
    }

    pub fn bootstrap_capabilities() -> &'static [Capability] {
        use Capability::*;
        const BOOTSTRAP: &[Capability] = &[
            FsReadUserDocuments,
            FsWriteUserDocuments,
            FsReadUserDownloads,
            FsWriteUserDownloads,
            FsReadUserDesktop,
            FsWriteUserDesktop,
            FsReadUserPictures,
            FsWriteUserPictures,
            FsReadUserMusic,
            FsWriteUserMusic,
            FsReadUserVideos,
            FsWriteUserVideos,
            FsReadUser,
            FsWriteUser,
            FsReadTmp,
            FsWriteTmp,
            FsReadRemovable,
            FsWriteRemovable,
            FsReadAll,
            FsWriteAll,
            IpcClient,
            IpcServer,
            ProcessSpawn,
            ProcessInspect,
            ProcessKill,
            DisplayRead,
            UsbAccess,
            SerialAccess,
            SystemTimeRead,
            SystemRandomRead,
            ServiceRegister,
            DmaAllocate,
            MemoryPhysMap,
            MemoryPhysTranslate,
            KernelDebug,
            DeviceGpu,
            DeviceInput,
            DeviceStorage,
            DeviceNet,
            SettingsRead,
            SettingsWrite,
            CapabilitiesManage,
            Unsandboxed,
            DeveloperProfile,
            SignatureRead,
            SignatureWrite,
        ];
        BOOTSTRAP
    }
}

#[derive(Default)]
struct DynamicCapabilityRegistry {
    names: Vec<String>,
}

static DYNAMIC_CAPABILITIES: spin::Mutex<Option<DynamicCapabilityRegistry>> =
    spin::Mutex::new(None);

fn with_dynamic_registry<R>(f: impl FnOnce(&mut DynamicCapabilityRegistry) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut registry = DYNAMIC_CAPABILITIES.lock();
        f(registry.get_or_insert_with(DynamicCapabilityRegistry::default))
    })
}

fn valid_capability_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let endpoint_is_valid = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 512
        && endpoint_is_valid(bytes[0])
        && endpoint_is_valid(bytes[bytes.len() - 1])
        && !bytes.windows(2).any(|pair| pair == b"..")
        && bytes.iter().copied().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn builtin_capability(name: &str) -> Option<Capability> {
    Capability::bootstrap_capabilities()
        .iter()
        .copied()
        .find(|capability| capability.builtin_name() == Some(name))
}

fn lookup_dynamic_capability(name: &str) -> Option<Capability> {
    if !valid_capability_name(name) {
        return None;
    }
    with_dynamic_registry(|registry| {
        registry
            .names
            .iter()
            .position(|registered| registered == name)
            .map(|id| Capability::Dynamic(id as u32))
    })
}

fn intern_dynamic_capability(name: &str) -> Option<Capability> {
    const MAX_DYNAMIC_CAPABILITIES: usize = 4096;

    with_dynamic_registry(|registry| {
        if let Some(id) = registry
            .names
            .iter()
            .position(|registered| registered == name)
        {
            return Some(Capability::Dynamic(id as u32));
        }
        if registry.names.len() >= MAX_DYNAMIC_CAPABILITIES {
            return None;
        }
        let id = registry.names.len() as u32;
        registry.names.push(name.to_string());
        Some(Capability::Dynamic(id))
    })
}

/// `parent` が `child` を含意するか（階層継承）
///
/// ここでの含意は「より広い権限が、より細かい権限を内包する」関係を表す。
/// 例: `fs.read.all` は `fs.read.user.documents` を含意する。
pub fn capability_implies(parent: Capability, child: Capability) -> bool {
    use Capability::*;

    if parent == child {
        return true;
    }

    match parent {
        // unsandboxed は明示的に「すべて」を許可する最後の手段。
        // これを持つプロセスは隔離を回避できるため、付与経路は信頼済みでなければならない。
        Unsandboxed => true,

        FsReadAll => matches!(
            child,
            FsReadUser
                | FsReadUserDocuments
                | FsReadUserDownloads
                | FsReadUserDesktop
                | FsReadUserPictures
                | FsReadUserMusic
                | FsReadUserVideos
                | FsReadTmp
                | FsReadRemovable
        ),

        FsWriteAll => matches!(
            child,
            FsWriteUser
                | FsWriteUserDocuments
                | FsWriteUserDownloads
                | FsWriteUserDesktop
                | FsWriteUserPictures
                | FsWriteUserMusic
                | FsWriteUserVideos
                | FsWriteTmp
                | FsWriteRemovable
        ),

        FsReadUser => matches!(
            child,
            FsReadUserDocuments
                | FsReadUserDownloads
                | FsReadUserDesktop
                | FsReadUserPictures
                | FsReadUserMusic
                | FsReadUserVideos
        ),

        FsWriteUser => matches!(
            child,
            FsWriteUserDocuments
                | FsWriteUserDownloads
                | FsWriteUserDesktop
                | FsWriteUserPictures
                | FsWriteUserMusic
                | FsWriteUserVideos
        ),

        _ => false,
    }
}

/// capability の集合
#[derive(Clone, Debug, Default)]
pub struct CapabilitySet {
    caps: BTreeSet<Capability>,
}

#[derive(Clone, Debug, Default)]
pub struct KernelAuthoritySet {
    authorities: Vec<KernelAuthority>,
}

/// capability 文字列の解析エラー
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityParseError {
    InvalidCapability { name: String },
}

impl CapabilitySet {
    /// 空集合
    pub fn empty() -> Self {
        Self {
            caps: BTreeSet::new(),
        }
    }

    /// capability を追加
    pub fn insert(&mut self, cap: Capability) {
        self.caps.insert(cap);
    }

    /// capability を削除
    pub fn remove(&mut self, cap: Capability) -> bool {
        self.caps.remove(&cap)
    }

    /// capability の個数を返す
    pub fn len(&self) -> usize {
        self.caps.len()
    }

    /// 空集合かどうか
    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }

    /// capability の反復子を返す
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.caps.iter().copied()
    }

    /// 完全一致で含まれるか
    pub fn contains_exact(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    /// 含意（階層継承）を考慮して含まれるか
    pub fn contains(&self, cap: Capability) -> bool {
        self.implies(cap)
    }

    /// この集合が `cap` を満たすか（階層継承を含む）
    pub fn implies(&self, cap: Capability) -> bool {
        self.caps
            .iter()
            .copied()
            .any(|parent| capability_implies(parent, cap))
    }

    /// 文字列リストから生成
    pub fn from_strings(list: &[String]) -> Result<Self, CapabilityParseError> {
        let mut set = Self::empty();
        for s in list {
            let Some(cap) = Capability::intern(s.as_str()) else {
                return Err(CapabilityParseError::InvalidCapability {
                    name: s.to_string(),
                });
            };
            set.insert(cap);
        }
        Ok(set)
    }

    /// この集合が `other` に含まれるか（階層継承を考慮）
    pub fn is_subset_of(&self, other: &CapabilitySet) -> bool {
        self.iter().all(|cap| other.implies(cap))
    }
}

impl KernelAuthoritySet {
    pub fn empty() -> Self {
        Self {
            authorities: Vec::new(),
        }
    }

    pub fn insert(&mut self, authority: KernelAuthority) {
        if !self.authorities.contains(&authority) {
            self.authorities.push(authority);
        }
    }

    pub fn remove_exact(&mut self, authority: &KernelAuthority) -> bool {
        let Some(index) = self
            .authorities
            .iter()
            .position(|existing| existing == authority)
        else {
            return false;
        };
        self.authorities.remove(index);
        true
    }

    pub fn len(&self) -> usize {
        self.authorities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &KernelAuthority> {
        self.authorities.iter()
    }

    pub fn contains_exact(&self, authority: &KernelAuthority) -> bool {
        self.authorities.contains(authority)
    }

    pub fn implies(&self, authority: &KernelAuthority) -> bool {
        self.authorities
            .iter()
            .any(|parent| kernel_authority_implies(parent, authority))
    }

    pub fn contains_capability(&self, capability: KernelCapability) -> bool {
        self.authorities
            .iter()
            .any(|authority| authority.capability == capability)
    }

    pub fn is_subset_of(&self, other: &KernelAuthoritySet) -> bool {
        self.iter().all(|authority| other.implies(authority))
    }
}
