//! capability（権限）定義と集合型
//!
//! 外部表現は文字列（manifest 等）で扱い、カーネル内部では enum として保持する。
//! 文字列のまま全処理すると typo や比較の取り違えが起きやすく、また高速化もしづらいため、
//! ここで変換を集中管理する。

extern crate alloc;
pub mod path;

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};

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

/// service や application が解釈する高水準権限
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UserCapability {
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
    NetConnect,
    NetListen,
    NetRaw,
    WindowCreate,
    WindowOverlay,
    WindowCapture,
    DisplayRead,
    DisplayCapture,
    InputKeyboard,
    InputKeyboardGlobal,
    InputPointer,
    InputPointerGlobal,
    InputGamepad,
    AudioPlayback,
    AudioRecord,
    ClipboardRead,
    ClipboardWrite,
    NotificationSend,
    CameraAccess,
    MicrophoneAccess,
    LocationAccess,
    BluetoothAccess,
    UsbAccess,
    SerialAccess,
    PowerShutdown,
    PowerReboot,
    PowerSuspend,
    SystemTimeRead,
    SystemTimeSet,
    SystemInfoRead,
    SystemLogsRead,
    PackageInstall,
    PackageRemove,
    PackageUpdate,
    ServiceRegister,
    ServiceControl,
    VmCreate,
    VmControl,
    KernelModuleLoad,
    AccountSelfRead,
    AccountSelfModify,
    AccountOtherRead,
    AccountOtherModify,
    SettingsRead,
    SettingsWrite,
    CapabilitiesManage,
    Unsandboxed,
    DeveloperDebug,
    DeveloperProfile,
    DeveloperTracing,
}

impl UserCapability {
    pub fn as_str(&self) -> &'static str {
        use UserCapability::*;
        match self {
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
            NetConnect => "net.connect",
            NetListen => "net.listen",
            NetRaw => "net.raw",
            WindowCreate => "window.create",
            WindowOverlay => "window.overlay",
            WindowCapture => "window.capture",
            DisplayRead => "display.read",
            DisplayCapture => "display.capture",
            InputKeyboard => "input.keyboard",
            InputKeyboardGlobal => "input.keyboard.global",
            InputPointer => "input.pointer",
            InputPointerGlobal => "input.pointer.global",
            InputGamepad => "input.gamepad",
            AudioPlayback => "audio.playback",
            AudioRecord => "audio.record",
            ClipboardRead => "clipboard.read",
            ClipboardWrite => "clipboard.write",
            NotificationSend => "notification.send",
            CameraAccess => "camera.access",
            MicrophoneAccess => "microphone.access",
            LocationAccess => "location.access",
            BluetoothAccess => "bluetooth.access",
            UsbAccess => "usb.access",
            SerialAccess => "serial.access",
            PowerShutdown => "power.shutdown",
            PowerReboot => "power.reboot",
            PowerSuspend => "power.suspend",
            SystemTimeRead => "system.time.read",
            SystemTimeSet => "system.time.set",
            SystemInfoRead => "system.info.read",
            SystemLogsRead => "system.logs.read",
            PackageInstall => "package.install",
            PackageRemove => "package.remove",
            PackageUpdate => "package.update",
            ServiceRegister => "service.register",
            ServiceControl => "service.control",
            VmCreate => "vm.create",
            VmControl => "vm.control",
            KernelModuleLoad => "kernel.module.load",
            AccountSelfRead => "account.self.read",
            AccountSelfModify => "account.self.modify",
            AccountOtherRead => "account.other.read",
            AccountOtherModify => "account.other.modify",
            SettingsRead => "settings.read",
            SettingsWrite => "settings.write",
            CapabilitiesManage => "capabilities.manage",
            Unsandboxed => "unsandboxed",
            DeveloperDebug => "developer.debug",
            DeveloperProfile => "developer.profile",
            DeveloperTracing => "developer.tracing",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        use UserCapability::*;
        match s {
            "fs.read.user.documents" => Some(FsReadUserDocuments),
            "fs.write.user.documents" => Some(FsWriteUserDocuments),
            "fs.read.user.downloads" => Some(FsReadUserDownloads),
            "fs.write.user.downloads" => Some(FsWriteUserDownloads),
            "fs.read.user.desktop" => Some(FsReadUserDesktop),
            "fs.write.user.desktop" => Some(FsWriteUserDesktop),
            "fs.read.user.pictures" => Some(FsReadUserPictures),
            "fs.write.user.pictures" => Some(FsWriteUserPictures),
            "fs.read.user.music" => Some(FsReadUserMusic),
            "fs.write.user.music" => Some(FsWriteUserMusic),
            "fs.read.user.videos" => Some(FsReadUserVideos),
            "fs.write.user.videos" => Some(FsWriteUserVideos),
            "fs.read.user" => Some(FsReadUser),
            "fs.write.user" => Some(FsWriteUser),
            "fs.read.tmp" => Some(FsReadTmp),
            "fs.write.tmp" => Some(FsWriteTmp),
            "fs.read.removable" => Some(FsReadRemovable),
            "fs.write.removable" => Some(FsWriteRemovable),
            "fs.read.all" => Some(FsReadAll),
            "fs.write.all" => Some(FsWriteAll),
            "net.connect" => Some(NetConnect),
            "net.listen" => Some(NetListen),
            "net.raw" => Some(NetRaw),
            "window.create" => Some(WindowCreate),
            "window.overlay" => Some(WindowOverlay),
            "window.capture" => Some(WindowCapture),
            "display.read" => Some(DisplayRead),
            "display.capture" => Some(DisplayCapture),
            "input.keyboard" => Some(InputKeyboard),
            "input.keyboard.global" => Some(InputKeyboardGlobal),
            "input.pointer" => Some(InputPointer),
            "input.pointer.global" => Some(InputPointerGlobal),
            "input.gamepad" => Some(InputGamepad),
            "audio.playback" => Some(AudioPlayback),
            "audio.record" => Some(AudioRecord),
            "clipboard.read" => Some(ClipboardRead),
            "clipboard.write" => Some(ClipboardWrite),
            "notification.send" => Some(NotificationSend),
            "camera.access" => Some(CameraAccess),
            "microphone.access" => Some(MicrophoneAccess),
            "location.access" => Some(LocationAccess),
            "bluetooth.access" => Some(BluetoothAccess),
            "usb.access" => Some(UsbAccess),
            "serial.access" => Some(SerialAccess),
            "power.shutdown" => Some(PowerShutdown),
            "power.reboot" => Some(PowerReboot),
            "power.suspend" => Some(PowerSuspend),
            "system.time.read" => Some(SystemTimeRead),
            "system.time.set" => Some(SystemTimeSet),
            "system.info.read" => Some(SystemInfoRead),
            "system.logs.read" => Some(SystemLogsRead),
            "package.install" => Some(PackageInstall),
            "package.remove" => Some(PackageRemove),
            "package.update" => Some(PackageUpdate),
            "service.register" => Some(ServiceRegister),
            "service.control" => Some(ServiceControl),
            "vm.create" => Some(VmCreate),
            "vm.control" => Some(VmControl),
            "kernel.module.load" => Some(KernelModuleLoad),
            "account.self.read" => Some(AccountSelfRead),
            "account.self.modify" => Some(AccountSelfModify),
            "account.other.read" => Some(AccountOtherRead),
            "account.other.modify" => Some(AccountOtherModify),
            "settings.read" => Some(SettingsRead),
            "settings.write" => Some(SettingsWrite),
            "capabilities.manage" => Some(CapabilitiesManage),
            "unsandboxed" => Some(Unsandboxed),
            "developer.debug" => Some(DeveloperDebug),
            "developer.profile" => Some(DeveloperProfile),
            "developer.tracing" => Some(DeveloperTracing),
            _ => None,
        }
    }
}

/// capability の種別
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapabilityKind {
    Kernel,
    User,
}

/// capability（権限）
///
/// 文字列名は `Capability::as_str()` / `Capability::from_str()` で相互変換する。
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

    NetConnect,
    NetListen,
    NetRaw,

    IpcClient,
    IpcServer,

    ProcessSpawn,
    ProcessInspect,
    ProcessKill,

    WindowCreate,
    WindowOverlay,
    WindowCapture,

    DisplayRead,
    DisplayCapture,

    InputKeyboard,
    InputKeyboardGlobal,
    InputPointer,
    InputPointerGlobal,
    InputGamepad,

    AudioPlayback,
    AudioRecord,

    ClipboardRead,
    ClipboardWrite,

    NotificationSend,

    CameraAccess,
    MicrophoneAccess,
    LocationAccess,

    BluetoothAccess,
    UsbAccess,
    SerialAccess,

    PowerShutdown,
    PowerReboot,
    PowerSuspend,

    SystemTimeRead,
    SystemTimeSet,
    SystemInfoRead,
    SystemLogsRead,

    PackageInstall,
    PackageRemove,
    PackageUpdate,

    ServiceRegister,
    ServiceControl,

    VmCreate,
    VmControl,

    MemoryPhysMap,
    MemoryPhysTranslate,

    KernelModuleLoad,
    KernelDebug,

    DeviceGpu,
    DeviceAudio,
    DeviceInput,
    DeviceStorage,
    DeviceNet,

    AccountSelfRead,
    AccountSelfModify,
    AccountOtherRead,
    AccountOtherModify,

    SettingsRead,
    SettingsWrite,
    CapabilitiesManage,

    Unsandboxed,

    DeveloperDebug,
    DeveloperProfile,
    DeveloperTracing,

    SignatureRead,
    SignatureWrite,
}

impl Capability {
    /// 文字列名へ変換する
    pub fn as_str(&self) -> &'static str {
        use Capability::*;
        match self {
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

            NetConnect => "net.connect",
            NetListen => "net.listen",
            NetRaw => "net.raw",

            IpcClient => "ipc.client",
            IpcServer => "ipc.server",

            ProcessSpawn => "process.spawn",
            ProcessInspect => "process.inspect",
            ProcessKill => "process.kill",

            WindowCreate => "window.create",
            WindowOverlay => "window.overlay",
            WindowCapture => "window.capture",

            DisplayRead => "display.read",
            DisplayCapture => "display.capture",

            InputKeyboard => "input.keyboard",
            InputKeyboardGlobal => "input.keyboard.global",
            InputPointer => "input.pointer",
            InputPointerGlobal => "input.pointer.global",
            InputGamepad => "input.gamepad",

            AudioPlayback => "audio.playback",
            AudioRecord => "audio.record",

            ClipboardRead => "clipboard.read",
            ClipboardWrite => "clipboard.write",

            NotificationSend => "notification.send",

            CameraAccess => "camera.access",
            MicrophoneAccess => "microphone.access",
            LocationAccess => "location.access",

            BluetoothAccess => "bluetooth.access",
            UsbAccess => "usb.access",
            SerialAccess => "serial.access",

            PowerShutdown => "power.shutdown",
            PowerReboot => "power.reboot",
            PowerSuspend => "power.suspend",

            SystemTimeRead => "system.time.read",
            SystemTimeSet => "system.time.set",
            SystemInfoRead => "system.info.read",
            SystemLogsRead => "system.logs.read",

            PackageInstall => "package.install",
            PackageRemove => "package.remove",
            PackageUpdate => "package.update",

            ServiceRegister => "service.register",
            ServiceControl => "service.control",

            VmCreate => "vm.create",
            VmControl => "vm.control",

            MemoryPhysMap => "memory.phys.map",
            MemoryPhysTranslate => "memory.phys.translate",

            KernelModuleLoad => "kernel.module.load",
            KernelDebug => "kernel.debug",

            DeviceGpu => "device.gpu",
            DeviceAudio => "device.audio",
            DeviceInput => "device.input",
            DeviceStorage => "device.storage",
            DeviceNet => "device.net",

            AccountSelfRead => "account.self.read",
            AccountSelfModify => "account.self.modify",
            AccountOtherRead => "account.other.read",
            AccountOtherModify => "account.other.modify",

            SettingsRead => "settings.read",
            SettingsWrite => "settings.write",
            CapabilitiesManage => "capabilities.manage",

            Unsandboxed => "unsandboxed",

            DeveloperDebug => "developer.debug",
            DeveloperProfile => "developer.profile",
            DeveloperTracing => "developer.tracing",

            SignatureRead => "signature.db.read",
            SignatureWrite => "signature.db.write",
        }
    }

    /// 文字列名から変換する（不明な文字列は `None`）
    pub fn from_str(s: &str) -> Option<Self> {
        use Capability::*;
        let cap = match s {
            "fs.read.user.documents" => FsReadUserDocuments,
            "fs.write.user.documents" => FsWriteUserDocuments,
            "fs.read.user.downloads" => FsReadUserDownloads,
            "fs.write.user.downloads" => FsWriteUserDownloads,
            "fs.read.user.desktop" => FsReadUserDesktop,
            "fs.write.user.desktop" => FsWriteUserDesktop,
            "fs.read.user.pictures" => FsReadUserPictures,
            "fs.write.user.pictures" => FsWriteUserPictures,
            "fs.read.user.music" => FsReadUserMusic,
            "fs.write.user.music" => FsWriteUserMusic,
            "fs.read.user.videos" => FsReadUserVideos,
            "fs.write.user.videos" => FsWriteUserVideos,
            "fs.read.user" => FsReadUser,
            "fs.write.user" => FsWriteUser,
            "fs.read.tmp" => FsReadTmp,
            "fs.write.tmp" => FsWriteTmp,
            "fs.read.removable" => FsReadRemovable,
            "fs.write.removable" => FsWriteRemovable,
            "fs.read.all" => FsReadAll,
            "fs.write.all" => FsWriteAll,

            "net.connect" => NetConnect,
            "net.listen" => NetListen,
            "net.raw" => NetRaw,

            "ipc.client" => IpcClient,
            "ipc.server" => IpcServer,

            "process.spawn" => ProcessSpawn,
            "process.inspect" => ProcessInspect,
            "process.kill" => ProcessKill,

            "window.create" => WindowCreate,
            "window.overlay" => WindowOverlay,
            "window.capture" => WindowCapture,

            "display.read" => DisplayRead,
            "display.capture" => DisplayCapture,

            "input.keyboard" => InputKeyboard,
            "input.keyboard.global" => InputKeyboardGlobal,
            "input.pointer" => InputPointer,
            "input.pointer.global" => InputPointerGlobal,
            "input.gamepad" => InputGamepad,

            "audio.playback" => AudioPlayback,
            "audio.record" => AudioRecord,

            "clipboard.read" => ClipboardRead,
            "clipboard.write" => ClipboardWrite,

            "notification.send" => NotificationSend,

            "camera.access" => CameraAccess,
            "microphone.access" => MicrophoneAccess,
            "location.access" => LocationAccess,

            "bluetooth.access" => BluetoothAccess,
            "usb.access" => UsbAccess,
            "serial.access" => SerialAccess,

            "power.shutdown" => PowerShutdown,
            "power.reboot" => PowerReboot,
            "power.suspend" => PowerSuspend,

            "system.time.read" => SystemTimeRead,
            "system.time.set" => SystemTimeSet,
            "system.info.read" => SystemInfoRead,
            "system.logs.read" => SystemLogsRead,

            "package.install" => PackageInstall,
            "package.remove" => PackageRemove,
            "package.update" => PackageUpdate,

            "service.register" => ServiceRegister,
            "service.control" => ServiceControl,

            "vm.create" => VmCreate,
            "vm.control" => VmControl,

            "memory.phys.map" => MemoryPhysMap,
            "memory.phys.translate" => MemoryPhysTranslate,

            "kernel.module.load" => KernelModuleLoad,
            "kernel.debug" => KernelDebug,

            "device.gpu" => DeviceGpu,
            "device.audio" => DeviceAudio,
            "device.input" => DeviceInput,
            "device.storage" => DeviceStorage,
            "device.net" => DeviceNet,

            "account.self.read" => AccountSelfRead,
            "account.self.modify" => AccountSelfModify,
            "account.other.read" => AccountOtherRead,
            "account.other.modify" => AccountOtherModify,

            "settings.read" => SettingsRead,
            "settings.write" => SettingsWrite,
            "capabilities.manage" => CapabilitiesManage,

            "unsandboxed" => Unsandboxed,

            "developer.debug" => DeveloperDebug,
            "developer.profile" => DeveloperProfile,
            "developer.tracing" => DeveloperTracing,

            "signature.db.write" => SignatureWrite,
            "signature.db.read" => SignatureRead,

            _ => return None,
        };
        Some(cap)
    }

    pub fn kind(&self) -> CapabilityKind {
        if self.to_kernel_capability().is_some() {
            CapabilityKind::Kernel
        } else {
            CapabilityKind::User
        }
    }

    pub fn to_kernel_capability(&self) -> Option<KernelCapability> {
        use Capability::*;
        Some(match self {
            ProcessKill => KernelCapability::ProcessKill,
            ProcessSpawn => KernelCapability::ProcessSpawn,
            IpcClient => KernelCapability::IpcEndpointSend,
            IpcServer => KernelCapability::IpcEndpointRecv,
            VmCreate | VmControl => KernelCapability::VmMap,
            MemoryPhysMap => KernelCapability::PhysMap,
            MemoryPhysTranslate => KernelCapability::PhysTranslate,
            KernelModuleLoad => KernelCapability::CextLoad,
            KernelDebug => KernelCapability::KernelDebug,
            SignatureRead => KernelCapability::SignatureRead,
            SignatureWrite => KernelCapability::SignatureWrite,
            _ => return None,
        })
    }

    pub fn to_user_capability(&self) -> Option<UserCapability> {
        use Capability::*;
        Some(match self {
            FsReadUserDocuments => UserCapability::FsReadUserDocuments,
            FsWriteUserDocuments => UserCapability::FsWriteUserDocuments,
            FsReadUserDownloads => UserCapability::FsReadUserDownloads,
            FsWriteUserDownloads => UserCapability::FsWriteUserDownloads,
            FsReadUserDesktop => UserCapability::FsReadUserDesktop,
            FsWriteUserDesktop => UserCapability::FsWriteUserDesktop,
            FsReadUserPictures => UserCapability::FsReadUserPictures,
            FsWriteUserPictures => UserCapability::FsWriteUserPictures,
            FsReadUserMusic => UserCapability::FsReadUserMusic,
            FsWriteUserMusic => UserCapability::FsWriteUserMusic,
            FsReadUserVideos => UserCapability::FsReadUserVideos,
            FsWriteUserVideos => UserCapability::FsWriteUserVideos,
            FsReadUser => UserCapability::FsReadUser,
            FsWriteUser => UserCapability::FsWriteUser,
            FsReadTmp => UserCapability::FsReadTmp,
            FsWriteTmp => UserCapability::FsWriteTmp,
            FsReadRemovable => UserCapability::FsReadRemovable,
            FsWriteRemovable => UserCapability::FsWriteRemovable,
            FsReadAll => UserCapability::FsReadAll,
            FsWriteAll => UserCapability::FsWriteAll,
            NetConnect => UserCapability::NetConnect,
            NetListen => UserCapability::NetListen,
            NetRaw => UserCapability::NetRaw,
            WindowCreate => UserCapability::WindowCreate,
            WindowOverlay => UserCapability::WindowOverlay,
            WindowCapture => UserCapability::WindowCapture,
            DisplayRead => UserCapability::DisplayRead,
            DisplayCapture => UserCapability::DisplayCapture,
            InputKeyboard => UserCapability::InputKeyboard,
            InputKeyboardGlobal => UserCapability::InputKeyboardGlobal,
            InputPointer => UserCapability::InputPointer,
            InputPointerGlobal => UserCapability::InputPointerGlobal,
            InputGamepad => UserCapability::InputGamepad,
            AudioPlayback => UserCapability::AudioPlayback,
            AudioRecord => UserCapability::AudioRecord,
            ClipboardRead => UserCapability::ClipboardRead,
            ClipboardWrite => UserCapability::ClipboardWrite,
            NotificationSend => UserCapability::NotificationSend,
            CameraAccess => UserCapability::CameraAccess,
            MicrophoneAccess => UserCapability::MicrophoneAccess,
            LocationAccess => UserCapability::LocationAccess,
            BluetoothAccess => UserCapability::BluetoothAccess,
            UsbAccess => UserCapability::UsbAccess,
            SerialAccess => UserCapability::SerialAccess,
            PowerShutdown => UserCapability::PowerShutdown,
            PowerReboot => UserCapability::PowerReboot,
            PowerSuspend => UserCapability::PowerSuspend,
            SystemTimeRead => UserCapability::SystemTimeRead,
            SystemTimeSet => UserCapability::SystemTimeSet,
            SystemInfoRead => UserCapability::SystemInfoRead,
            SystemLogsRead => UserCapability::SystemLogsRead,
            PackageInstall => UserCapability::PackageInstall,
            PackageRemove => UserCapability::PackageRemove,
            PackageUpdate => UserCapability::PackageUpdate,
            ServiceRegister => UserCapability::ServiceRegister,
            ServiceControl => UserCapability::ServiceControl,
            VmCreate => UserCapability::VmCreate,
            VmControl => UserCapability::VmControl,
            MemoryPhysMap | MemoryPhysTranslate => return None,
            KernelModuleLoad => UserCapability::KernelModuleLoad,
            AccountSelfRead => UserCapability::AccountSelfRead,
            AccountSelfModify => UserCapability::AccountSelfModify,
            AccountOtherRead => UserCapability::AccountOtherRead,
            AccountOtherModify => UserCapability::AccountOtherModify,
            SettingsRead => UserCapability::SettingsRead,
            SettingsWrite => UserCapability::SettingsWrite,
            CapabilitiesManage => UserCapability::CapabilitiesManage,
            Unsandboxed => UserCapability::Unsandboxed,
            DeveloperDebug => UserCapability::DeveloperDebug,
            DeveloperProfile => UserCapability::DeveloperProfile,
            DeveloperTracing => UserCapability::DeveloperTracing,
            _ => return None,
        })
    }

    /// カーネルが最終的に強制する capability かどうか
    ///
    /// 現行の設計では、ここに列挙される capability はすべてカーネルが
    /// 付与・検証の最終責任を持つ。
    pub fn is_kernel_enforced(&self) -> bool {
        Self::kernel_enforced_capabilities().contains(self)
    }

    /// 他プロセスへ委譲可能かどうか。
    ///
    /// `Unsandboxed` や物理メモリ、プロセス生成のような強い権限は
    /// 低い権限のプロセスへ転送しない。
    pub fn is_delegable(&self) -> bool {
        !matches!(
            self,
            Capability::Unsandboxed
                | Capability::ProcessSpawn
                | Capability::KernelDebug
                | Capability::MemoryPhysMap
                | Capability::MemoryPhysTranslate
        )
    }

    /// カーネルが強制対象として扱う capability 一覧
    pub fn kernel_enforced_capabilities() -> &'static [Capability] {
        use Capability::*;
        const KERNEL_ENFORCED: &[Capability] = &[
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
            NetConnect,
            NetListen,
            NetRaw,
            IpcClient,
            IpcServer,
            ProcessSpawn,
            ProcessInspect,
            ProcessKill,
            WindowCreate,
            WindowOverlay,
            WindowCapture,
            DisplayRead,
            DisplayCapture,
            InputKeyboard,
            InputKeyboardGlobal,
            InputPointer,
            InputPointerGlobal,
            InputGamepad,
            AudioPlayback,
            AudioRecord,
            ClipboardRead,
            ClipboardWrite,
            NotificationSend,
            CameraAccess,
            MicrophoneAccess,
            LocationAccess,
            BluetoothAccess,
            UsbAccess,
            SerialAccess,
            PowerShutdown,
            PowerReboot,
            PowerSuspend,
            SystemTimeRead,
            SystemTimeSet,
            SystemInfoRead,
            SystemLogsRead,
            PackageInstall,
            PackageRemove,
            PackageUpdate,
            ServiceRegister,
            ServiceControl,
            VmCreate,
            VmControl,
            MemoryPhysMap,
            MemoryPhysTranslate,
            KernelModuleLoad,
            KernelDebug,
            DeviceGpu,
            DeviceAudio,
            DeviceInput,
            DeviceStorage,
            DeviceNet,
            AccountSelfRead,
            AccountSelfModify,
            AccountOtherRead,
            AccountOtherModify,
            SettingsRead,
            SettingsWrite,
            CapabilitiesManage,
            Unsandboxed,
            DeveloperDebug,
            DeveloperProfile,
            DeveloperTracing,
            SignatureRead,
            SignatureWrite,
        ];
        KERNEL_ENFORCED
    }

    /// 将来の拡張のための全 capability 一覧
    pub fn all_capabilities() -> &'static [Capability] {
        Self::kernel_enforced_capabilities()
    }
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

/// capability 文字列の解析エラー
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityParseError {
    /// 未知の capability 名
    UnknownCapability { name: String },
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
            let Some(cap) = Capability::from_str(s.as_str()) else {
                return Err(CapabilityParseError::UnknownCapability {
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
