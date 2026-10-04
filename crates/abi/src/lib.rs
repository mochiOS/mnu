#![no_std]

/// ブートローダーからmnuへ渡す起動情報のABIです。
pub mod boot;

/// Canonical metadata for named capabilities shared by kernel and user space.
pub mod capability;

/// プロセス作成時に渡すメタデータのABIです。
pub mod exec;

/// ハイパーバイザーのDomainとして起動するときに使うABIです。
pub mod hypervisor;

/// mnuの性能計測結果をユーザー空間へ渡す固定ABIです。
pub mod performance;

/// Generic user-space-backed object operation protocol.
pub mod provider;

/// Grantで共有するrequest/response ringの固定ABIです。
pub mod shared_ring;

/// システムコール番号（Linux x86_64互換とmnu固有の番号）
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Lstat = 6,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    RtSigreturn = 15,
    Ioctl = 16,
    Readv = 19,
    Writev = 20,
    Access = 21,
    Pipe = 22,
    Select = 23,
    Dup = 32,
    Dup2 = 33,
    Nanosleep = 35,
    GetPid = 39,
    Fork = 57,
    Clone = 56,
    Execve = 59,
    Exit = 60,
    Wait = 61,
    Kill = 62,
    Uname = 63,
    Fcntl = 72,
    Fsync = 74,
    Fdatasync = 75,
    Ftruncate = 77,
    Getcwd = 79,
    Unlink = 87,
    // Native mnu file syscalls
    FileOpen = 560,
    FileOpenAt = 561,
    FileClose = 562,
    FileRead = 563,
    FileWrite = 564,
    FileSeek = 565,
    FileStat = 566,
    FileStatAt = 567,
    FileFstat = 568,
    FileReadDir = 569,
    FileCreateDir = 570,
    FileRemove = 571,
    FileRename = 572,
    FileSync = 573,
    Getuid = 102,
    Getgid = 104,
    Setuid = 105,
    Setgid = 106,
    Geteuid = 107,
    Getegid = 108,
    Setpgid = 109,
    GetPpid = 110,
    Setsid = 112,
    Getpgid = 121,
    Getsid = 124,
    Sigaltstack = 131,
    Statfs = 137,
    ArchPrctl = 158,
    GetTid = 186,
    Tkill = 200,
    Futex = 202,
    SetTidAddress = 218,
    ClockGettime = 228,
    ExitGroup = 231,
    Tgkill = 234,
    Openat = 257,
    Newfstatat = 262,
    Unlinkat = 263,
    Renameat = 264,
    Faccessat = 269,
    Pselect6 = 270,
    Ppoll = 271,
    SetRobustList = 273,
    Pipe2 = 293,
    Prlimit64 = 302,
    Getrandom = 318,
    Getrlimit = 97,
    Getdents64 = 217,

    Yield = 512,
    GetTicks = 513,
    IpcSend = 514,
    IpcRecv = 515,
    Exec = 516,
    Sleep = 517,
    FindProcessByName = 518,
    Log = 519,
    PortIn = 520,
    PortOut = 521,
    Mkdir = 522,
    Rmdir = 523,
    Readdir = 524,
    Chdir = 525,
    Reserved526 = 526,
    GetThreadPrivilege = 527,
    GetFramebufferInfo = 528,
    MapFramebuffer = 529,
    ExecFromBuffer = 530,
    SetConsoleCursor = 531,
    GetConsoleCursor = 532,
    IpcRecvWait = 533,
    Reserved534 = 534,
    Reserved535 = 535,
    MapPhysicalRange = 536,
    VirtToPhys = 537,
    PortInWords = 538,
    PortOutWords = 539,
    KeyboardInject = 540,
    MouseInject = 541,
    ExecFromBufferNamed = 542,
    ExecFromBufferNamedArgs = 543,
    ExecFromBufferNamedArgsWithRequester = 544,
    ExecFromFsStream = 545,
    MapPhysicalPages = 546,
    GetPhysicalAddr = 547,
    AllocSharedPages = 548,
    UnmapPages = 549,
    IpcSendPages = 550,
    IpcEndpointAlive = 551,
    ListProcesses = 552,
    CheckThreadCapability = 553,
    ExecWithCapabilities = 554,
    BlockRead = 555,
    BlockWrite = 556,
    IpcEndpointOwner = 557,
    ProcessExit = 574,
    ProcessSpawn = 575,
    ProcessWait = 576,
    ThreadCreate = 577,
    ThreadExit = 578,
    ThreadYield = 579,
    MemoryAlloc = 580,
    MemoryFree = 581,
    MemoryMap = 582,
    MemoryUnmap = 583,
    MemoryProtect = 584,
    MemoryShare = 585,
    MemorySync = 586,
    IpcCreate = 587,
    IpcCall = 588,
    IpcReply = 589,
    IpcWait = 590,
    CapClone = 591,
    CapDrop = 592,
    CapTransfer = 593,
    CapQuery = 594,
    CapRestrict = 595,
    EventCreate = 596,
    EventWait = 597,
    EventSignal = 598,
    EventPoll = 599,
    TimeNow = 600,
    ServiceSpawn = 601,
    ServiceDelegateRegister = 602,
    DriverSpawn = 603,
    DmaAlloc = 604,
    DmaFree = 605,
    ExecManifest = 606,
    RandomFill = 607,
    ExecManifestWithCredentials = 608,
    ExecManifestForRequester = 609,
    PresentFramebuffer = 610,
    StorageControl = 611,
    PerformanceSnapshot = 612,
    FramebufferTransferLimit = 613,
    CommitFramebuffer = 614,
    DeviceControl = 615,
    AuthorizeExec = 616,
    GetThreadSecurityContext = 617,
    BootSystemSlot = 618,
    BlockFlush = 619,
    BootEspGuid = 620,
    IpcSendHandles = 621,
    IpcRecvHandles = 622,
    IpcCallHandles = 623,
    FilesystemRegister = 624,
    FilesystemMount = 625,
    HandleClose = 626,
    HandleDuplicate = 627,
    LaunchHandleGet = 628,
    IpcCreateHandle = 629,
    IpcSendObjectHandles = 630,
    IpcRecvObjectHandles = 631,
    IpcCallObjectHandles = 632,
    IpcReplyObjectHandles = 633,
    HandleRead = 634,
    HandleWrite = 635,
    HandleSeek = 636,
    ProviderObjectCreate = 637,
    ProviderObjectIdentify = 638,
    LaunchValueGet = 639,
    CheckGravityExist = 999,
}

/// Maximum number of generic kernel object handles carried by one IPC message.
pub const IPC_MAX_OBJECT_HANDLES: usize = 4;

pub const HANDLE_RIGHT_READ: u64 = 1 << 0;
pub const HANDLE_RIGHT_WRITE: u64 = 1 << 1;
pub const HANDLE_RIGHT_SEND: u64 = 1 << 2;
pub const HANDLE_RIGHT_RECEIVE: u64 = 1 << 3;
pub const HANDLE_RIGHT_WAIT: u64 = 1 << 4;
pub const HANDLE_RIGHT_SIGNAL: u64 = 1 << 5;
pub const HANDLE_RIGHT_MAP: u64 = 1 << 6;
pub const HANDLE_RIGHT_SEEK: u64 = 1 << 7;
pub const HANDLE_RIGHT_DUPLICATE: u64 = 1 << 62;
pub const HANDLE_RIGHT_TRANSFER: u64 = 1 << 63;
pub const HANDLE_RIGHT_ALL: u64 = HANDLE_RIGHT_READ
    | HANDLE_RIGHT_WRITE
    | HANDLE_RIGHT_SEND
    | HANDLE_RIGHT_RECEIVE
    | HANDLE_RIGHT_WAIT
    | HANDLE_RIGHT_SIGNAL
    | HANDLE_RIGHT_MAP
    | HANDLE_RIGHT_SEEK
    | HANDLE_RIGHT_DUPLICATE
    | HANDLE_RIGHT_TRANSFER;

/// Native seek bases used by `HandleSeek`.
///
/// These values intentionally do not match the POSIX `SEEK_*` constants.
/// Compatibility libraries must translate their public ABI to this native
/// mechanism explicitly.
pub const HANDLE_SEEK_START: u64 = 0x4d4e_5501;
pub const HANDLE_SEEK_CURRENT: u64 = 0x4d4e_5502;
pub const HANDLE_SEEK_END: u64 = 0x4d4e_5503;

/// One process-local object handle and the rights requested for transfer.
///
/// The receiver gets a different process-local handle number. `rights` must be
/// a subset of the sender's rights and the source must include TRANSFER.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcObjectHandle {
    pub handle: u32,
    pub reserved: u32,
    pub rights: u64,
}

/// Fixed-size generic object-handle attachment buffer used by IPC syscalls.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcObjectHandles {
    pub count: u32,
    pub reserved: u32,
    pub handles: [IpcObjectHandle; IPC_MAX_OBJECT_HANDLES],
}

/// Maximum number of file handles carried by one IPC message.
pub const IPC_MAX_FILE_HANDLES: usize = 4;

pub const FILE_HANDLE_RIGHT_READ: u32 = 1 << 0;
pub const FILE_HANDLE_RIGHT_WRITE: u32 = 1 << 1;
pub const FILE_HANDLE_RIGHT_SEEK: u32 = 1 << 2;
pub const FILE_HANDLE_RIGHT_STAT: u32 = 1 << 3;
pub const FILE_HANDLE_RIGHT_READDIR: u32 = 1 << 5;
pub const FILE_HANDLE_RIGHT_CREATE: u32 = 1 << 6;
pub const FILE_HANDLE_RIGHT_REMOVE: u32 = 1 << 7;
pub const FILE_HANDLE_RIGHT_RENAME: u32 = 1 << 8;
pub const FILE_HANDLE_RIGHT_SYNC: u32 = 1 << 9;
pub const FILE_HANDLE_RIGHT_TRUNCATE: u32 = 1 << 10;
/// Allows the receiving process to attach the handle to another IPC message.
pub const FILE_HANDLE_RIGHT_TRANSFER: u32 = 1 << 11;
/// Requests a new open-file description whose offset starts at zero.
///
/// This is an IPC transfer option, not a capability granted to the receiver.
/// The kernel strips it before validating and installing the requested rights.
pub const IPC_FILE_HANDLE_FLAG_FRESH_OFFSET: u32 = 1 << 31;
pub const FILE_HANDLE_RIGHT_ALL: u32 = FILE_HANDLE_RIGHT_READ
    | FILE_HANDLE_RIGHT_WRITE
    | FILE_HANDLE_RIGHT_SEEK
    | FILE_HANDLE_RIGHT_STAT
    | FILE_HANDLE_RIGHT_READDIR
    | FILE_HANDLE_RIGHT_CREATE
    | FILE_HANDLE_RIGHT_REMOVE
    | FILE_HANDLE_RIGHT_RENAME
    | FILE_HANDLE_RIGHT_SYNC
    | FILE_HANDLE_RIGHT_TRUNCATE
    | FILE_HANDLE_RIGHT_TRANSFER;

/// One file descriptor and the rights requested for an IPC transfer.
///
/// On send, `fd` belongs to the sender. On receive, it is replaced with the
/// descriptor installed in the receiver.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcFileHandle {
    pub fd: i32,
    pub rights: u32,
}

/// Fixed-size file-handle attachment buffer used by IPC syscalls.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcFileHandles {
    pub count: u32,
    pub reserved: u32,
    pub handles: [IpcFileHandle; IPC_MAX_FILE_HANDLES],
}

/// `StorageControl` が受け取る、プラットフォーム固有ストレージ操作の固定長要求です。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageControlRequest {
    pub operation: u16,
    pub reserved0: u16,
    pub device_id: u32,
    pub arguments: [u64; 4],
}

/// `StorageControl` が返す固定長応答です。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageControlResponse {
    pub status: u32,
    pub device_id: u32,
    pub values: [u64; 4],
}

#[cfg(test)]
mod object_handle_tests {
    use super::*;

    #[test]
    fn object_handle_wire_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<IpcObjectHandle>(), 16);
        assert_eq!(core::mem::size_of::<IpcObjectHandles>(), 72);
        assert_eq!(core::mem::align_of::<IpcObjectHandles>(), 8);
    }

    #[test]
    fn object_handle_rights_are_disjoint_and_complete() {
        let rights = [
            HANDLE_RIGHT_READ,
            HANDLE_RIGHT_WRITE,
            HANDLE_RIGHT_SEND,
            HANDLE_RIGHT_RECEIVE,
            HANDLE_RIGHT_WAIT,
            HANDLE_RIGHT_SIGNAL,
            HANDLE_RIGHT_MAP,
            HANDLE_RIGHT_SEEK,
            HANDLE_RIGHT_DUPLICATE,
            HANDLE_RIGHT_TRANSFER,
        ];
        let mut combined = 0;
        for right in rights {
            assert_eq!(combined & right, 0);
            combined |= right;
        }
        assert_eq!(combined, HANDLE_RIGHT_ALL);
    }

    #[test]
    fn native_handle_syscalls_do_not_overlap_filesystem_registration() {
        let numbers = [
            SyscallNumber::HandleClose as u64,
            SyscallNumber::HandleDuplicate as u64,
            SyscallNumber::LaunchHandleGet as u64,
            SyscallNumber::IpcCreateHandle as u64,
            SyscallNumber::IpcSendObjectHandles as u64,
            SyscallNumber::IpcRecvObjectHandles as u64,
            SyscallNumber::IpcCallObjectHandles as u64,
            SyscallNumber::IpcReplyObjectHandles as u64,
            SyscallNumber::HandleRead as u64,
            SyscallNumber::HandleWrite as u64,
            SyscallNumber::HandleSeek as u64,
            SyscallNumber::ProviderObjectCreate as u64,
            SyscallNumber::ProviderObjectIdentify as u64,
            SyscallNumber::LaunchValueGet as u64,
        ];
        assert!(numbers.iter().all(|number| *number > 625));
        for (index, number) in numbers.iter().enumerate() {
            assert!(!numbers[..index].contains(number));
        }
    }
}

/// Opaque platform device messages; the selected capability scopes operations.
pub type DeviceControlRequest = StorageControlRequest;
pub type DeviceControlResponse = StorageControlResponse;

/// `arguments[0]` 番目のストレージ候補を返します。
pub const STORAGE_CONTROL_LIST_DEVICE: u16 = 0;
pub const STORAGE_CONTROL_INSPECT: u16 = 1;
pub const STORAGE_CONTROL_CREATE_PARTITION: u16 = 2;
pub const STORAGE_CONTROL_DELETE_PARTITION: u16 = 3;
pub const STORAGE_CONTROL_INSTALL_PARTITION: u16 = 4;

pub const STORAGE_STATUS_OK: u32 = 0;
pub const STORAGE_STATUS_END: u32 = 6;

pub const STORAGE_QUERY_DISK: u64 = 0;
pub const STORAGE_QUERY_PARTITION_GUIDS: u64 = 1;
pub const STORAGE_QUERY_PARTITION_RANGE: u64 = 2;

/// `ExecManifestWithCredentials` に渡す固定長の資格情報指定。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecManifestCredentials {
    pub execution_class: u64,
    pub uid: u32,
    pub gid: u32,
    pub reserved: u64,
}

/// `ExecManifestForRequester` に渡す固定長の要求元指定。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecManifestRequester {
    pub execution_class: u64,
    pub requester_tid: u64,
    pub reserved: u64,
}

pub const APPLICATION_ID_FIELD_LEN: usize = 128;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadSecurityContext {
    pub process_id: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub provenance: u8,
    pub reserved0: [u8; 7],
    pub subject_key_id: [u8; 32],
    pub package_id_len: u16,
    pub developer_id_len: u16,
    pub reserved1: u32,
    pub package_id: [u8; APPLICATION_ID_FIELD_LEN],
    pub developer_id: [u8; APPLICATION_ID_FIELD_LEN],
}

impl Default for ThreadSecurityContext {
    fn default() -> Self {
        Self {
            process_id: 0,
            effective_uid: 0,
            effective_gid: 0,
            provenance: 0,
            reserved0: [0; 7],
            subject_key_id: [0; 32],
            package_id_len: 0,
            developer_id_len: 0,
            reserved1: 0,
            package_id: [0; APPLICATION_ID_FIELD_LEN],
            developer_id: [0; APPLICATION_ID_FIELD_LEN],
        }
    }
}

#[cfg(test)]
mod credential_spawn_tests {
    use super::{
        ExecManifestCredentials, ExecManifestRequester, StorageControlRequest,
        StorageControlResponse,
    };

    #[test]
    fn credential_request_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<ExecManifestCredentials>(), 24);
        assert_eq!(core::mem::align_of::<ExecManifestCredentials>(), 8);
    }

    #[test]
    fn requester_request_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<ExecManifestRequester>(), 24);
        assert_eq!(core::mem::align_of::<ExecManifestRequester>(), 8);
    }

    #[test]
    fn storage_control_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<StorageControlRequest>(), 40);
        assert_eq!(core::mem::align_of::<StorageControlRequest>(), 8);
        assert_eq!(core::mem::size_of::<StorageControlResponse>(), 40);
        assert_eq!(core::mem::align_of::<StorageControlResponse>(), 8);
    }

    #[test]
    fn boot_system_slot_syscall_number_is_stable() {
        assert_eq!(super::SyscallNumber::BootSystemSlot as u64, 618);
    }

    #[test]
    fn ipc_file_handle_abi_is_stable() {
        assert_eq!(super::SyscallNumber::IpcSendHandles as u64, 621);
        assert_eq!(super::SyscallNumber::IpcRecvHandles as u64, 622);
        assert_eq!(super::SyscallNumber::IpcCallHandles as u64, 623);
        assert_eq!(core::mem::size_of::<super::IpcFileHandle>(), 8);
        assert_eq!(core::mem::size_of::<super::IpcFileHandles>(), 40);
        assert_eq!(super::FILE_HANDLE_RIGHT_ALL & (1 << 4), 0);
        assert_eq!(
            super::FILE_HANDLE_RIGHT_ALL & super::IPC_FILE_HANDLE_FLAG_FRESH_OFFSET,
            0
        );
    }

    #[test]
    fn userspace_filesystem_syscall_numbers_are_stable() {
        assert_eq!(super::SyscallNumber::FilesystemRegister as u64, 624);
        assert_eq!(super::SyscallNumber::FilesystemMount as u64, 625);
    }

    #[test]
    fn native_file_handle_io_abi_is_not_posix_seek_abi() {
        assert_eq!(super::SyscallNumber::HandleRead as u64, 634);
        assert_eq!(super::SyscallNumber::HandleWrite as u64, 635);
        assert_eq!(super::SyscallNumber::HandleSeek as u64, 636);
        assert_eq!(super::SyscallNumber::ProviderObjectCreate as u64, 637);
        assert_eq!(super::SyscallNumber::ProviderObjectIdentify as u64, 638);
        assert!(![0, 1, 2].contains(&super::HANDLE_SEEK_START));
        assert!(![0, 1, 2].contains(&super::HANDLE_SEEK_CURRENT));
        assert!(![0, 1, 2].contains(&super::HANDLE_SEEK_END));
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DmaAllocation {
    pub handle: u64,
    pub virt_addr: u64,
    pub phys_addr: u64,
    pub len: u64,
}

/// 成功
pub const SUCCESS: u64 = 0;
/// 操作が許可されていない
pub const EPERM: u64 = (-1i64) as u64;
/// ファイルが見つからない
pub const ENOENT: u64 = (-2i64) as u64;
/// プロセスが見つからない
pub const ESRCH: u64 = (-3i64) as u64;
/// I/Oエラー
pub const EIO: u64 = (-5i64) as u64;
/// デバイスが見つからない
pub const ENXIO: u64 = (-6i64) as u64;
/// 不正なファイルディスクリプタ
pub const EBADF: u64 = (-9i64) as u64;
/// 子プロセスが存在しない
pub const ECHILD: u64 = (-10i64) as u64;
/// 受信/送信できない（キュー空/満杯）
pub const EAGAIN: u64 = (-11i64) as u64;
/// メモリ不足
pub const ENOMEM: u64 = (-12i64) as u64;
/// アクセス権がない
pub const EACCES: u64 = (-13i64) as u64;
/// 不正なアドレス
pub const EFAULT: u64 = (-14i64) as u64;
/// ファイルが既に存在する
pub const EEXIST: u64 = (-17i64) as u64;
/// ディレクトリではない
pub const ENOTDIR: u64 = (-20i64) as u64;
/// ディレクトリを開こうとしたがファイルだった
pub const EISDIR: u64 = (-21i64) as u64;
/// 無効な引数
pub const EINVAL: u64 = (-22i64) as u64;
/// ファイルディスクリプタが多すぎる
pub const EMFILE: u64 = (-24i64) as u64;
/// ファイルが実装上の最大サイズを超える
pub const EFBIG: u64 = (-27i64) as u64;
/// ディスク/ストレージに空きがない
pub const ENOSPC: u64 = (-28i64) as u64;
/// 読み取り専用ファイルシステム
pub const EROFS: u64 = (-30i64) as u64;
/// デバイスでない
pub const ENOTTY: u64 = (-25i64) as u64;
/// パイプが壊れている
pub const EPIPE: u64 = (-32i64) as u64;
/// 引数が範囲外
pub const ERANGE: u64 = (-34i64) as u64;
/// 未実装
pub const ENOSYS: u64 = (-38i64) as u64;
/// データがない / ノンブロッキングで読み出しできない
pub const ENODATA: u64 = (-61i64) as u64;
/// 値が表現可能な範囲を超える
pub const EOVERFLOW: u64 = (-75i64) as u64;
/// Message cannot be received by the selected IPC receive operation.
pub const EMSGSIZE: u64 = (-90i64) as u64;
/// 操作がサポートされていない
pub const ENOTSUP: u64 = (-95i64) as u64;
