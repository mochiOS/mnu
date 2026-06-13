#![no_std]

/// mnu の公開システムコール番号
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    ProcessExit = 0,
    ProcessSpawn = 1,
    ProcessWait = 2,
    ThreadCreate = 3,
    ThreadExit = 4,
    ThreadYield = 5,
    MemoryAlloc = 6,
    MemoryFree = 7,
    MemoryMap = 8,
    MemoryUnmap = 9,
    MemoryProtect = 10,
    MemoryShare = 11,
    MemorySync = 12,
    IpcCreate = 13,
    IpcSend = 14,
    IpcRecv = 15,
    IpcCall = 16,
    IpcReply = 17,
    IpcWait = 18,
    CapClone = 19,
    CapDrop = 20,
    CapTransfer = 21,
    CapQuery = 22,
    CapRestrict = 23,
    EventCreate = 24,
    EventWait = 25,
    EventSignal = 26,
    EventPoll = 27,
    TimeNow = 28,
    Sleep = 29,
    CheckGravityExist = 30,
    Write = 31,
    FileOpen = 32,
    FileClose = 33,
    FileRead = 34,
    FileSeek = 35,
    FileStat = 36,
    FileTruncate = 37,
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
/// 無効な引数
pub const EINVAL: u64 = (-22i64) as u64;
/// ファイルディスクリプタが多すぎる
pub const EMFILE: u64 = (-24i64) as u64;
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
/// 操作がサポートされていない
pub const ENOTSUP: u64 = (-95i64) as u64;
