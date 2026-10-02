//! プロセスごとのファイルディスクリプタテーブル

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::interrupt::spinlock::SpinLock;
use crate::vfs::Vnode;

/// stdin / stdout / stderr の予約 FD 番号
pub const FD_BASE: usize = 3;

/// プロセスあたりの最大 FD 数
pub const PROCESS_MAX_FDS: usize = 256;

/// FD フラグ: exec 時にクローズする
pub const FD_CLOEXEC: u8 = 0x01;

/// open() フラグ: O_CLOEXEC (Linux: 0o2000000 = 0x80000)
pub const O_CLOEXEC: u64 = 0x80000;

/// FileHandle に付与する権限
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHandleCap(u32);

impl FileHandleCap {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_READ);
    pub const WRITE: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_WRITE);
    pub const SEEK: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_SEEK);
    pub const STAT: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_STAT);
    // Bit 4 used to represent CLOSE. Closing only discards a descriptor owned
    // by the current process, so it is intentionally not a resource right.
    pub const READDIR: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_READDIR);
    pub const CREATE: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_CREATE);
    pub const REMOVE: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_REMOVE);
    pub const RENAME: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_RENAME);
    pub const SYNC: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_SYNC);
    pub const TRUNCATE: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_TRUNCATE);
    pub const TRANSFER: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_TRANSFER);
    pub const ALL: Self = Self(mnu_abi::FILE_HANDLE_RIGHT_ALL);

    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits != 0 && (bits & !Self::ALL.0) == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub fn from_open_flags(flags: u64) -> Self {
        let mut cap = Self::STAT
            .union(Self::SEEK)
            .union(Self::SYNC)
            .union(Self::TRANSFER);
        let acc = flags & 0o3;
        if acc == 0o0 {
            cap = cap.union(Self::READ);
        }
        if acc == 0o1 {
            cap = cap.union(Self::WRITE).union(Self::TRUNCATE);
        }
        if acc == 0o2 {
            cap = cap
                .union(Self::READ)
                .union(Self::WRITE)
                .union(Self::TRUNCATE);
        }
        if (flags & 0o100) != 0 {
            cap = cap.union(Self::CREATE);
        }
        if (flags & 0o200) != 0 {
            cap = cap.union(Self::CREATE);
        }
        if (flags & 0o1000) != 0 {
            cap = cap.union(Self::TRUNCATE);
        }
        cap
    }
}

/// `open(2)` が生成する open file description。
///
/// `dup(2)` と `fork(2)` はこのオブジェクトを共有するため、ファイル位置と
/// status flags は複製後も同じ状態を参照する。
pub struct OpenFile {
    /// ファイル内容（initfs からロード済み、パイプの場合は空）
    pub data: Box<[u8]>,
    /// 現在の読み取り/書き込み位置（パイプの場合はエントリインデックス兼用）
    pub pos: usize,
    /// 解決済みfilesystem object。pipeや匿名一時ファイルではNone。
    pub vnode: Option<Arc<Vnode>>,
    /// true の場合、データはリモート FD バックエンドで管理される（fd_remote 値を参照）
    pub is_remote: bool,
    /// リモートバックエンド側のファイルディスクリプタ（is_remote=true のとき有効）
    pub fd_remote: u64,
    /// Some(id) であればパイプ fd（グローバル PIPE_TABLE のインデックス）
    pub pipe_id: Option<usize>,
    /// パイプの書き込み端の場合 true
    pub pipe_write: bool,
    /// open()/openat() のファイル状態フラグ（F_GETFL/F_SETFL 用）
    pub open_flags: u64,
}

impl OpenFile {
    fn new_pipe(pipe_id: usize, pipe_write: bool, open_flags: u64) -> Self {
        Self {
            data: Box::new([]),
            pos: 0,
            vnode: None,
            is_remote: false,
            fd_remote: 0,
            pipe_id: Some(pipe_id),
            pipe_write,
            open_flags,
        }
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if let Some(pipe_id) = self.pipe_id {
            crate::syscall::fs::close_pipe_endpoint_from_kernel(pipe_id, self.pipe_write);
        }
        if self.is_remote {
            crate::syscall::fs::close_remote_fd_from_kernel(self.fd_remote);
        }
    }
}

/// プロセスの FD table が保持する descriptor。
///
/// descriptor 固有の capability と、共有される open file description を分離する。
pub struct FileHandle {
    pub open: Arc<SpinLock<OpenFile>>,
    /// この FD に許可された操作
    pub cap: FileHandleCap,
}

impl FileHandle {
    pub fn new(open: OpenFile, cap: FileHandleCap) -> Self {
        Self {
            open: Arc::new(SpinLock::new(open)),
            cap,
        }
    }

    pub fn duplicate(&self) -> Self {
        Self {
            open: self.open.clone(),
            cap: self.cap,
        }
    }

    /// Duplicates this handle with a subset of its rights for IPC transfer.
    pub fn duplicate_restricted(&self, requested: FileHandleCap) -> Option<Self> {
        if !self.cap.contains(FileHandleCap::TRANSFER) || !self.cap.contains(requested) {
            return None;
        }
        Some(Self {
            open: self.open.clone(),
            cap: requested,
        })
    }

    pub fn new_pipe_read(pipe_id: usize) -> Self {
        Self::new(
            OpenFile::new_pipe(pipe_id, false, 0),
            FileHandleCap::READ
                .union(FileHandleCap::SEEK)
                .union(FileHandleCap::STAT)
                .union(FileHandleCap::TRANSFER),
        )
    }

    pub fn new_pipe_write(pipe_id: usize) -> Self {
        Self::new(
            OpenFile::new_pipe(pipe_id, true, 1),
            FileHandleCap::WRITE.union(FileHandleCap::TRANSFER),
        )
    }
}

/// プロセスごとのファイルディスクリプタテーブル
///
/// エントリの所有権はテーブル自身が持つ。
pub struct FdTable {
    /// FD ごとのハンドル (`None` = 空き)
    entries: Box<[Option<Box<FileHandle>>]>,
    /// FD ごとのフラグ (FD_CLOEXEC など)
    flags: Box<[u8]>,
}

impl FdTable {
    /// 配列本体を直接ヒープへ確保して空のテーブルを作成する。
    pub fn new_boxed() -> Box<Self> {
        let entries = core::iter::repeat_with(|| None)
            .take(PROCESS_MAX_FDS)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let flags = alloc::vec![0; PROCESS_MAX_FDS].into_boxed_slice();
        Box::new(Self { entries, flags })
    }

    /// 新しい FileHandle を割り当て、使用した FD 番号 (>= FD_BASE) を返す。
    ///
    /// 空きスロットがない場合は `None`。
    pub fn alloc(&mut self, handle: Box<FileHandle>, cloexec: bool) -> Option<usize> {
        for i in FD_BASE..PROCESS_MAX_FDS {
            if self.entries[i].is_none() {
                self.entries[i] = Some(handle);
                self.flags[i] = if cloexec { FD_CLOEXEC } else { 0 };
                return Some(i);
            }
        }
        None
    }

    /// FD に対応する FileHandle の参照を返す。
    pub fn get(&self, fd: usize) -> Option<&FileHandle> {
        self.entries.get(fd)?.as_deref()
    }

    /// FD に対応する FileHandle の可変参照を返す。
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileHandle> {
        self.entries.get_mut(fd)?.as_deref_mut()
    }

    /// FD の所有権を取り出す（close に相当）。
    pub fn take(&mut self, fd: usize) -> Option<Box<FileHandle>> {
        if fd < FD_BASE || fd >= PROCESS_MAX_FDS {
            return None;
        }
        self.flags[fd] = 0;
        self.entries[fd].take()
    }

    /// 指定したFDへハンドルを設定する。既存のハンドルはここで閉じる。
    pub fn replace(&mut self, fd: usize, handle: Box<FileHandle>, cloexec: bool) -> bool {
        if fd < FD_BASE || fd >= PROCESS_MAX_FDS {
            return false;
        }
        self.entries[fd] = Some(handle);
        self.flags[fd] = if cloexec { FD_CLOEXEC } else { 0 };
        true
    }

    /// FD を閉じる。閉じた場合 `true`、既に空きの場合 `false`。
    pub fn close_fd(&mut self, fd: usize) -> bool {
        self.take(fd).is_some()
    }

    /// FD_CLOEXEC が設定されているすべての FD を閉じる（execve 時に呼ぶ）。
    pub fn close_cloexec_fds(&mut self) {
        for i in FD_BASE..PROCESS_MAX_FDS {
            if self.entries[i].is_some() && (self.flags[i] & FD_CLOEXEC) != 0 {
                self.entries[i] = None;
                self.flags[i] = 0;
            }
        }
    }

    /// すべての FD を閉じる（Drop で自動的に呼ばれる）。
    pub fn close_all(&mut self) {
        for i in FD_BASE..PROCESS_MAX_FDS {
            self.entries[i] = None;
            self.flags[i] = 0;
        }
    }

    /// fork 用: 全エントリを複製して新しい FdTable を返す。
    ///
    /// POSIX と同様、親子は同じ open file description とファイル位置を共有する。
    pub fn clone_for_fork(&self) -> Box<FdTable> {
        let mut new_table = FdTable::new_boxed();
        for i in 0..PROCESS_MAX_FDS {
            let Some(fh) = self.entries[i].as_deref() else {
                continue;
            };
            let new_fh = Box::new(fh.duplicate());
            new_table.entries[i] = Some(new_fh);
            new_table.flags[i] = self.flags[i];
        }
        new_table
    }

    /// FD のフラグを取得する。FD が未使用の場合 `None`。
    pub fn get_flags(&self, fd: usize) -> Option<u8> {
        if fd < FD_BASE || fd >= PROCESS_MAX_FDS {
            return None;
        }
        if self.entries[fd].is_none() {
            return None;
        }
        Some(self.flags[fd])
    }

    /// FD のフラグを設定する。FD が有効な場合 `true`。
    pub fn set_flags(&mut self, fd: usize, flags: u8) -> bool {
        if fd < FD_BASE || fd >= PROCESS_MAX_FDS {
            return false;
        }
        if self.entries[fd].is_none() {
            return false;
        }
        self.flags[fd] = flags;
        true
    }
}

impl Drop for FdTable {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{FileHandle, FileHandleCap};

    #[test]
    fn transferred_rights_must_be_a_subset() {
        let source = FileHandle::new_pipe_read(usize::MAX);
        let restricted = source
            .duplicate_restricted(FileHandleCap::READ.union(FileHandleCap::STAT))
            .expect("read-only subset should transfer");
        assert!(restricted.cap.contains(FileHandleCap::READ));
        assert!(!restricted.cap.contains(FileHandleCap::TRANSFER));
        assert!(source.duplicate_restricted(FileHandleCap::WRITE).is_none());
        assert!(restricted
            .duplicate_restricted(FileHandleCap::READ)
            .is_none());
    }

    #[test]
    fn close_is_not_a_file_handle_right() {
        assert_eq!(FileHandleCap::ALL.bits() & (1 << 4), 0);
        assert!(FileHandleCap::from_bits(1 << 4).is_none());
    }
}
