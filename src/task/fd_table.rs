//! プロセスごとのファイルディスクリプタテーブル

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

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
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SEEK: Self = Self(1 << 2);
    pub const STAT: Self = Self(1 << 3);
    pub const CLOSE: Self = Self(1 << 4);
    pub const READDIR: Self = Self(1 << 5);
    pub const CREATE: Self = Self(1 << 6);
    pub const REMOVE: Self = Self(1 << 7);
    pub const RENAME: Self = Self(1 << 8);
    pub const SYNC: Self = Self(1 << 9);
    pub const TRUNCATE: Self = Self(1 << 10);
    pub const ALL: Self = Self((1 << 11) - 1);

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

    pub fn from_open_flags(flags: u64) -> Self {
        let mut cap = Self::CLOSE
            .union(Self::STAT)
            .union(Self::SEEK)
            .union(Self::SYNC);
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

/// オープンファイルの状態を保持するハンドル
pub struct FileHandle {
    /// ファイル内容（initfs からロード済み、パイプの場合は空）
    pub data: Box<[u8]>,
    /// 現在の読み取り/書き込み位置（パイプの場合はエントリインデックス兼用）
    pub pos: usize,
    /// 実ファイルのパス（通常の永続ファイルにのみ設定）
    pub fs_path: Option<String>,
    /// Some(path) であればディレクトリ fd
    pub dir_path: Option<String>,
    /// true の場合、データはリモート FD バックエンドで管理される（fd_remote 値を参照）
    pub is_remote: bool,
    /// リモートバックエンド側のファイルディスクリプタ（is_remote=true のとき有効）
    pub fd_remote: u64,
    /// is_remote=true の場合の参照カウント（close時の二重クローズ防止）
    pub remote_refs: Option<Arc<AtomicUsize>>,
    /// Some(id) であればパイプ fd（グローバル PIPE_TABLE のインデックス）
    pub pipe_id: Option<usize>,
    /// パイプの書き込み端の場合 true
    pub pipe_write: bool,
    /// open()/openat() のファイル状態フラグ（F_GETFL/F_SETFL 用）
    pub open_flags: u64,
    /// この FD に許可された操作
    pub cap: FileHandleCap,
}

impl FileHandle {
    pub fn new_pipe_read(pipe_id: usize) -> Self {
        Self {
            data: Box::new([]),
            pos: 0,
            fs_path: None,
            dir_path: None,
            is_remote: false,
            fd_remote: 0,
            remote_refs: None,
            pipe_id: Some(pipe_id),
            pipe_write: false,
            open_flags: 0,
            cap: FileHandleCap::READ
                .union(FileHandleCap::SEEK)
                .union(FileHandleCap::STAT)
                .union(FileHandleCap::CLOSE),
        }
    }

    pub fn new_pipe_write(pipe_id: usize) -> Self {
        Self {
            data: Box::new([]),
            pos: 0,
            fs_path: None,
            dir_path: None,
            is_remote: false,
            fd_remote: 0,
            remote_refs: None,
            pipe_id: Some(pipe_id),
            pipe_write: true,
            open_flags: 1,
            cap: FileHandleCap::WRITE.union(FileHandleCap::CLOSE),
        }
    }

    #[inline]
    pub fn clone_remote_refs(&self) -> Option<Arc<AtomicUsize>> {
        if !self.is_remote {
            return None;
        }
        self.remote_refs.as_ref().map(|refs| {
            refs.fetch_add(1, Ordering::AcqRel);
            refs.clone()
        })
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        if let Some(pipe_id) = self.pipe_id {
            crate::syscall::fs::close_pipe_endpoint_from_kernel(pipe_id, self.pipe_write);
        }
        if !self.is_remote {
            return;
        }
        if let Some(refs) = self.remote_refs.as_ref() {
            if refs.fetch_sub(1, Ordering::AcqRel) == 1 {
                crate::syscall::fs::close_remote_fd_from_kernel(self.fd_remote);
            }
        } else {
            crate::syscall::fs::close_remote_fd_from_kernel(self.fd_remote);
        }
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
    /// 親子は独立したファイル位置を持つ（簡易コピーセマンティクス）。
    pub fn clone_for_fork(&self) -> Box<FdTable> {
        let mut new_table = FdTable::new_boxed();
        for i in 0..PROCESS_MAX_FDS {
            let Some(fh) = self.entries[i].as_deref() else {
                continue;
            };
            if let Some(pipe_id) = fh.pipe_id {
                crate::syscall::fs::clone_pipe_endpoint_from_kernel(pipe_id, fh.pipe_write);
            }
            let new_fh = Box::new(FileHandle {
                data: fh.data.clone(),
                pos: fh.pos,
                fs_path: fh.fs_path.clone(),
                dir_path: fh.dir_path.clone(),
                is_remote: fh.is_remote,
                fd_remote: fh.fd_remote,
                remote_refs: fh.clone_remote_refs(),
                pipe_id: fh.pipe_id,
                pipe_write: fh.pipe_write,
                open_flags: fh.open_flags,
                cap: fh.cap,
            });
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
