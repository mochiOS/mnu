//! ファイルシステム関連のシステムコール

use super::types::{
    EACCES, EBADF, EEXIST, EFAULT, EINVAL, EIO, EISDIR, ENOENT, ENOSPC, ENOSYS, ENOTDIR, ESRCH,
    SUCCESS,
};
use crate::capability::path::{
    self, PathOwner, PathType, UserPath, PATH_CREATE, PATH_DELETE, PATH_LIST, PATH_READ, PATH_WRITE,
};
use crate::capability::Capability;
use crate::task::fd_table::{
    FdTable, FileHandle, FileHandleCap, FD_BASE, O_CLOEXEC, PROCESS_MAX_FDS,
};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

const MAX_IO_BYTES: usize = 128 * 1024 * 1024;
const IO_CHUNK_BYTES: usize = 1 * 1024 * 1024;

// グローバル FD テーブルは廃止。各プロセスの Process::fd_table を使用する。

#[inline]
fn current_process_id_raw() -> Option<u64> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id().as_u64()))
}

/// 現在プロセスの FD テーブルを読み取り専用で操作する。
fn with_fd_table<F, R>(pid_raw: u64, f: F) -> Option<R>
where
    F: FnOnce(&FdTable) -> R,
{
    let pid = crate::task::ids::ProcessId::from_u64(pid_raw);
    crate::task::with_process(pid, |p| f(p.fd_table()))
}

/// 現在プロセスの FD テーブルを可変で操作する。
fn with_fd_table_mut<F, R>(pid_raw: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut FdTable) -> R,
{
    let pid = crate::task::ids::ProcessId::from_u64(pid_raw);
    crate::task::with_process_mut(pid, |p| f(p.fd_table_mut()))
}

fn file_handle_cap(pid_raw: u64, fd: u64) -> Result<FileHandleCap, u64> {
    if fd < FD_BASE as u64 {
        return Err(EBADF);
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return Err(EBADF);
    }
    with_fd_table(pid_raw, |t| t.get(idx).map(|fh| fh.cap))
        .ok_or(EBADF)?
        .ok_or(EBADF)
}

fn require_cap(pid_raw: u64, fd: u64, need: FileHandleCap) -> Result<(), u64> {
    let cap = file_handle_cap(pid_raw, fd)?;
    if cap.contains(need) {
        Ok(())
    } else {
        Err(EACCES)
    }
}

fn read_cstring(ptr: u64) -> Result<String, u64> {
    crate::syscall::read_user_cstring(ptr, 1024)
}

fn resolve_path_at(pid_raw: u64, dirfd: i64, path_ptr: u64) -> Result<String, u64> {
    const AT_FDCWD: i64 = -100;

    if dirfd == AT_FDCWD {
        return read_cstring(path_ptr).map(|path| normalize_path(&path));
    }

    let idx = dirfd as usize;
    if idx >= PROCESS_MAX_FDS {
        return Err(EBADF);
    }
    let dir_path = match with_fd_table(pid_raw, |t| t.get(idx).and_then(|fh| fh.dir_path.clone())) {
        Some(Some(p)) => p,
        _ => return Err(EBADF),
    };
    let path = read_cstring(path_ptr)?;
    let full_path = if path.starts_with('/') {
        path
    } else {
        alloc::format!("{}/{}", dir_path.trim_end_matches('/'), path)
    };
    Ok(normalize_path(&full_path))
}

pub(crate) fn ensure_fs_path_readable(path: &str) -> Result<(), u64> {
    ensure_fs_path_access(path, PATH_READ)
}

fn ensure_fs_path_access(path: &str, needed_rights: u32) -> Result<(), u64> {
    let Some(entry) = path::lookup_path(path) else {
        return enforce_fs_path_capability(path, needed_rights);
    };
    let Some(pid_raw) = current_process_id_raw() else {
        return Err(EACCES);
    };
    if !path_owner_allows(entry.owner, pid_raw) {
        return Err(EACCES);
    }
    if entry.rights.contains(needed_rights) {
        Ok(())
    } else {
        enforce_fs_path_capability(path, needed_rights)
    }
}

fn path_owner_allows(owner: PathOwner, pid_raw: u64) -> bool {
    match owner {
        PathOwner::Any => true,
        PathOwner::System => false,
        PathOwner::Service(owner_pid) | PathOwner::Application(owner_pid) => owner_pid == pid_raw,
        PathOwner::User(_) => false,
    }
}

fn caller_has_cap(cap: Capability) -> bool {
    crate::syscall::security::caller_has_any_capability(&[cap])
}

fn cap_for_path(path_type: PathType, needed_rights: u32) -> Capability {
    let is_write = (needed_rights & (PATH_WRITE | PATH_CREATE | PATH_DELETE)) != 0;
    let is_read = (needed_rights & PATH_READ) != 0 || (needed_rights & PATH_LIST) != 0;

    match path_type {
        PathType::Temporary => {
            if is_write {
                Capability::FsWriteTmp
            } else {
                Capability::FsReadTmp
            }
        }
        PathType::User(UserPath::Documents) => {
            if is_write {
                Capability::FsWriteUserDocuments
            } else {
                Capability::FsReadUserDocuments
            }
        }
        PathType::User(UserPath::Download) => {
            if is_write {
                Capability::FsWriteUserDownloads
            } else {
                Capability::FsReadUserDownloads
            }
        }
        PathType::User(UserPath::Desktop) => {
            if is_write {
                Capability::FsWriteUserDesktop
            } else {
                Capability::FsReadUserDesktop
            }
        }
        PathType::User(UserPath::Images) => {
            if is_write {
                Capability::FsWriteUserPictures
            } else {
                Capability::FsReadUserPictures
            }
        }
        PathType::User(UserPath::Musics) => {
            if is_write {
                Capability::FsWriteUserMusic
            } else {
                Capability::FsReadUserMusic
            }
        }
        PathType::User(UserPath::Movies) => {
            if is_write {
                Capability::FsWriteUserVideos
            } else {
                Capability::FsReadUserVideos
            }
        }
        PathType::User(UserPath::Develop)
        | PathType::User(UserPath::Home)
        | PathType::User(UserPath::HomeRoot) => {
            if is_write {
                Capability::FsWriteUser
            } else {
                Capability::FsReadUser
            }
        }
        PathType::Binary
        | PathType::Libraries(_)
        | PathType::System(_)
        | PathType::Config
        | PathType::Applications(_)
        | PathType::Mount(_)
        | PathType::Var(_)
        | PathType::Root
        | PathType::Custom => {
            if is_write {
                Capability::FsWriteAll
            } else if is_read {
                Capability::FsReadAll
            } else {
                Capability::FsReadAll
            }
        }
    }
}

fn enforce_fs_path_capability(path: &str, needed_rights: u32) -> Result<(), u64> {
    let path_type = path::classify_path(path);
    let required = cap_for_path(path_type, needed_rights);
    if caller_has_cap(required) {
        return Ok(());
    }
    if required != Capability::FsReadAll
        && (needed_rights & (PATH_WRITE | PATH_CREATE | PATH_DELETE)) == 0
        && caller_has_cap(Capability::FsReadAll)
    {
        return Ok(());
    }
    if (needed_rights & (PATH_WRITE | PATH_CREATE | PATH_DELETE)) != 0
        && caller_has_cap(Capability::FsWriteAll)
    {
        return Ok(());
    }
    Err(EACCES)
}

fn open_required_rights(path: &str, flags: u64, is_dir: bool) -> u32 {
    const O_ACCMODE: u64 = 0o3;
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_EXCL: u64 = 0o200;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;
    let _ = path;
    let mut rights = if is_dir { PATH_LIST } else { PATH_READ };
    let acc = flags & O_ACCMODE;
    if acc == O_WRONLY || acc == O_RDWR || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0 {
        rights |= PATH_WRITE;
    }
    if (flags & O_CREAT) != 0 || (flags & O_EXCL) != 0 || (flags & O_TRUNC) != 0 {
        rights |= PATH_CREATE;
    }
    rights
}

fn required_rights_for_path_op(op: &str) -> u32 {
    match op {
        "read" | "stat" | "readlink" => PATH_READ,
        "write" | "truncate" => PATH_WRITE,
        "list" | "readdir" | "chdir" => PATH_LIST,
        "create" | "mkdir" => PATH_CREATE,
        "delete" | "rmdir" | "unlink" | "rename" => PATH_DELETE,
        _ => PATH_READ,
    }
}

pub(crate) fn close_remote_fd_from_kernel(_fd_remote: u64) {}

#[inline]
fn mode_is_directory(mode: u16) -> bool {
    (mode & 0xF000) == 0x4000
}

#[inline]
fn mode_for_stat(mode: u16) -> u32 {
    let mut out = mode as u32;
    if (out & 0xF000) == 0 {
        out |= 0x8000;
    }
    if (out & 0o777) == 0 {
        out |= 0o755;
    }
    out
}

#[inline]
pub(crate) fn metadata_rootfs_first(path: &str) -> Option<(u16, u64)> {
    crate::cext::fs::file_metadata(path).or_else(|| crate::init::fs::file_metadata(path))
}

#[inline]
pub(crate) fn is_directory_rootfs_first(path: &str) -> bool {
    crate::cext::fs::is_directory(path) || crate::init::fs::is_directory(path)
}

#[inline]
pub(crate) fn readdir_rootfs_first(path: &str) -> Option<Vec<String>> {
    crate::cext::fs::readdir_path(path).or_else(|| crate::init::fs::readdir_path(path))
}

fn parse_readdir_names(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in bytes.split(|&b| b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        if let Ok(name) = core::str::from_utf8(raw) {
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn parse_readdir_typed(bytes: &[u8]) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    for record in bytes.split(|&b| b == b'\n') {
        if record.len() < 2 {
            continue;
        }
        let dtype = record[record.len() - 1];
        if dtype == 0 {
            continue;
        }
        if record.len() >= 2 && record[record.len() - 2] == 0 {
            let name_bytes = &record[..record.len() - 2];
            if let Ok(name) = core::str::from_utf8(name_bytes) {
                if !name.is_empty() {
                    out.push((name.to_string(), dtype));
                }
            }
        }
    }
    out
}

/// パスを正規化する（`.` / `..` を解決し重複スラッシュを除去）
fn normalize_path(path: &str) -> String {
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
    if parts.is_empty() {
        "/".to_string()
    } else {
        alloc::format!("/{}", parts.join("/"))
    }
}

/// プロセスの CWD を基に相対パスを絶対パスへ解決する
fn resolve_path(pid_raw: u64, path: &str) -> String {
    if path.starts_with('/') {
        normalize_path(path)
    } else {
        let pid = crate::task::ids::ProcessId::from_u64(pid_raw);
        let cwd = crate::task::with_process(pid, |p| {
            let mut s = String::new();
            s.push_str(p.cwd());
            s
        })
        .unwrap_or_else(|| "/".to_string());
        normalize_path(&alloc::format!("{}/{}", cwd.trim_end_matches('/'), path))
    }
}

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

fn open_resolved_for_pid(owner_pid: u64, path: &str, flags: u64) -> u64 {
    let metadata = metadata_rootfs_first(path);
    let is_dir = metadata
        .map(|(mode, _)| mode_is_directory(mode))
        .unwrap_or_else(|| crate::cext::fs::is_directory(path));
    if let Err(errno) = ensure_fs_path_access(path, open_required_rights(path, flags, is_dir)) {
        return errno;
    }

    let acc = flags & O_ACCMODE;
    if is_dir && acc != 0 {
        return EISDIR;
    }

    let exists = metadata.is_some() || crate::cext::fs::file_metadata(path).is_some();
    if !exists {
        if (flags & O_CREAT) != 0 {
            if crate::cext::fs::create(path, 0o644) != 0 {
                return EIO;
            }
        } else {
            return ENOENT;
        }
    }
    if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 && exists {
        return EEXIST;
    }
    if (flags & O_TRUNC) != 0 && crate::cext::fs::truncate(path, 0) != 0 {
        return EIO;
    }

    let data_vec = if is_dir {
        Vec::new()
    } else {
        match crate::cext::fs::read_all(path) {
            Some(d) => d,
            None => return ENOENT,
        }
    };

    let cloexec = (flags & O_CLOEXEC) != 0;
    let handle = alloc::boxed::Box::new(FileHandle {
        data: data_vec.into_boxed_slice(),
        pos: 0,
        fs_path: if exists { Some(path.to_string()) } else { None },
        dir_path: if is_dir { Some(path.to_string()) } else { None },
        is_remote: false,
        fd_remote: 0,
        remote_refs: None,
        pipe_id: None,
        pipe_write: false,
        open_flags: flags,
        cap: if is_dir {
            FileHandleCap::READDIR
                .union(FileHandleCap::STAT)
                .union(FileHandleCap::SEEK)
                .union(FileHandleCap::CLOSE)
        } else {
            FileHandleCap::from_open_flags(flags).union(FileHandleCap::CLOSE)
        },
    });

    match with_fd_table_mut(owner_pid, |t| t.alloc(handle, cloexec)) {
        Some(Some(fd)) => fd as u64,
        _ => ENOSYS,
    }
}

/// Openシステムコール (initfs の読み取り専用をサポートする簡易実装)
pub fn open(path_ptr: u64, flags: u64) -> u64 {
    let owner_pid = match current_process_id_raw() {
        Some(pid) => pid,
        None => return EBADF,
    };

    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let path = resolve_path(owner_pid, &path);
    open_resolved_for_pid(owner_pid, &path, flags)
}

/// Closeシステムコール
pub fn close(fd: u64) -> u64 {
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::CLOSE) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    match with_fd_table_mut(pid, |t| t.take(idx)) {
        Some(Some(_)) => SUCCESS,
        _ => EBADF,
    }
}

/// Seekシステムコール
pub fn seek(fd: u64, offset: i64, whence: u64) -> u64 {
    if fd < FD_BASE as u64 {
        return ENOSYS;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::SEEK) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }

    match with_fd_table_mut(pid, |t| {
        let fh = t.get_mut(idx).ok_or(EBADF)?;
        let new_pos = match whence {
            0 => offset,
            1 => fh.pos as i64 + offset,
            2 => fh.data.len() as i64 + offset,
            _ => return Err(EINVAL),
        };
        if new_pos < 0 {
            return Err(EINVAL);
        }
        let new_pos = core::cmp::min(new_pos as usize, fh.data.len());
        fh.pos = new_pos;
        Ok(fh.pos as u64)
    }) {
        Some(Ok(pos)) => pos,
        Some(Err(e)) => e,
        None => EBADF,
    }
}

/// Linux x86_64 struct stat をユーザーバッファに書き込む
///
/// struct stat のレイアウト (144 バイト):
///   0:  st_dev    (u64)
///   8:  st_ino    (u64)
///   16: st_nlink  (u64)
///   24: st_mode   (u32)
///   28: st_uid    (u32)
///   32: st_gid    (u32)
///   36: __pad0    (u32)
///   40: st_rdev   (u64)
///   48: st_size   (i64)
///   56: st_blksize (i64)
///   64: st_blocks  (i64)  — 512 バイト単位
///   72-143: timespec × 3 + unused (ゼロ)
fn write_stat_buf(stat_ptr: u64, mode: u32, size: u64) {
    const STAT_SIZE: usize = 144;
    let blocks = size.div_ceil(512);
    let mut buf = [0u8; STAT_SIZE];
    buf[0..8].copy_from_slice(&1u64.to_ne_bytes());
    buf[8..16].copy_from_slice(&1u64.to_ne_bytes());
    buf[16..24].copy_from_slice(&1u64.to_ne_bytes());
    buf[24..28].copy_from_slice(&mode.to_ne_bytes());
    buf[48..56].copy_from_slice(&size.to_ne_bytes());
    buf[56..64].copy_from_slice(&4096u64.to_ne_bytes());
    buf[64..72].copy_from_slice(&blocks.to_ne_bytes());
    let _ = crate::syscall::copy_to_user(stat_ptr, &buf);
}

/// Fstatシステムコール
pub fn fstat(fd: u64, stat_ptr: u64) -> u64 {
    if stat_ptr == 0 {
        return EFAULT;
    }
    const STAT_SIZE: u64 = 144;
    if !crate::syscall::validate_user_ptr(stat_ptr, STAT_SIZE) {
        return EFAULT;
    }

    if fd < FD_BASE as u64 {
        // stdin/stdout/stderr → キャラクタデバイス (S_IFCHR | 0666 = 0x2000 | 0o666)
        write_stat_buf(stat_ptr, 0x2000 | 0o666, 0);
        return SUCCESS;
    }

    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::STAT) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }

    // FileHandle からメタデータを取得する
    let file_info = with_fd_table(pid, |t| {
        t.get(idx).map(|fh| {
            let metadata = fh
                .dir_path
                .as_deref()
                .or(fh.fs_path.as_deref())
                .and_then(metadata_rootfs_first);
            let size = metadata
                .map(|(_, size)| size)
                .unwrap_or(fh.data.len() as u64);
            let is_dir = metadata
                .map(|(mode, _)| mode_is_directory(mode))
                .unwrap_or(fh.dir_path.is_some());
            (size, is_dir)
        })
    });
    let (size, is_dir) = match file_info {
        Some(Some(v)) => v,
        _ => return EBADF,
    };
    let mode = if is_dir {
        0x4000u32 | 0o755
    } else {
        0x8000u32 | 0o644
    };
    write_stat_buf(stat_ptr, mode, size);
    SUCCESS
}

/// Statシステムコール
pub fn stat(path_ptr: u64, stat_ptr: u64) -> u64 {
    if path_ptr == 0 || stat_ptr == 0 {
        return EINVAL;
    }
    const STAT_SIZE: u64 = 144;
    if !crate::syscall::validate_user_ptr(stat_ptr, STAT_SIZE) {
        return EFAULT;
    }
    let owner_pid = match current_process_id_raw() {
        Some(pid) => pid,
        None => return EBADF,
    };
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let resolved = resolve_path(owner_pid, &path);
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_READ) {
        return errno;
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, size)) => {
            write_stat_buf(stat_ptr, mode_for_stat(mode), size);
            SUCCESS
        }
        None => ENOENT,
    }
}

/// Mkdirシステムコール（読み取り専用ファイルシステムのため未実装）
pub fn mkdir(_path_ptr: u64, _mode: u64) -> u64 {
    ENOSYS
}

/// Rmdirシステムコール
pub fn rmdir(path_ptr: u64) -> u64 {
    if path_ptr == 0 {
        return EINVAL;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let resolved = resolve_path(pid, &path);
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_DELETE) {
        return errno;
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, _)) if mode_is_directory(mode) => {}
        Some(_) => return ENOTDIR,
        None => return ENOENT,
    }
    if crate::cext::fs::remove(&resolved, true) != 0 {
        return EIO;
    }
    SUCCESS
}

/// Readdirシステムコール
pub fn readdir(fd: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    if buf_ptr == 0 || buf_len == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::READDIR) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }

    let dir_path = match with_fd_table(pid, |t| t.get(idx).and_then(|fh| fh.dir_path.clone())) {
        Some(Some(p)) => p,
        _ => return EBADF,
    };

    if let Err(errno) = ensure_fs_path_access(&dir_path, PATH_LIST) {
        return errno;
    }

    let names = match readdir_rootfs_first(&dir_path) {
        Some(n) => n,
        None => return EINVAL,
    };
    let joined = names.join("\n");
    let bytes = joined.as_bytes();
    let to_copy = core::cmp::min(bytes.len(), buf_len as usize);
    if crate::syscall::copy_to_user(buf_ptr, &bytes[..to_copy]).is_err() {
        return EFAULT;
    }
    to_copy as u64
}

/// Chdirシステムコール
pub fn chdir(path_ptr: u64) -> u64 {
    if path_ptr == 0 {
        return EINVAL;
    }
    let pid_raw = match current_process_id_raw() {
        Some(pid) => pid,
        None => return EBADF,
    };
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let resolved = resolve_path(pid_raw, &path);
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_LIST) {
        return errno;
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, _)) => {
            if !mode_is_directory(mode) {
                return ENOTDIR;
            }
        }
        None => return ENOENT,
    }
    let pid = crate::task::ids::ProcessId::from_u64(pid_raw);
    crate::task::with_process_mut(pid, |p| p.set_cwd(&resolved));
    SUCCESS
}

/// Getcwdシステムコール
pub fn getcwd(buf_ptr: u64, size: u64) -> u64 {
    if buf_ptr == 0 || size == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, size) {
        return EFAULT;
    }
    let pid_raw = match current_process_id_raw() {
        Some(pid) => pid,
        None => return EFAULT,
    };
    let pid = crate::task::ids::ProcessId::from_u64(pid_raw);
    let mut tmp = [0u8; 256];
    let cwd_len = crate::task::with_process(pid, |p| {
        let s = p.cwd().as_bytes();
        let n = s.len().min(255);
        tmp[..n].copy_from_slice(&s[..n]);
        n
    })
    .unwrap_or(1);
    let needed = cwd_len + 1;
    if (size as usize) < needed {
        return EINVAL;
    }
    if crate::syscall::copy_to_user(buf_ptr, &tmp[..cwd_len]).is_err() {
        return EFAULT;
    }
    if crate::syscall::copy_to_user(buf_ptr + cwd_len as u64, &[0]).is_err() {
        return EFAULT;
    }
    buf_ptr
}

/// Read: 開かれたファイルからデータを読み込む
pub fn read(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    if len == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, len) {
        return EFAULT;
    }
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::READ) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }

    let to_copy = match usize::try_from(len) {
        Ok(v) => v.min(MAX_IO_BYTES),
        Err(_) => MAX_IO_BYTES,
    };
    let mut written = 0usize;
    let mut tmp = alloc::vec![0u8; IO_CHUNK_BYTES];

    while written < to_copy {
        let chunk_len = core::cmp::min(IO_CHUNK_BYTES, to_copy - written);
        let read_len = match with_fd_table_mut(pid, |t| {
            let fh = t.get_mut(idx)?;
            let avail = fh.data.len().saturating_sub(fh.pos);
            let take = core::cmp::min(avail, chunk_len);
            if take == 0 {
                return Some(0usize);
            }
            tmp[..take].copy_from_slice(&fh.data[fh.pos..fh.pos + take]);
            fh.pos += take;
            Some(take)
        }) {
            Some(Some(v)) => v,
            _ => return EBADF,
        };
        if read_len == 0 {
            break;
        }
        if crate::syscall::copy_to_user(buf_ptr + written as u64, &tmp[..read_len]).is_err() {
            return EFAULT;
        }
        written += read_len;
    }

    written as u64
}

/// Write: 開かれたファイルへデータを書き込む
pub fn write(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    if len == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, len) {
        return EFAULT;
    }
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::WRITE) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }

    let Ok(len_usize) = usize::try_from(len) else {
        return EINVAL;
    };
    if len_usize > MAX_IO_BYTES {
        return ENOSPC;
    }

    let (start_pos, fs_path) =
        match with_fd_table(pid, |t| t.get(idx).map(|fh| (fh.pos, fh.fs_path.clone()))) {
            Some(Some(info)) => info,
            _ => return EBADF,
        };
    let mut written = 0usize;
    let mut tmp = alloc::vec![0u8; IO_CHUNK_BYTES];

    while written < len_usize {
        let chunk_len = core::cmp::min(IO_CHUNK_BYTES, len_usize - written);
        if let Err(errno) =
            crate::syscall::copy_from_user(buf_ptr + written as u64, &mut tmp[..chunk_len])
        {
            return errno;
        }

        if let Some(path) = fs_path.as_deref() {
            match crate::cext::fs::write_all(path, (start_pos + written) as u64, &tmp[..chunk_len])
            {
                Some(wrote_chunk) if wrote_chunk == chunk_len => {}
                _ => return EIO,
            }
        }

        let wrote = with_fd_table_mut(pid, |t| {
            let fh = t.get_mut(idx).ok_or(EBADF)?;
            let end = start_pos.checked_add(written + chunk_len).ok_or(EINVAL)?;
            let mut data = fh.data.to_vec();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start_pos + written..end].copy_from_slice(&tmp[..chunk_len]);
            fh.data = data.into_boxed_slice();
            fh.pos = end;
            Ok(())
        });
        match wrote {
            Some(Ok(())) => {}
            Some(Err(errno)) => return errno,
            None => return EBADF,
        }

        written += chunk_len;
    }

    written as u64
}

/// Fcntl システムコール（FD フラグ操作）
///
/// - F_GETFD (1): FD フラグを取得
/// - F_SETFD (2): FD フラグを設定
/// - F_GETFL (3): ファイル状態フラグを取得（スタブ: 0 を返す）
/// - F_SETFL (4): ファイル状態フラグを設定（スタブ: 成功を返す）
pub fn fcntl(fd: u64, cmd: u64, arg: u64) -> u64 {
    use crate::task::fd_table::FD_CLOEXEC;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;

    if fd < FD_BASE as u64 {
        // stdin/stdout/stderr: FD フラグは 0
        return match cmd {
            F_GETFD | F_GETFL | F_GETLK => 0,
            F_SETFD | F_SETFL | F_SETLK | F_SETLKW => SUCCESS,
            _ => EINVAL,
        };
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };

    match cmd {
        F_GETFD => match with_fd_table(pid, |t| t.get_flags(idx)) {
            Some(Some(flags)) => flags as u64,
            _ => EBADF,
        },
        F_SETFD => {
            let cloexec = (arg & 1) != 0;
            let new_flags = if cloexec { FD_CLOEXEC } else { 0 };
            match with_fd_table_mut(pid, |t| t.set_flags(idx, new_flags)) {
                Some(true) => SUCCESS,
                _ => EBADF,
            }
        }
        F_GETFL => match with_fd_table(pid, |t| t.get(idx).map(|fh| fh.open_flags)) {
            Some(Some(v)) => v,
            _ => EBADF,
        },
        F_SETFL => {
            match with_fd_table_mut(pid, |t| {
                let fh = t.get_mut(idx).ok_or(EBADF)?;
                fh.open_flags = (fh.open_flags & O_ACCMODE) | (arg & !O_ACCMODE);
                Ok::<(), u64>(())
            }) {
                Some(Ok(())) => SUCCESS,
                Some(Err(errno)) => errno,
                None => EBADF,
            }
        }
        F_GETLK => SUCCESS,
        F_SETLK | F_SETLKW => SUCCESS,
        _ => EINVAL,
    }
}

/// fsync/fdatasync システムコール（最小実装）
pub fn fsync(fd: u64) -> u64 {
    if fd < FD_BASE as u64 {
        return SUCCESS;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::SYNC) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    match with_fd_table(pid, |t| t.get(idx).is_some()) {
        Some(true) => SUCCESS,
        _ => EBADF,
    }
}

/// truncate システムコール（最小実装）
pub fn truncate(path_ptr: u64, len: u64) -> u64 {
    if path_ptr == 0 {
        return EFAULT;
    }
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let path = resolve_path(pid, &path);
    match metadata_rootfs_first(&path) {
        Some((mode, _)) if mode_is_directory(mode) => return EISDIR,
        Some(_) => {}
        None => return ENOENT,
    }
    if crate::cext::fs::file_metadata(&path).is_none() {
        return ENOENT;
    }
    if crate::cext::fs::truncate(&path, len) != 0 {
        return EIO;
    }
    SUCCESS
}

/// ftruncate システムコール（ローカル一時FDのみ）
pub fn ftruncate(fd: u64, len: u64) -> u64 {
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    if let Err(errno) = require_cap(pid, fd, FileHandleCap::TRUNCATE) {
        return errno;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let new_len = match usize::try_from(len) {
        Ok(v) => v,
        Err(_) => return EINVAL,
    };
    let res = with_fd_table_mut(pid, |t| {
        let fh = t.get_mut(idx).ok_or(EBADF)?;
        if fh.dir_path.is_some() {
            return Err(EISDIR);
        }
        if let Some(path) = fh.fs_path.as_deref() {
            if crate::cext::fs::truncate(path, len) != 0 {
                return Err(EIO);
            }
        }
        let mut data = fh.data.to_vec();
        data.resize(new_len, 0);
        fh.data = data.into_boxed_slice();
        if fh.pos > new_len {
            fh.pos = new_len;
        }
        Ok(())
    });
    match res {
        Some(Ok(())) => SUCCESS,
        Some(Err(errno)) => errno,
        None => EBADF,
    }
}

/// Dup システムコール: FD を複製して最小の空き番号に割り当てる
pub fn dup(fd: u64) -> u64 {
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };

    // 既存エントリをクローンして新しい FD を割り当てる
    let cloned = with_fd_table(pid, |t| {
        t.get(idx).map(|fh| {
            alloc::boxed::Box::new(FileHandle {
                data: fh.data.clone(),
                pos: fh.pos,
                fs_path: fh.fs_path.clone(),
                dir_path: fh.dir_path.clone(),
                is_remote: false,
                fd_remote: 0,
                remote_refs: None,
                pipe_id: fh.pipe_id,
                pipe_write: fh.pipe_write,
                open_flags: fh.open_flags,
                cap: fh.cap,
            })
        })
    });
    let new_handle = match cloned {
        Some(Some(h)) => h,
        _ => return EBADF,
    };

    match with_fd_table_mut(pid, |t| t.alloc(new_handle, false)) {
        Some(Some(new_fd)) => new_fd as u64,
        _ => ENOSYS,
    }
}

/// Dup2 システムコール: FD を指定した番号に複製する
pub fn dup2(old_fd: u64, new_fd: u64) -> u64 {
    if new_fd < FD_BASE as u64 || new_fd as usize >= PROCESS_MAX_FDS {
        return EBADF;
    }
    if old_fd == new_fd {
        // old_fd が有効かどうかだけ確認
        if old_fd < FD_BASE as u64 {
            return EBADF;
        }
        let pid = match current_process_id_raw() {
            Some(p) => p,
            None => return EBADF,
        };
        return match with_fd_table(pid, |t| t.get(old_fd as usize).is_some()) {
            Some(true) => old_fd,
            _ => EBADF,
        };
    }

    let new_idx = new_fd as usize;
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };

    if old_fd < FD_BASE as u64 {
        return EBADF;
    }
    let old_idx = old_fd as usize;
    if old_idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let new_handle = match with_fd_table(pid, |t| {
        t.get(old_idx).map(|fh| {
            alloc::boxed::Box::new(FileHandle {
                data: fh.data.clone(),
                pos: fh.pos,
                fs_path: fh.fs_path.clone(),
                dir_path: fh.dir_path.clone(),
                is_remote: false,
                fd_remote: 0,
                remote_refs: None,
                pipe_id: fh.pipe_id,
                pipe_write: fh.pipe_write,
                open_flags: fh.open_flags,
                cap: fh.cap,
            })
        })
    }) {
        Some(Some(h)) => h,
        _ => return EBADF,
    };

    // new_fd が使用中なら閉じる
    with_fd_table_mut(pid, |t| {
        t.close_fd(new_idx);
        let ptr = alloc::boxed::Box::into_raw(new_handle) as u64;
        t.entries[new_idx] = ptr;
        t.flags[new_idx] = 0;
    });

    new_fd
}

/// unlink システムコール
pub fn unlink(path_ptr: u64) -> u64 {
    if path_ptr == 0 {
        return EINVAL;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(errno) => return errno,
    };
    let resolved = resolve_path(pid, &path);
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_WRITE) {
        return errno;
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, _)) if mode_is_directory(mode) => return EISDIR,
        Some(_) => {}
        None => return ENOENT,
    }
    if crate::cext::fs::remove(&resolved, false) != 0 {
        return EIO;
    }
    SUCCESS
}

/// unlinkat システムコール（最小実装）
pub fn unlinkat(_dirfd: i64, path_ptr: u64, _flags: u64) -> u64 {
    unlink(path_ptr)
}

/// renameat システムコール
pub fn renameat(old_dirfd: i64, old_path_ptr: u64, new_dirfd: i64, new_path_ptr: u64) -> u64 {
    if old_path_ptr == 0 || new_path_ptr == 0 {
        return EINVAL;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let old_path = match resolve_path_at(pid, old_dirfd, old_path_ptr) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let new_path = match resolve_path_at(pid, new_dirfd, new_path_ptr) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    if let Err(errno) = ensure_fs_path_access(&old_path, PATH_DELETE) {
        return errno;
    }
    if let Err(errno) = ensure_fs_path_access(&new_path, PATH_CREATE) {
        return errno;
    }
    if metadata_rootfs_first(&old_path).is_none() || metadata_rootfs_first(&new_path).is_none() {
        return ENOENT;
    }
    if crate::cext::fs::rename(&old_path, &new_path) != 0 {
        return EIO;
    }
    SUCCESS
}

/// Openat システムコール
///
/// AT_FDCWD(-100) の場合は CWD 相対の open() と同等。
/// それ以外の dirfd は fd_table からディレクトリパスを取得してプレフィックスとして使用する。
pub fn openat(dirfd: i64, path_ptr: u64, flags: u64, _mode: u64) -> u64 {
    const AT_FDCWD: i64 = -100;

    if dirfd == AT_FDCWD {
        // CWD 相対 → 通常の open() と同じ
        return open(path_ptr, flags);
    }

    // dirfd が示すディレクトリを取得
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let idx = dirfd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let dir_path = match with_fd_table(pid, |t| t.get(idx).and_then(|fh| fh.dir_path.clone())) {
        Some(Some(p)) => p,
        _ => return EBADF,
    };

    // path を dir_path に対して解決する
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let full_path = if path.starts_with('/') {
        path
    } else {
        alloc::format!("{}/{}", dir_path.trim_end_matches('/'), path)
    };

    open_resolved_for_pid(pid, &normalize_path(&full_path), flags)
}

/// Newfstatat (fstatat) システムコール
///
/// AT_FDCWD(-100) の場合は stat() と同等。
pub fn newfstatat(dirfd: i64, path_ptr: u64, stat_ptr: u64, flags: u64) -> u64 {
    const AT_FDCWD: i64 = -100;
    const AT_EMPTY_PATH: u64 = 0x1000;

    // AT_EMPTY_PATH: path が空の場合は dirfd 自体を fstat する
    if (flags & AT_EMPTY_PATH) != 0 {
        if dirfd == AT_FDCWD {
            return stat(path_ptr, stat_ptr);
        }
        return fstat(dirfd as u64, stat_ptr);
    }

    if dirfd == AT_FDCWD {
        return stat(path_ptr, stat_ptr);
    }

    // dirfd 相対パスを解決して stat
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let idx = dirfd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let dir_path = match with_fd_table(pid, |t| t.get(idx).and_then(|fh| fh.dir_path.clone())) {
        Some(Some(p)) => p,
        _ => return EBADF,
    };
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let full = if path.starts_with('/') {
        normalize_path(&path)
    } else {
        normalize_path(&alloc::format!(
            "{}/{}",
            dir_path.trim_end_matches('/'),
            path
        ))
    };
    match metadata_rootfs_first(&full) {
        Some((mode, size)) => {
            const STAT_SIZE: u64 = 144;
            if !crate::syscall::validate_user_ptr(stat_ptr, STAT_SIZE) {
                return EFAULT;
            }
            write_stat_buf(stat_ptr, mode_for_stat(mode), size);
            SUCCESS
        }
        None => ENOENT,
    }
}

/// Faccessat システムコール
pub fn faccessat(dirfd: i64, path_ptr: u64, _mode: u64, _flags: u64) -> u64 {
    const AT_FDCWD: i64 = -100;
    if path_ptr == 0 {
        return EINVAL;
    }
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let resolved = if dirfd == AT_FDCWD || path.starts_with('/') {
        normalize_path(&path)
    } else {
        let pid = match current_process_id_raw() {
            Some(p) => p,
            None => return EBADF,
        };
        let idx = dirfd as usize;
        if idx >= PROCESS_MAX_FDS {
            return EBADF;
        }
        match with_fd_table(current_process_id_raw().unwrap_or(0), |t| {
            t.get(idx).and_then(|fh| fh.dir_path.clone())
        }) {
            Some(Some(d)) => {
                normalize_path(&alloc::format!("{}/{}", d.trim_end_matches('/'), path))
            }
            _ => return EBADF,
        }
    };
    if metadata_rootfs_first(&resolved).is_some() {
        SUCCESS
    } else {
        ENOENT
    }
}

/// statfs システムコール（最小実装）
///
/// Linux x86_64 の `struct statfs` (120 bytes) を埋めて返す。
pub fn statfs(path_ptr: u64, buf_ptr: u64) -> u64 {
    const STATFS_SIZE: u64 = 120;
    if path_ptr == 0 || buf_ptr == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, STATFS_SIZE) {
        return EFAULT;
    }

    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let path = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let resolved = resolve_path(pid, &path);
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_READ) {
        return errno;
    }
    if metadata_rootfs_first(&resolved).is_none() {
        return ENOENT;
    }

    // struct statfs {
    //   long f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    //   fsid_t f_fsid; long f_namelen, f_frsize, f_flags, f_spare[4];
    // }
    let mut buf = [0u8; STATFS_SIZE as usize];
    buf[0..8].copy_from_slice(&0xEF53u64.to_ne_bytes()); // ext2 magic
    buf[8..16].copy_from_slice(&4096u64.to_ne_bytes()); // f_bsize
    buf[64..72].copy_from_slice(&255u64.to_ne_bytes()); // f_namelen
    buf[72..80].copy_from_slice(&4096u64.to_ne_bytes()); // f_frsize
    crate::syscall::copy_to_user(buf_ptr, &buf)
        .map(|_| SUCCESS)
        .unwrap_or_else(|e| e)
}

/// readlinkat システムコール（最小実装）
///
/// `/proc/self/exe` と `/proc/self/cwd` のみをサポートする。
pub fn readlinkat(dirfd: i64, path_ptr: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    const AT_FDCWD: i64 = -100;
    if path_ptr == 0 || buf_ptr == 0 || buf_len == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }
    let raw = match read_cstring(path_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let path = if raw.starts_with('/') || dirfd == AT_FDCWD {
        normalize_path(&raw)
    } else {
        // 最小実装: dirfd 相対は未対応
        return EBADF;
    };

    let pid = match current_process_id_raw() {
        Some(p) => crate::task::ids::ProcessId::from_u64(p),
        None => return EBADF,
    };
    let target = if path == "/proc/self/exe" {
        match crate::task::with_process(pid, |p| {
            let exe = p.exe_path();
            if exe.is_empty() {
                String::from(p.name())
            } else {
                String::from(exe)
            }
        }) {
            Some(name) if name.starts_with('/') => name,
            Some(name) => alloc::format!("/{}", name),
            None => return ESRCH,
        }
    } else if path == "/proc/self/cwd" {
        match crate::task::with_process(pid, |p| String::from(p.cwd())) {
            Some(cwd) => cwd,
            None => return ESRCH,
        }
    } else {
        return ENOENT;
    };

    let bytes = target.as_bytes();
    let copy_len = core::cmp::min(bytes.len(), buf_len as usize);
    if let Err(errno) = crate::syscall::copy_to_user(buf_ptr, &bytes[..copy_len]) {
        return errno;
    }
    copy_len as u64
}

/// Getdents64 システムコール
///
/// struct linux_dirent64 形式でエントリをバッファに書き込む。
/// - d_ino (8), d_off (8), d_reclen (2), d_type (1), d_name (可変長, null終端)
/// - レコードは 8 バイトアラインメント
/// FD の `pos` をエントリインデックスとして使用する。
pub fn getdents64(fd: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    if buf_ptr == 0 || buf_len == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }
    if fd < FD_BASE as u64 {
        return EBADF;
    }
    let idx = fd as usize;
    if idx >= PROCESS_MAX_FDS {
        return EBADF;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };

    let (dir_path, start_pos) =
        match with_fd_table(pid, |t| t.get(idx).map(|fh| (fh.dir_path.clone(), fh.pos))) {
            Some(Some((Some(p), pos))) => (p, pos),
            _ => return EBADF,
        };

    if let Err(errno) = ensure_fs_path_access(&dir_path, PATH_LIST) {
        return errno;
    }

    let entries: Vec<(String, u8)> = match readdir_rootfs_first(&dir_path) {
        Some(e) => e
            .into_iter()
            .map(|name| {
                let child = normalize_path(&alloc::format!(
                    "{}/{}",
                    dir_path.trim_end_matches('/'),
                    name
                ));
                let dtype = match metadata_rootfs_first(&child) {
                    Some((mode, _)) if mode_is_directory(mode) => 4u8,
                    Some(_) => 8u8,
                    None => 0u8,
                };
                (name, dtype)
            })
            .collect(),
        None => return EINVAL,
    };

    let mut written: usize = 0;
    let mut new_pos = start_pos;

    // "." と ".." を先頭に追加
    let dot_entries: [(&str, u8); 2] = [(".", 4u8), ("..", 4u8)];
    let all_entries: Vec<(String, u8)> = {
        let mut v: Vec<(String, u8)> = dot_entries
            .iter()
            .map(|(n, t)| (String::from(*n), *t))
            .collect();
        for (name, dtype) in &entries {
            v.push((name.clone(), *dtype));
        }
        v
    };

    let mut out = alloc::vec![0u8; buf_len as usize];
    for (i, (name, dtype)) in all_entries.iter().enumerate().skip(start_pos) {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len() + 1;
        let raw_size = 8 + 8 + 2 + 1 + name_len;
        let reclen = (raw_size + 7) & !7usize;
        if written + reclen > buf_len as usize {
            break;
        }
        let buf = &mut out[written..written + reclen];
        buf.fill(0);
        buf[0..8].copy_from_slice(&((i as u64 + 1).to_ne_bytes()));
        let next_off = (i + 1) as u64;
        buf[8..16].copy_from_slice(&next_off.to_ne_bytes());
        buf[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        buf[18] = *dtype;
        buf[19..19 + name_bytes.len()].copy_from_slice(name_bytes);
        buf[19 + name_bytes.len()] = 0;
        written += reclen;
        new_pos = i + 1;
    }
    if written > 0 && crate::syscall::copy_to_user(buf_ptr, &out[..written]).is_err() {
        return EFAULT;
    }

    // FD の pos を更新する
    with_fd_table_mut(pid, |t| {
        if let Some(fh) = t.get_mut(idx) {
            fh.pos = new_pos;
        }
    });

    written as u64
}

pub fn file_open(path_ptr: u64, flags: u64) -> u64 {
    open(path_ptr, flags)
}

pub fn file_open_at(dirfd: i64, path_ptr: u64, flags: u64, mode: u64) -> u64 {
    openat(dirfd, path_ptr, flags, mode)
}

pub fn file_close(fd: u64) -> u64 {
    close(fd)
}

pub fn file_read(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    read(fd, buf_ptr, len)
}

pub fn file_write(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    write(fd, buf_ptr, len)
}

pub fn file_seek(fd: u64, offset: i64, whence: u64) -> u64 {
    seek(fd, offset, whence)
}

pub fn file_stat(path_ptr: u64, stat_ptr: u64) -> u64 {
    stat(path_ptr, stat_ptr)
}

pub fn file_stat_at(dirfd: i64, path_ptr: u64, stat_ptr: u64, flags: u64) -> u64 {
    newfstatat(dirfd, path_ptr, stat_ptr, flags)
}

pub fn file_fstat(fd: u64, stat_ptr: u64) -> u64 {
    fstat(fd, stat_ptr)
}

pub fn file_read_dir(fd: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    getdents64(fd, buf_ptr, buf_len)
}

pub fn file_create_dir(_path_ptr: u64, _mode: u64) -> u64 {
    mkdir(_path_ptr, _mode)
}

pub fn file_remove(path_ptr: u64) -> u64 {
    unlink(path_ptr)
}

pub fn file_rename(old_dirfd: i64, old_path_ptr: u64, new_dirfd: i64, new_path_ptr: u64) -> u64 {
    renameat(old_dirfd, old_path_ptr, new_dirfd, new_path_ptr)
}

pub fn file_sync(fd: u64) -> u64 {
    fsync(fd)
}
