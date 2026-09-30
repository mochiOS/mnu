//! ファイルシステム関連のシステムコール

use super::types::{
    EACCES, EAGAIN, EBADF, EEXIST, EFAULT, EFBIG, EINVAL, EIO, EISDIR, ENOENT, ENOSPC, ENOSYS,
    ENOTDIR, EOVERFLOW, EPIPE, EROFS, ESRCH, SUCCESS,
};
use crate::capability::path::{
    self, PathOwner, PATH_CREATE, PATH_DELETE, PATH_EXEC, PATH_LIST, PATH_READ, PATH_WRITE,
};
use crate::capability::Capability;
use crate::task::fd_table::{
    FdTable, FileHandle, FileHandleCap, OpenFile, FD_BASE, O_CLOEXEC, PROCESS_MAX_FDS,
};
use crate::vfs::{self, InodeId, MountId, Vnode, VnodeKind, DATA_FILESYSTEM_ID};
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

const MAX_IO_BYTES: usize = 128 * 1024 * 1024;
const READ_IO_CHUNK_BYTES: usize = 256 * 1024;
const WRITE_IO_CHUNK_BYTES: usize = 256 * 1024;
const MAX_PIPES: usize = 64;
const PIPE_BUFFER_CAP: usize = 64 * 1024;
const UNIX_EXECUTE: u32 = 1 << 31;

fn transferred_io_bytes(result: u64) -> u64 {
    (result <= MAX_IO_BYTES as u64)
        .then_some(result)
        .unwrap_or(0)
}

struct PipeState {
    data: Vec<u8>,
    readers: usize,
    writers: usize,
}

static PIPE_TABLE: crate::interrupt::spinlock::SpinLock<[Option<PipeState>; MAX_PIPES]> =
    crate::interrupt::spinlock::SpinLock::new([const { None }; MAX_PIPES]);

fn alloc_pipe_state() -> Option<usize> {
    let mut table = PIPE_TABLE.lock();
    for (index, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PipeState {
                data: Vec::new(),
                readers: 1,
                writers: 1,
            });
            return Some(index);
        }
    }
    None
}

pub fn close_pipe_endpoint_from_kernel(pipe_id: usize, write_end: bool) {
    let mut table = PIPE_TABLE.lock();
    let Some(slot) = table.get_mut(pipe_id) else {
        return;
    };
    let Some(pipe) = slot.as_mut() else {
        return;
    };
    if write_end {
        pipe.writers = pipe.writers.saturating_sub(1);
    } else {
        pipe.readers = pipe.readers.saturating_sub(1);
    }
    if pipe.readers == 0 && pipe.writers == 0 {
        *slot = None;
    }
}

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

fn open_file(
    pid_raw: u64,
    fd: usize,
) -> Option<alloc::sync::Arc<crate::interrupt::spinlock::SpinLock<OpenFile>>> {
    with_fd_table(pid_raw, |table| {
        table.get(fd).map(|handle| handle.open.clone())
    })
    .flatten()
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
        let path = read_cstring(path_ptr)?;
        if path.starts_with('/') {
            return Ok(normalize_path(&path));
        }
        let cwd =
            crate::task::with_process(crate::task::ids::ProcessId::from_u64(pid_raw), |process| {
                process.cwd().to_string()
            })
            .ok_or(EACCES)?;
        return Ok(resolve_relative_to_cwd(&cwd, &path));
    }

    let idx = dirfd as usize;
    if idx >= PROCESS_MAX_FDS {
        return Err(EBADF);
    }
    let dir_path = open_file(pid_raw, idx)
        .and_then(|open_file| {
            open_file
                .lock()
                .vnode
                .as_ref()
                .filter(|vnode| vnode.is_directory())
                .map(|vnode| vnode.path().to_string())
        })
        .ok_or(EBADF)?;
    let path = read_cstring(path_ptr)?;
    let full_path = if path.starts_with('/') {
        path
    } else {
        alloc::format!("{}/{}", dir_path.trim_end_matches('/'), path)
    };
    Ok(normalize_path(&full_path))
}

fn resolve_relative_to_cwd(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        normalize_path(path)
    } else {
        normalize_path(&alloc::format!("{}/{}", cwd.trim_end_matches('/'), path))
    }
}

pub(crate) fn ensure_fs_path_readable(path: &str) -> Result<(), u64> {
    ensure_fs_path_access(path, PATH_READ)
}

pub(crate) fn ensure_fs_path_executable_for_process(
    path: &str,
    pid: crate::task::ids::ProcessId,
) -> Result<(), u64> {
    let pid_raw = pid.as_u64();
    ensure_fs_capability_access_for_process(path, PATH_EXEC, pid_raw)?;
    ensure_unix_traversal_for_process(path, pid_raw)?;
    ensure_unix_mode_access_for_process(path, UNIX_EXECUTE, pid_raw)
}

fn ensure_fs_path_access(path: &str, needed_rights: u32) -> Result<(), u64> {
    let Some(pid_raw) = current_process_id_raw() else {
        return Err(EACCES);
    };
    ensure_fs_path_access_for_process(path, needed_rights, pid_raw)
}

fn ensure_fs_path_access_for_process(
    path: &str,
    needed_rights: u32,
    pid_raw: u64,
) -> Result<(), u64> {
    let identity_storage = identity_storage_path_allows(path, pid_raw);
    ensure_fs_capability_access_for_process(path, needed_rights, pid_raw)?;
    ensure_unix_traversal_for_process(path, pid_raw)?;
    if identity_storage {
        return Ok(());
    }
    if (needed_rights & (PATH_CREATE | PATH_DELETE)) != 0 {
        ensure_unix_parent_write_for_process(path, pid_raw)?;
        if (needed_rights & PATH_DELETE) != 0 {
            ensure_unix_sticky_delete_for_process(path, pid_raw)?;
        }
        Ok(())
    } else if metadata_rootfs_first(path).is_some() {
        ensure_unix_mode_access_for_process(path, needed_rights, pid_raw)
    } else {
        Ok(())
    }
}

fn ensure_fs_capability_access(path: &str, needed_rights: u32) -> Result<(), u64> {
    let Some(pid_raw) = current_process_id_raw() else {
        return Err(EACCES);
    };
    ensure_fs_capability_access_for_process(path, needed_rights, pid_raw)
}

fn ensure_fs_capability_access_for_process(
    path: &str,
    needed_rights: u32,
    pid_raw: u64,
) -> Result<(), u64> {
    if path::scoped_path_allows(pid_raw, path, needed_rights) {
        return Ok(());
    }
    if identity_storage_path_allows(path, pid_raw) {
        return Ok(());
    }
    if let Some(entry) = path::lookup_path(path) {
        if !path_owner_allows(entry.owner, pid_raw) {
            return Err(EACCES);
        }
        let missing_rights = needed_rights & !entry.rights.bits;
        if missing_rights != 0 {
            enforce_fs_capabilities_for_process(
                entry.read_capability,
                entry.write_capability,
                missing_rights,
                pid_raw,
            )?;
        }
    } else {
        enforce_fs_capabilities_for_process(
            Capability::FsReadAll,
            Capability::FsWriteAll,
            needed_rights,
            pid_raw,
        )?;
    }
    Ok(())
}

fn identity_storage_path_allows(path: &str, pid_raw: u64) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let Some(storage_root) = crate::config::kernel().policy_paths.identity_storage_root() else {
        return false;
    };
    let normalized = normalize_path(path);
    crate::task::with_process(crate::task::ids::ProcessId::from_u64(pid_raw), |process| {
        process.security_identity().is_some_and(|identity| {
            path_is_in_identity_storage(&normalized, storage_root, identity)
        })
    })
    .unwrap_or(false)
}

fn path_is_in_identity_storage(normalized: &str, storage_root: &str, identity: &str) -> bool {
    if identity.is_empty() || identity.as_bytes().contains(&b'/') {
        return false;
    }
    let Some(relative) = path_relative_to(normalized, storage_root) else {
        return false;
    };
    relative == identity
        || relative
            .strip_prefix(identity)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn path_relative_to<'a>(normalized: &'a str, root: &str) -> Option<&'a str> {
    if root == "/" {
        return normalized.strip_prefix('/');
    }
    normalized.strip_prefix(root)?.strip_prefix('/')
}

fn current_effective_ids() -> Option<(u32, u32)> {
    effective_ids_for_process(crate::syscall::security::current_process_id()?.as_u64())
}

fn effective_ids_for_process(pid_raw: u64) -> Option<(u32, u32)> {
    let pid = crate::task::ids::ProcessId::from_u64(pid_raw);
    crate::task::with_process(pid, |process| {
        let credentials = process.credentials();
        (credentials.effective_uid(), credentials.effective_gid())
    })
}

fn unix_mode_allows(mode: u16, owner: u32, group: u32, uid: u32, gid: u32, rights: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let shift = if uid == owner {
        6
    } else if gid == group {
        3
    } else {
        0
    };
    let granted = ((mode >> shift) & 0o7) as u32;
    let mut required = 0u32;
    if (rights & (PATH_READ | PATH_LIST)) != 0 {
        required |= 0o4;
    }
    if (rights & (PATH_WRITE | PATH_CREATE | PATH_DELETE)) != 0 {
        required |= 0o2;
    }
    if (rights & UNIX_EXECUTE) != 0 || ((rights & PATH_LIST) != 0 && mode_is_directory(mode)) {
        required |= 0o1;
    }
    (granted & required) == required
}

fn ensure_unix_mode_access(path: &str, rights: u32) -> Result<(), u64> {
    let Some(pid_raw) = current_process_id_raw() else {
        return Err(EACCES);
    };
    ensure_unix_mode_access_for_process(path, rights, pid_raw)
}

fn ensure_unix_mode_access_for_process(path: &str, rights: u32, pid_raw: u64) -> Result<(), u64> {
    let Some((mode, _, owner, group)) = metadata_rootfs_first(path) else {
        return Ok(());
    };
    let Some((uid, gid)) = effective_ids_for_process(pid_raw) else {
        return Err(EACCES);
    };
    if unix_mode_allows(mode, owner, group, uid, gid, rights) {
        Ok(())
    } else {
        Err(EACCES)
    }
}

fn ensure_unix_traversal(path: &str) -> Result<(), u64> {
    let Some(pid_raw) = current_process_id_raw() else {
        return Err(EACCES);
    };
    ensure_unix_traversal_for_process(path, pid_raw)
}

fn ensure_unix_traversal_for_process(path: &str, pid_raw: u64) -> Result<(), u64> {
    let normalized = normalize_path(path);
    if normalized != "/" {
        ensure_unix_mode_access_for_process("/", UNIX_EXECUTE, pid_raw)?;
    }
    let mut parent = String::from("/");
    let mut components = normalized.trim_start_matches('/').split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        if parent.len() > 1 {
            parent.push('/');
        }
        parent.push_str(component);
        ensure_unix_mode_access_for_process(&parent, UNIX_EXECUTE, pid_raw)?;
    }
    Ok(())
}

fn ensure_unix_parent_write_for_process(path: &str, pid_raw: u64) -> Result<(), u64> {
    let normalized = normalize_path(path);
    let parent =
        normalized.rsplit_once('/').map_or(
            "/",
            |(parent, _)| if parent.is_empty() { "/" } else { parent },
        );
    ensure_unix_mode_access_for_process(parent, PATH_WRITE | UNIX_EXECUTE, pid_raw)
}

fn sticky_directory_allows_delete(
    parent_mode: u16,
    parent_owner: u32,
    target_owner: u32,
    uid: u32,
) -> bool {
    (parent_mode & 0o1000) == 0 || uid == 0 || uid == parent_owner || uid == target_owner
}

fn ensure_unix_sticky_delete_for_process(path: &str, pid_raw: u64) -> Result<(), u64> {
    let normalized = normalize_path(path);
    let parent =
        normalized.rsplit_once('/').map_or(
            "/",
            |(parent, _)| if parent.is_empty() { "/" } else { parent },
        );
    let Some((parent_mode, _, parent_owner, _)) = metadata_rootfs_first(parent) else {
        return Ok(());
    };
    let Some((_, _, target_owner, _)) = metadata_rootfs_first(&normalized) else {
        return Ok(());
    };
    let Some((uid, _)) = effective_ids_for_process(pid_raw) else {
        return Err(EACCES);
    };
    if sticky_directory_allows_delete(parent_mode, parent_owner, target_owner, uid) {
        Ok(())
    } else {
        Err(EACCES)
    }
}

fn path_owner_allows(owner: PathOwner, pid_raw: u64) -> bool {
    match owner {
        PathOwner::Any => true,
        PathOwner::System => false,
        PathOwner::Service(owner_pid) | PathOwner::Application(owner_pid) => owner_pid == pid_raw,
        PathOwner::User(owner_uid) => {
            crate::task::with_process(crate::task::ids::ProcessId::from_u64(pid_raw), |process| {
                u64::from(process.credentials().effective_uid()) == owner_uid
            })
            .is_some_and(|matches| matches)
        }
    }
}

fn process_has_cap(pid_raw: u64, cap: Capability) -> bool {
    crate::syscall::security::process_has_any_capability(
        crate::task::ids::ProcessId::from_u64(pid_raw),
        &[cap],
    )
}

fn capability_requirement_satisfied(
    required: Capability,
    broad: Capability,
    has_required: bool,
    has_broad: bool,
) -> bool {
    has_required || (required != broad && has_broad)
}

fn enforce_required_capability(
    required: Capability,
    broad: Capability,
    pid_raw: u64,
) -> Result<(), u64> {
    let has_required = process_has_cap(pid_raw, required);
    let has_broad = process_has_cap(pid_raw, broad);
    if capability_requirement_satisfied(required, broad, has_required, has_broad) {
        Ok(())
    } else {
        Err(EACCES)
    }
}

fn enforce_fs_capabilities_for_process(
    read_capability: Capability,
    write_capability: Capability,
    needed_rights: u32,
    pid_raw: u64,
) -> Result<(), u64> {
    if needed_rights & (PATH_READ | PATH_LIST | PATH_EXEC) != 0 {
        enforce_required_capability(read_capability, Capability::FsReadAll, pid_raw)?;
    }
    if (needed_rights & (PATH_WRITE | PATH_CREATE | PATH_DELETE)) != 0 {
        enforce_required_capability(write_capability, Capability::FsWriteAll, pid_raw)?;
    }
    Ok(())
}

fn open_required_rights(path: &str, flags: u64, is_dir: bool) -> u32 {
    const O_ACCMODE: u64 = 0o3;
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;
    let _ = path;
    let mut rights = if is_dir { PATH_LIST } else { PATH_READ };
    let acc = flags & O_ACCMODE;
    if acc == O_WRONLY || acc == O_RDWR || (flags & (O_TRUNC | O_APPEND)) != 0 {
        rights |= PATH_WRITE;
    }
    rights
}

fn open_path_required_rights(flags: u64, is_dir: bool, exists: bool) -> u32 {
    if !exists && (flags & O_CREAT) != 0 {
        PATH_CREATE
    } else {
        open_required_rights("", flags, is_dir)
    }
}

fn access_mode_rights(mode: u64) -> Option<u32> {
    const X_OK: u64 = 1;
    const W_OK: u64 = 2;
    const R_OK: u64 = 4;
    if mode & !(R_OK | W_OK | X_OK) != 0 {
        return None;
    }
    let mut rights = 0u32;
    if (mode & R_OK) != 0 {
        rights |= PATH_READ;
    }
    if (mode & W_OK) != 0 {
        rights |= PATH_WRITE;
    }
    if (mode & X_OK) != 0 {
        rights |= PATH_EXEC | UNIX_EXECUTE;
    }
    Some(rights)
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
    out
}

#[inline]
pub(crate) fn metadata_rootfs_first(path: &str) -> Option<(u16, u64, u32, u32)> {
    crate::performance::record_vfs_metadata_query();
    // initfs is one authenticated boot generation. If it contains a path, its
    // metadata and contents must shadow a mounted filesystem from another
    // generation. Paths absent from initfs continue to use the runtime disk.
    if let Some((mode, size)) = crate::init::fs::initfs_file_metadata(path) {
        return Some((mode, size, 0, 0));
    }
    crate::cext::fs::file_metadata(path)
        .or_else(|| crate::init::fs::file_metadata(path).map(|(mode, size)| (mode, size, 0, 0)))
}

#[inline]
pub(crate) fn readdir_rootfs_first(path: &str) -> Option<Vec<String>> {
    crate::cext::fs::readdir_path(path).or_else(|| crate::init::fs::readdir_path(path))
}

#[inline]
pub(crate) fn read_file_range_rootfs_first(
    path: &str,
    offset: u64,
    buf: &mut [u8],
) -> Option<usize> {
    crate::performance::record_vfs_read_range();
    if let Some(read) = crate::init::fs::read_range_initfs(path, offset, buf) {
        return Some(read);
    }
    crate::cext::fs::read_range(path, offset, buf)
        .or_else(|| crate::init::fs::read_range_rootfs(path, offset, buf))
        .or_else(|| crate::init::fs::read_range(path, offset, buf))
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
    #[cfg(feature = "performance-instrumentation")]
    let start = crate::performance::timestamp();

    let resolved = if path.starts_with('/') {
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
    };

    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_latency(crate::performance::LatencyMetric::VfsPathLookup, start);

    resolved
}

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
#[cfg(test)]
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_NONBLOCK: u64 = 0x4000;
const USERSPACE_DATA_ROUTING: bool = false;

fn errno_from_cext(rc: i32) -> u64 {
    match rc {
        -2 => ENOENT,
        -5 => EIO,
        -17 => EEXIST,
        -20 => ENOTDIR,
        -21 => EISDIR,
        -22 => EINVAL,
        -27 => EFBIG,
        -28 => ENOSPC,
        -30 => EROFS,
        -38 => ENOSYS,
        -39 => (-39i64) as u64,
        -75 => EOVERFLOW,
        _ => EIO,
    }
}

fn userspace_mount(path: &str) -> Option<vfs::ResolvedMount> {
    if !USERSPACE_DATA_ROUTING {
        return None;
    }
    vfs::resolve(path).filter(|mount| mount.filesystem_id == DATA_FILESYSTEM_ID)
}

fn vnode_kind_from_protocol(kind: u32) -> VnodeKind {
    match kind {
        mochios_filesystem_protocol::NODE_TYPE_DIRECTORY => VnodeKind::Directory,
        mochios_filesystem_protocol::NODE_TYPE_SYMLINK => VnodeKind::Symlink,
        mochios_filesystem_protocol::NODE_TYPE_REGULAR => VnodeKind::Regular,
        _ => VnodeKind::Other,
    }
}

fn open_userspace_for_pid(
    owner_pid: u64,
    path: &str,
    flags: u64,
    mode: u64,
    mount: vfs::ResolvedMount,
) -> u64 {
    let mut node = match vfs::userspace::lookup(mount.mount_id.0, &mount.path) {
        Ok(node) => Some(node),
        Err(errno) if errno == ENOENT => None,
        Err(errno) => return errno,
    };
    let existed_before = node.is_some();
    let is_dir =
        node.is_some_and(|node| node.kind == mochios_filesystem_protocol::NODE_TYPE_DIRECTORY);
    let acc = flags & O_ACCMODE;
    if is_dir && acc != 0 {
        return EISDIR;
    }
    if let Err(errno) = ensure_fs_path_access(
        path,
        open_path_required_rights(flags, is_dir, existed_before),
    ) {
        return errno;
    }
    if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 && existed_before {
        return EEXIST;
    }
    if node.is_none() {
        if (flags & O_CREAT) == 0 {
            return ENOENT;
        }
        node = match vfs::userspace::create(
            mount.mount_id.0,
            &mount.path,
            (mode & 0o777) as u32,
            mochios_filesystem_protocol::NODE_TYPE_REGULAR,
        ) {
            Ok(node) => Some(node),
            Err(errno) => return errno,
        };
    }
    let Some(node) = node else {
        return EIO;
    };
    let kind = vnode_kind_from_protocol(node.kind);
    let open_id = if kind == VnodeKind::Directory {
        0
    } else {
        match u32::try_from(flags)
            .map_err(|_| EINVAL)
            .and_then(|flags| vfs::userspace::open(mount.mount_id.0, node.node_id, flags))
        {
            Ok(open_id) => open_id,
            Err(errno) => return errno,
        }
    };
    if (flags & O_TRUNC) != 0 && kind == VnodeKind::Regular {
        if let Err(errno) = vfs::userspace::truncate(mount.mount_id.0, open_id, 0) {
            let _ = vfs::userspace::close(mount.mount_id.0, open_id);
            return errno;
        }
    }

    let cloexec = (flags & O_CLOEXEC) != 0;
    let cap = if kind == VnodeKind::Directory {
        FileHandleCap::READDIR
            .union(FileHandleCap::STAT)
            .union(FileHandleCap::SEEK)
            .union(FileHandleCap::CLOSE)
    } else {
        FileHandleCap::from_open_flags(flags).union(FileHandleCap::CLOSE)
    };
    let vnode = Vnode::userspace_handle(
        mount.mount_id,
        InodeId(node.node_id),
        path.to_string(),
        open_id,
        kind,
    );
    let handle = alloc::boxed::Box::new(FileHandle::new(
        OpenFile {
            data: alloc::boxed::Box::new([]),
            pos: 0,
            vnode: Some(Arc::new(vnode)),
            is_remote: false,
            fd_remote: 0,
            pipe_id: None,
            pipe_write: false,
            open_flags: flags,
        },
        cap,
    ));
    match with_fd_table_mut(owner_pid, |table| table.alloc(handle, cloexec)) {
        Some(Some(fd)) => fd as u64,
        _ => ENOSYS,
    }
}

fn open_resolved_for_pid(owner_pid: u64, path: &str, flags: u64, mode: u64) -> u64 {
    if let Some(mount) = userspace_mount(path) {
        return open_userspace_for_pid(owner_pid, path, flags, mode, mount);
    }
    let mut metadata = metadata_rootfs_first(path);
    let mut is_dir = metadata
        .map(|(mode, _, _, _)| mode_is_directory(mode))
        .unwrap_or_else(|| crate::cext::fs::is_directory(path));

    let acc = flags & O_ACCMODE;
    if is_dir && acc != 0 {
        return EISDIR;
    }

    let existed_before = metadata.is_some();
    let required_rights = open_path_required_rights(flags, is_dir, existed_before);
    if let Err(errno) = ensure_fs_path_access(path, required_rights) {
        return errno;
    }
    if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 && existed_before {
        return EEXIST;
    }
    let mut exists = existed_before;
    if !exists {
        if (flags & O_CREAT) != 0 {
            let Some((uid, gid)) = current_effective_ids() else {
                return EACCES;
            };
            let rc = crate::cext::fs::create(path, (mode & 0o777) as u32, uid, gid);
            if rc != 0 {
                return (-rc as i64) as u64;
            }
            metadata = metadata_rootfs_first(path);
            is_dir = metadata
                .map(|(mode, _, _, _)| mode_is_directory(mode))
                .unwrap_or_else(|| crate::cext::fs::is_directory(path));
            exists = metadata.is_some();
            if !exists {
                return ENOENT;
            }
        } else {
            return ENOENT;
        }
    }
    if (flags & O_TRUNC) != 0 {
        let rc = crate::cext::fs::truncate(path, 0);
        if rc != 0 {
            return errno_from_cext(rc);
        }
    }

    let cloexec = (flags & O_CLOEXEC) != 0;
    let cap = if is_dir {
        FileHandleCap::READDIR
            .union(FileHandleCap::STAT)
            .union(FileHandleCap::SEEK)
            .union(FileHandleCap::CLOSE)
    } else {
        FileHandleCap::from_open_flags(flags).union(FileHandleCap::CLOSE)
    };
    let kind = if is_dir {
        VnodeKind::Directory
    } else {
        VnodeKind::Regular
    };
    let mount_id = vfs::resolve(path)
        .map(|mount| mount.mount_id)
        .unwrap_or(MountId(1));
    let vnode = if crate::init::fs::initfs_file_metadata(path).is_none() {
        crate::cext::fs::open_handle(path)
            .map(|handle| Vnode::cext_handle(mount_id, path.to_string(), handle, kind))
            .unwrap_or_else(|_| Vnode::legacy_path_on(mount_id, path.to_string(), kind))
    } else {
        Vnode::legacy_path_on(mount_id, path.to_string(), kind)
    };
    let handle = alloc::boxed::Box::new(FileHandle::new(
        OpenFile {
            data: alloc::boxed::Box::new([]),
            pos: 0,
            vnode: Some(Arc::new(vnode)),
            is_remote: false,
            fd_remote: 0,
            pipe_id: None,
            pipe_write: false,
            open_flags: flags,
        },
        cap,
    ));

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
    open_resolved_for_pid(owner_pid, &path, flags, 0o644)
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

    let Some(open_file) = open_file(pid, idx) else {
        return EBADF;
    };
    let result = (|| {
        let mut open = open_file.lock();
        let file_len = if let Some(vnode) = open.vnode.as_ref() {
            if let Some((node_id, open_id)) = vnode.userspace_handle_ids() {
                let node = vfs::userspace::stat(vnode.inode.mount_id.0, node_id, open_id)?;
                usize::try_from(node.size).map_err(|_| EOVERFLOW)?
            } else {
                vnode
                    .cext_handle_id()
                    .and_then(crate::cext::fs::handle_metadata)
                    .or_else(|| metadata_rootfs_first(vnode.path()))
                    .map(|(_, size, _, _)| size as usize)
                    .unwrap_or(open.data.len())
            }
        } else {
            open.data.len()
        };
        let new_pos = match whence {
            0 => offset,
            1 => open.pos as i64 + offset,
            2 => file_len as i64 + offset,
            _ => return Err(EINVAL),
        };
        if new_pos < 0 {
            return Err(EINVAL);
        }
        let new_pos = usize::try_from(new_pos).map_err(|_| EINVAL)?;
        open.pos = new_pos;
        Ok(open.pos as u64)
    })();
    match result {
        Ok(pos) => pos,
        Err(e) => e,
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
fn write_stat_buf(stat_ptr: u64, mode: u32, size: u64, uid: u32, gid: u32) {
    const STAT_SIZE: usize = 144;
    let blocks = size.div_ceil(512);
    let mut buf = [0u8; STAT_SIZE];
    buf[0..8].copy_from_slice(&1u64.to_ne_bytes());
    buf[8..16].copy_from_slice(&1u64.to_ne_bytes());
    buf[16..24].copy_from_slice(&1u64.to_ne_bytes());
    buf[24..28].copy_from_slice(&mode.to_ne_bytes());
    buf[28..32].copy_from_slice(&uid.to_ne_bytes());
    buf[32..36].copy_from_slice(&gid.to_ne_bytes());
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
        write_stat_buf(stat_ptr, 0x2000 | 0o666, 0, 0, 0);
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
            let open = fh.open.lock();
            let metadata = if let Some(vnode) = open.vnode.as_ref() {
                if let Some((node_id, open_id)) = vnode.userspace_handle_ids() {
                    let node = vfs::userspace::stat(vnode.inode.mount_id.0, node_id, open_id)?;
                    Some((node.mode as u16, node.size, 0, 0))
                } else {
                    vnode
                        .cext_handle_id()
                        .and_then(crate::cext::fs::handle_metadata)
                        .or_else(|| metadata_rootfs_first(vnode.path()))
                }
            } else {
                None
            };
            let size = metadata
                .map(|(_, size, _, _)| size)
                .unwrap_or(open.data.len() as u64);
            let mode = metadata.map_or_else(
                || {
                    if open
                        .vnode
                        .as_ref()
                        .is_some_and(|vnode| vnode.is_directory())
                    {
                        0x4000u32 | 0o755
                    } else {
                        0x8000u32 | 0o644
                    }
                },
                |(mode, _, _, _)| mode_for_stat(mode),
            );
            let (uid, gid) = metadata.map_or((0, 0), |(_, _, uid, gid)| (uid, gid));
            Ok::<_, u64>((size, mode, uid, gid))
        })
    });
    let (size, mode, uid, gid) = match file_info {
        Some(Some(Ok(v))) => v,
        Some(Some(Err(errno))) => return errno,
        _ => return EBADF,
    };
    write_stat_buf(stat_ptr, mode, size, uid, gid);
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
    if let Some(mount) = userspace_mount(&resolved) {
        return match vfs::userspace::lookup(mount.mount_id.0, &mount.path) {
            Ok(node) => {
                write_stat_buf(stat_ptr, node.mode, node.size, 0, 0);
                SUCCESS
            }
            Err(errno) => errno,
        };
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, size, uid, gid)) => {
            write_stat_buf(stat_ptr, mode_for_stat(mode), size, uid, gid);
            SUCCESS
        }
        None => ENOENT,
    }
}

/// Mkdirシステムコール
pub fn mkdir(path_ptr: u64, mode: u64) -> u64 {
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
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_CREATE) {
        return errno;
    }
    const S_IFDIR: u32 = 0x4000;
    let Some((uid, gid)) = current_effective_ids() else {
        return EACCES;
    };
    let rc = crate::cext::fs::create(&resolved, S_IFDIR | ((mode as u32) & 0o777), uid, gid);
    if rc != 0 {
        return errno_from_cext(rc);
    }
    SUCCESS
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
        Some((mode, _, _, _)) if mode_is_directory(mode) => {}
        Some(_) => return ENOTDIR,
        None => return ENOENT,
    }
    let rc = crate::cext::fs::remove(&resolved, true);
    if rc != 0 {
        return errno_from_cext(rc);
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

    let Some(open_file) = open_file(pid, idx) else {
        return EBADF;
    };
    let mut open = open_file.lock();
    let Some(vnode) = open
        .vnode
        .as_ref()
        .filter(|vnode| vnode.is_directory())
        .cloned()
    else {
        return EBADF;
    };
    let dir_path = vnode.path().to_string();

    if let Err(errno) = ensure_fs_path_access(&dir_path, PATH_LIST) {
        return errno;
    }

    if let Some((node_id, _)) = vnode.userspace_handle_ids() {
        let max_output = usize::try_from(buf_len)
            .unwrap_or(usize::MAX)
            .min(mochios_filesystem_protocol::MAX_IO_LEN);
        let mut output = Vec::new();
        let mut cursor = open.pos as u64;
        while output.len() < max_output {
            let batch = match vfs::userspace::read_dir(
                vnode.inode.mount_id.0,
                node_id,
                cursor,
                mochios_filesystem_protocol::DIRENT_HEADER_LEN
                    + mochios_filesystem_protocol::MAX_NAME_LEN,
            ) {
                Ok(batch) => batch,
                Err(errno) => return errno,
            };
            if batch.bytes.is_empty() {
                break;
            }
            let mut input = batch.bytes.as_slice();
            let mut consumed_any = false;
            while !input.is_empty() {
                let (entry, name, consumed) =
                    match mochios_filesystem_protocol::decode_dir_entry(input) {
                        Ok(entry) => entry,
                        Err(_) => return EIO,
                    };
                let record_len = (19usize + name.len() + 1).next_multiple_of(8);
                if output.len().saturating_add(record_len) > max_output {
                    break;
                }
                let start = output.len();
                output.resize(start + record_len, 0);
                output[start..start + 8].copy_from_slice(&entry.node_id.to_ne_bytes());
                let next_cursor = cursor.saturating_add(1);
                output[start + 8..start + 16].copy_from_slice(&next_cursor.to_ne_bytes());
                output[start + 16..start + 18].copy_from_slice(&(record_len as u16).to_ne_bytes());
                output[start + 18] = protocol_kind_to_dirent(entry.kind);
                output[start + 19..start + 19 + name.len()].copy_from_slice(name);
                cursor = next_cursor;
                consumed_any = true;
                input = &input[consumed..];
            }
            if !consumed_any {
                if output.is_empty() {
                    return EINVAL;
                }
                break;
            }
            if !input.is_empty() {
                break;
            }
        }
        if crate::syscall::copy_to_user(buf_ptr, &output).is_err() {
            return EFAULT;
        }
        open.pos = cursor as usize;
        return output.len() as u64;
    }
    drop(open);

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

fn protocol_kind_to_dirent(kind: u32) -> u8 {
    match kind {
        mochios_filesystem_protocol::NODE_TYPE_DIRECTORY => 4,
        mochios_filesystem_protocol::NODE_TYPE_REGULAR => 8,
        mochios_filesystem_protocol::NODE_TYPE_SYMLINK => 10,
        _ => 0,
    }
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
    if let Err(errno) = ensure_fs_capability_access(&resolved, PATH_LIST) {
        return errno;
    }
    if let Err(errno) = ensure_unix_traversal(&resolved) {
        return errno;
    }
    if let Err(errno) = ensure_unix_mode_access(&resolved, UNIX_EXECUTE) {
        return errno;
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, _, _, _)) => {
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
    let result = read_impl(fd, buf_ptr, len);
    crate::performance::record_vfs_read(len, transferred_io_bytes(result));
    result
}

fn read_impl(fd: u64, buf_ptr: u64, len: u64) -> u64 {
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
    let Some(open_file) = open_file(pid, idx) else {
        return EBADF;
    };
    let (pipe_id, open_flags) = {
        let open = open_file.lock();
        (open.pipe_id, open.open_flags)
    };
    if let Some(pipe_id) = pipe_id {
        return read_pipe(pipe_id, open_flags, buf_ptr, len);
    }

    let to_copy = match usize::try_from(len) {
        Ok(v) => v.min(MAX_IO_BYTES),
        Err(_) => MAX_IO_BYTES,
    };
    let mut written = 0usize;
    let mut tmp = alloc::vec![0u8; core::cmp::min(READ_IO_CHUNK_BYTES, to_copy)];
    crate::performance::record_vfs_temporary_buffer(tmp.len());

    while written < to_copy {
        let chunk_len = core::cmp::min(READ_IO_CHUNK_BYTES, to_copy - written)
            .min(mochios_filesystem_protocol::MAX_IO_LEN);
        let read_len = {
            let (vnode, pos) = {
                let open = open_file.lock();
                (open.vnode.clone(), open.pos)
            };
            if let Some(vnode) = vnode {
                let read = if let Some((_, open_id)) = vnode.userspace_handle_ids() {
                    match vfs::userspace::read(
                        vnode.inode.mount_id.0,
                        open_id,
                        pos as u64,
                        &mut tmp[..chunk_len],
                    ) {
                        Ok(read) => read,
                        Err(errno) => return errno,
                    }
                } else if let Some(handle) = vnode.cext_handle_id() {
                    match crate::cext::fs::read_handle(handle, pos as u64, &mut tmp[..chunk_len]) {
                        Ok(read) => read,
                        Err(_) => return EIO,
                    }
                } else {
                    match read_file_range_rootfs_first(
                        vnode.path(),
                        pos as u64,
                        &mut tmp[..chunk_len],
                    ) {
                        Some(read) => read,
                        None => return EIO,
                    }
                };
                let mut open = open_file.lock();
                if open.pos != pos {
                    continue;
                }
                open.pos = match open.pos.checked_add(read) {
                    Some(position) => position,
                    None => return EINVAL,
                };
                read
            } else {
                let mut open = open_file.lock();
                let avail = open.data.len().saturating_sub(open.pos);
                let take = core::cmp::min(avail, chunk_len);
                if take == 0 {
                    return written as u64;
                }
                tmp[..take].copy_from_slice(&open.data[open.pos..open.pos + take]);
                open.pos += take;
                take
            }
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

fn read_pipe(pipe_id: usize, open_flags: u64, buf_ptr: u64, len: u64) -> u64 {
    let target_len = match usize::try_from(len) {
        Ok(v) => v.min(MAX_IO_BYTES),
        Err(_) => MAX_IO_BYTES,
    };
    loop {
        let chunk = {
            let table = PIPE_TABLE.lock();
            let Some(Some(pipe)) = table.get(pipe_id) else {
                return EBADF;
            };
            if pipe.data.is_empty() {
                if pipe.writers == 0 {
                    return 0;
                }
                if (open_flags & O_NONBLOCK) != 0 {
                    return EAGAIN;
                }
                None
            } else {
                let take = core::cmp::min(pipe.data.len(), target_len);
                Some(pipe.data[..take].to_vec())
            }
        };
        let Some(chunk) = chunk else {
            crate::task::yield_now();
            continue;
        };
        crate::performance::record_vfs_temporary_buffer(chunk.len());
        if crate::syscall::copy_to_user(buf_ptr, &chunk).is_err() {
            return EFAULT;
        }
        let mut table = PIPE_TABLE.lock();
        let Some(Some(pipe)) = table.get_mut(pipe_id) else {
            return EBADF;
        };
        pipe.data.drain(0..chunk.len());
        return chunk.len() as u64;
    }
}

/// Write: 開かれたファイルへデータを書き込む
pub fn write(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    let result = write_impl(fd, buf_ptr, len);
    crate::performance::record_vfs_write(len, transferred_io_bytes(result));
    result
}

fn write_impl(fd: u64, buf_ptr: u64, len: u64) -> u64 {
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
    let Some(open_file) = open_file(pid, idx) else {
        return EBADF;
    };
    let pipe_id = {
        let open = open_file.lock();
        open.pipe_id
    };
    if let Some(pipe_id) = pipe_id {
        return write_pipe(pipe_id, buf_ptr, len);
    }

    let Ok(len_usize) = usize::try_from(len) else {
        return EINVAL;
    };
    if len_usize > MAX_IO_BYTES {
        return ENOSPC;
    }

    let (mut start_pos, vnode, open_flags) = {
        let open = open_file.lock();
        (open.pos, open.vnode.clone(), open.open_flags)
    };
    if (open_flags & O_APPEND) != 0 {
        let Some(vnode) = vnode.as_ref() else {
            return EINVAL;
        };
        let size = if let Some((node_id, open_id)) = vnode.userspace_handle_ids() {
            vfs::userspace::stat(vnode.inode.mount_id.0, node_id, open_id)
                .ok()
                .map(|node| node.size)
        } else {
            vnode
                .cext_handle_id()
                .and_then(crate::cext::fs::handle_metadata)
                .or_else(|| crate::cext::fs::file_metadata(vnode.path()))
                .map(|(_, size, _, _)| size)
        };
        start_pos = match size.and_then(|size| usize::try_from(size).ok()) {
            Some(size) => size,
            None => return EIO,
        };
    }
    let mut written = 0usize;
    let mut tmp = alloc::vec![0u8; core::cmp::min(WRITE_IO_CHUNK_BYTES, len_usize)];
    crate::performance::record_vfs_temporary_buffer(tmp.len());

    while written < len_usize {
        let chunk_len = core::cmp::min(WRITE_IO_CHUNK_BYTES, len_usize - written)
            .min(mochios_filesystem_protocol::MAX_IO_LEN);
        if let Err(errno) =
            crate::syscall::copy_from_user(buf_ptr + written as u64, &mut tmp[..chunk_len])
        {
            return errno;
        }

        if let Some(vnode) = vnode.as_ref() {
            crate::performance::record_vfs_write_range();
            let write_offset = match start_pos.checked_add(written) {
                Some(value) => value as u64,
                None => return if written == 0 { EFBIG } else { written as u64 },
            };
            let result: Result<usize, u64> =
                if let Some((_, open_id)) = vnode.userspace_handle_ids() {
                    vfs::userspace::write(
                        vnode.inode.mount_id.0,
                        open_id,
                        write_offset,
                        &tmp[..chunk_len],
                    )
                } else if let Some(handle) = vnode.cext_handle_id() {
                    crate::cext::fs::write_handle(handle, write_offset, &tmp[..chunk_len])
                        .map_err(errno_from_cext)
                } else {
                    crate::cext::fs::write_all(vnode.path(), write_offset, &tmp[..chunk_len])
                        .map_err(errno_from_cext)
                };
            match result {
                Ok(0) => return written as u64,
                Ok(wrote_chunk) => {
                    let end = match start_pos.checked_add(written + wrote_chunk) {
                        Some(value) => value,
                        None => return if written == 0 { EFBIG } else { written as u64 },
                    };
                    {
                        let mut open = open_file.lock();
                        if (open.open_flags & O_APPEND) != 0 || open.pos == start_pos + written {
                            open.pos = end;
                        }
                    }
                    written += wrote_chunk;
                    if wrote_chunk != chunk_len {
                        return written as u64;
                    }
                    continue;
                }
                Err(errno) => {
                    return if written == 0 { errno } else { written as u64 };
                }
            }
        }

        let wrote = (|| {
            let mut open = open_file.lock();
            let end = start_pos.checked_add(written + chunk_len).ok_or(EINVAL)?;
            let mut data = open.data.to_vec();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start_pos + written..end].copy_from_slice(&tmp[..chunk_len]);
            open.data = data.into_boxed_slice();
            open.pos = end;
            Ok::<(), u64>(())
        })();
        match wrote {
            Ok(()) => {}
            Err(errno) => return errno,
        }

        written += chunk_len;
    }

    written as u64
}

fn write_pipe(pipe_id: usize, buf_ptr: u64, len: u64) -> u64 {
    let Ok(len_usize) = usize::try_from(len) else {
        return EINVAL;
    };
    if len_usize > PIPE_BUFFER_CAP {
        return EAGAIN;
    }
    let mut tmp = alloc::vec![0u8; len_usize];
    crate::performance::record_vfs_temporary_buffer(tmp.len());
    if let Err(errno) = crate::syscall::copy_from_user(buf_ptr, &mut tmp) {
        return errno;
    }
    let mut table = PIPE_TABLE.lock();
    let Some(Some(pipe)) = table.get_mut(pipe_id) else {
        return EBADF;
    };
    if pipe.readers == 0 {
        return EPIPE;
    }
    if pipe.data.len().saturating_add(tmp.len()) > PIPE_BUFFER_CAP {
        return EAGAIN;
    }
    pipe.data.extend_from_slice(&tmp);
    len
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
        F_GETFL => match open_file(pid, idx) {
            Some(open_file) => open_file.lock().open_flags,
            None => EBADF,
        },
        F_SETFL => {
            let Some(open_file) = open_file(pid, idx) else {
                return EBADF;
            };
            let mut open = open_file.lock();
            open.open_flags = (open.open_flags & O_ACCMODE) | (arg & !O_ACCMODE);
            SUCCESS
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
    let Some(vnode) = open_file(pid, idx).and_then(|open_file| open_file.lock().vnode.clone())
    else {
        return EBADF;
    };
    if vnode.is_directory() {
        return SUCCESS;
    }
    if vnode.userspace_handle_ids().is_some() {
        match vfs::userspace::sync(vnode.inode.mount_id.0) {
            Ok(()) => SUCCESS,
            Err(errno) => errno,
        }
    } else {
        let rc = crate::cext::fs::sync();
        if rc == 0 {
            SUCCESS
        } else {
            errno_from_cext(rc)
        }
    }
}

pub fn fdatasync(fd: u64) -> u64 {
    // The ext2 cext currently has no deferred metadata cache, so its sync
    // operation is also the ordering barrier required for data-only sync.
    fsync(fd)
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
    if let Err(errno) = ensure_fs_path_access(&path, PATH_WRITE) {
        return errno;
    }
    if let Some(mount) = userspace_mount(&path) {
        let node = match vfs::userspace::lookup(mount.mount_id.0, &mount.path) {
            Ok(node) => node,
            Err(errno) => return errno,
        };
        if node.kind == mochios_filesystem_protocol::NODE_TYPE_DIRECTORY {
            return EISDIR;
        }
        let open_id = match vfs::userspace::open(mount.mount_id.0, node.node_id, O_WRONLY as u32) {
            Ok(open_id) => open_id,
            Err(errno) => return errno,
        };
        let result = vfs::userspace::truncate(mount.mount_id.0, open_id, len);
        let close_result = vfs::userspace::close(mount.mount_id.0, open_id);
        return match result.and(close_result) {
            Ok(()) => SUCCESS,
            Err(errno) => errno,
        };
    }
    match metadata_rootfs_first(&path) {
        Some((mode, _, _, _)) if mode_is_directory(mode) => return EISDIR,
        Some(_) => {}
        None => return ENOENT,
    }
    if crate::cext::fs::file_metadata(&path).is_none() {
        return ENOENT;
    }
    let rc = crate::cext::fs::truncate(&path, len);
    if rc != 0 {
        return errno_from_cext(rc);
    }
    SUCCESS
}

pub fn chmod(path_ptr: u64, mode: u64) -> u64 {
    if path_ptr == 0 || mode > u32::MAX as u64 {
        return EINVAL;
    }
    let Some(pid) = current_process_id_raw() else {
        return EBADF;
    };
    let path = match read_cstring(path_ptr) {
        Ok(path) => resolve_path(pid, &path),
        Err(errno) => return errno,
    };
    if let Err(errno) = ensure_fs_capability_access(&path, PATH_WRITE) {
        return errno;
    }
    if let Err(errno) = ensure_unix_traversal(&path) {
        return errno;
    }
    let Some((_, _, owner, _)) = metadata_rootfs_first(&path) else {
        return ENOENT;
    };
    let Some((uid, _)) = current_effective_ids() else {
        return EACCES;
    };
    if uid != 0 && uid != owner {
        return EACCES;
    }
    let rc = crate::cext::fs::chmod(&path, mode as u32);
    if rc == 0 {
        SUCCESS
    } else {
        errno_from_cext(rc)
    }
}

pub fn chown(path_ptr: u64, uid: u64, gid: u64) -> u64 {
    if path_ptr == 0 || uid > u32::MAX as u64 || gid > u32::MAX as u64 {
        return EINVAL;
    }
    let Some(pid) = current_process_id_raw() else {
        return EBADF;
    };
    let path = match read_cstring(path_ptr) {
        Ok(path) => resolve_path(pid, &path),
        Err(errno) => return errno,
    };
    if let Err(errno) = ensure_fs_path_access(&path, PATH_WRITE) {
        return errno;
    }
    let Some((effective_uid, _)) = current_effective_ids() else {
        return EACCES;
    };
    if effective_uid != 0 {
        return EACCES;
    }
    if metadata_rootfs_first(&path).is_none() {
        return ENOENT;
    }
    let rc = crate::cext::fs::chown(&path, uid as u32, gid as u32);
    if rc == 0 {
        SUCCESS
    } else {
        errno_from_cext(rc)
    }
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
    let Some(open_file) = open_file(pid, idx) else {
        return EBADF;
    };
    let res = (|| {
        let mut open = open_file.lock();
        if open
            .vnode
            .as_ref()
            .is_some_and(|vnode| vnode.is_directory())
        {
            return Err(EISDIR);
        }
        if let Some(vnode) = open.vnode.as_ref() {
            if let Some((_, open_id)) = vnode.userspace_handle_ids() {
                vfs::userspace::truncate(vnode.inode.mount_id.0, open_id, len)?;
            } else {
                let rc = if let Some(handle) = vnode.cext_handle_id() {
                    crate::cext::fs::truncate_handle(handle, len)
                } else {
                    crate::cext::fs::truncate(vnode.path(), len)
                };
                if rc != 0 {
                    return Err(errno_from_cext(rc));
                }
            }
        } else {
            let mut data = open.data.to_vec();
            data.resize(new_len, 0);
            open.data = data.into_boxed_slice();
        }
        if open.pos > new_len {
            open.pos = new_len;
        }
        Ok::<(), u64>(())
    })();
    match res {
        Ok(()) => SUCCESS,
        Err(errno) => errno,
    }
}

pub fn pipe2(fds_ptr: u64, flags: u64) -> u64 {
    if fds_ptr == 0 || !crate::syscall::validate_user_ptr(fds_ptr, 8) {
        return EFAULT;
    }
    const PIPE_ALLOWED_FLAGS: u64 = O_CLOEXEC;
    if flags & !PIPE_ALLOWED_FLAGS != 0 {
        return EINVAL;
    }
    let pid = match current_process_id_raw() {
        Some(p) => p,
        None => return EBADF,
    };
    let Some(pipe_id) = alloc_pipe_state() else {
        return ENOSPC;
    };
    let cloexec = (flags & O_CLOEXEC) != 0;
    let allocated = with_fd_table_mut(pid, |t| {
        let read_fd = match t.alloc(
            alloc::boxed::Box::new(FileHandle::new_pipe_read(pipe_id)),
            cloexec,
        ) {
            Some(fd) => fd,
            None => return Err(ENOSPC),
        };
        let write_fd = match t.alloc(
            alloc::boxed::Box::new(FileHandle::new_pipe_write(pipe_id)),
            cloexec,
        ) {
            Some(fd) => fd,
            None => {
                let _ = t.take(read_fd);
                return Err(ENOSPC);
            }
        };
        Ok((read_fd, write_fd))
    });
    let (read_fd, write_fd) = match allocated {
        Some(Ok(fds)) => fds,
        _ => {
            close_pipe_endpoint_from_kernel(pipe_id, false);
            close_pipe_endpoint_from_kernel(pipe_id, true);
            return ENOSPC;
        }
    };
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(read_fd as i32).to_ne_bytes());
    out[4..].copy_from_slice(&(write_fd as i32).to_ne_bytes());
    if let Err(errno) = crate::syscall::copy_to_user(fds_ptr, &out) {
        let _ = with_fd_table_mut(pid, |t| {
            let _ = t.take(read_fd);
            let _ = t.take(write_fd);
        });
        return errno;
    }
    SUCCESS
}

pub fn pipe(fds_ptr: u64) -> u64 {
    pipe2(fds_ptr, 0)
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
        t.get(idx).map(|fh| alloc::boxed::Box::new(fh.duplicate()))
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
        t.get(old_idx)
            .map(|fh| alloc::boxed::Box::new(fh.duplicate()))
    }) {
        Some(Some(h)) => h,
        _ => return EBADF,
    };

    // new_fd が使用中なら閉じる
    with_fd_table_mut(pid, |t| {
        let _ = t.replace(new_idx, new_handle, false);
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
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_DELETE) {
        return errno;
    }
    match metadata_rootfs_first(&resolved) {
        Some((mode, _, _, _)) if mode_is_directory(mode) => return EISDIR,
        Some(_) => {}
        None => return ENOENT,
    }
    if crate::cext::fs::remove(&resolved, false) != 0 {
        return EIO;
    }
    SUCCESS
}

/// unlinkat システムコール
pub fn unlinkat(dirfd: i64, path_ptr: u64, flags: u64) -> u64 {
    const AT_REMOVEDIR: u64 = 0x200;
    if path_ptr == 0 || flags & !AT_REMOVEDIR != 0 {
        return EINVAL;
    }
    let pid = match current_process_id_raw() {
        Some(pid) => pid,
        None => return EBADF,
    };
    let resolved = match resolve_path_at(pid, dirfd, path_ptr) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    if let Err(errno) = ensure_fs_path_access(&resolved, PATH_DELETE) {
        return errno;
    }
    let remove_directory = (flags & AT_REMOVEDIR) != 0;
    match metadata_rootfs_first(&resolved) {
        Some((mode, _, _, _)) if mode_is_directory(mode) != remove_directory => {
            return if remove_directory { ENOTDIR } else { EISDIR };
        }
        Some(_) => {}
        None => return ENOENT,
    }
    let rc = crate::cext::fs::remove(&resolved, remove_directory);
    if rc == 0 {
        SUCCESS
    } else {
        errno_from_cext(rc)
    }
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
    let new_rights = if metadata_rootfs_first(&new_path).is_some() {
        PATH_DELETE
    } else {
        PATH_CREATE
    };
    if let Err(errno) = ensure_fs_path_access(&new_path, new_rights) {
        return errno;
    }
    if metadata_rootfs_first(&old_path).is_none() {
        return ENOENT;
    }
    let rc = crate::cext::fs::rename(&old_path, &new_path);
    if rc != 0 {
        return errno_from_cext(rc);
    }
    SUCCESS
}

/// Openat システムコール
///
/// AT_FDCWD(-100) の場合は CWD 相対の open() と同等。
/// それ以外の dirfd は fd_table からディレクトリパスを取得してプレフィックスとして使用する。
pub fn openat(dirfd: i64, path_ptr: u64, flags: u64, mode: u64) -> u64 {
    const AT_FDCWD: i64 = -100;

    if dirfd == AT_FDCWD {
        // CWD 相対 → 通常の open() と同じ
        let pid = match current_process_id_raw() {
            Some(pid) => pid,
            None => return EBADF,
        };
        let path = match read_cstring(path_ptr) {
            Ok(path) => resolve_path(pid, &path),
            Err(errno) => return errno,
        };
        return open_resolved_for_pid(pid, &path, flags, mode);
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
    let Some(dir_path) = open_file(pid, idx).and_then(|open_file| {
        open_file
            .lock()
            .vnode
            .as_ref()
            .filter(|vnode| vnode.is_directory())
            .map(|vnode| vnode.path().to_string())
    }) else {
        return EBADF;
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

    open_resolved_for_pid(pid, &normalize_path(&full_path), flags, mode)
}

/// Newfstatat (fstatat) システムコール
///
/// AT_FDCWD(-100) の場合は stat() と同等。
pub fn newfstatat(dirfd: i64, path_ptr: u64, stat_ptr: u64, flags: u64) -> u64 {
    const AT_FDCWD: i64 = -100;
    const AT_SYMLINK_NOFOLLOW: u64 = 2;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const SUPPORTED_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

    if flags & !SUPPORTED_FLAGS != 0 {
        return EINVAL;
    }

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
    let Some(dir_path) = open_file(pid, idx).and_then(|open_file| {
        open_file
            .lock()
            .vnode
            .as_ref()
            .filter(|vnode| vnode.is_directory())
            .map(|vnode| vnode.path().to_string())
    }) else {
        return EBADF;
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
    if let Err(errno) = ensure_fs_path_access(&full, PATH_READ) {
        return errno;
    }
    match metadata_rootfs_first(&full) {
        Some((mode, size, uid, gid)) => {
            const STAT_SIZE: u64 = 144;
            if !crate::syscall::validate_user_ptr(stat_ptr, STAT_SIZE) {
                return EFAULT;
            }
            write_stat_buf(stat_ptr, mode_for_stat(mode), size, uid, gid);
            SUCCESS
        }
        None => ENOENT,
    }
}

/// Faccessat システムコール
pub fn faccessat(dirfd: i64, path_ptr: u64, mode: u64, flags: u64) -> u64 {
    const F_OK: u64 = 0;
    const AT_EACCESS: u64 = 0x200;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const SUPPORTED_FLAGS: u64 = AT_EACCESS | AT_SYMLINK_NOFOLLOW;
    let Some(rights) = access_mode_rights(mode) else {
        return EINVAL;
    };
    if path_ptr == 0 || flags & !SUPPORTED_FLAGS != 0 {
        return EINVAL;
    }
    let pid = match current_process_id_raw() {
        Some(pid) => pid,
        None => return EBADF,
    };
    let resolved = match resolve_path_at(pid, dirfd, path_ptr) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    if metadata_rootfs_first(&resolved).is_none() {
        return ENOENT;
    }
    if mode == F_OK {
        if let Err(errno) = ensure_fs_capability_access(&resolved, PATH_READ) {
            return errno;
        }
        return match ensure_unix_traversal(&resolved) {
            Ok(()) => SUCCESS,
            Err(errno) => errno,
        };
    }
    match ensure_fs_path_access(&resolved, rights) {
        Ok(()) => SUCCESS,
        Err(errno) => errno,
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

    let Some(open_file) = open_file(pid, idx) else {
        return EBADF;
    };
    let (dir_path, start_pos) = {
        let open = open_file.lock();
        let Some(path) = open
            .vnode
            .as_ref()
            .filter(|vnode| vnode.is_directory())
            .map(|vnode| vnode.path().to_string())
        else {
            return EBADF;
        };
        (path, open.pos)
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
                    Some((mode, _, _, _)) if mode_is_directory(mode) => 4u8,
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
    open_file.lock().pos = new_pos;

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

#[cfg(test)]
mod unix_mode_tests {
    use super::{
        access_mode_rights, capability_requirement_satisfied, open_path_required_rights,
        path_is_in_identity_storage, resolve_relative_to_cwd, sticky_directory_allows_delete,
        unix_mode_allows, O_CREAT, O_RDWR, O_WRONLY, PATH_CREATE, PATH_EXEC, PATH_LIST, PATH_READ,
        PATH_WRITE, UNIX_EXECUTE,
    };
    use crate::capability::Capability;

    #[test]
    fn root_bypasses_unix_mode_bits() {
        assert!(unix_mode_allows(
            0,
            1000,
            1000,
            0,
            0,
            PATH_READ | PATH_WRITE
        ));
    }

    #[test]
    fn owner_group_and_other_bits_are_selected_by_identity() {
        let mode = 0o640;
        assert!(unix_mode_allows(mode, 1000, 2000, 1000, 3000, PATH_WRITE));
        assert!(unix_mode_allows(mode, 1000, 2000, 3000, 2000, PATH_READ));
        assert!(!unix_mode_allows(mode, 1000, 2000, 3000, 3000, PATH_READ));
    }

    #[test]
    fn directory_listing_and_traversal_require_execute() {
        let directory = 0x4000 | 0o740;
        assert!(unix_mode_allows(
            directory, 1000, 2000, 1000, 3000, PATH_LIST
        ));
        assert!(!unix_mode_allows(
            directory, 1000, 2000, 3000, 2000, PATH_LIST
        ));
        assert!(!unix_mode_allows(
            directory,
            1000,
            2000,
            3000,
            2000,
            UNIX_EXECUTE
        ));
    }

    #[test]
    fn open_create_checks_existing_file_instead_of_its_parent() {
        assert_eq!(
            open_path_required_rights(O_CREAT | O_RDWR, false, true),
            PATH_READ | PATH_WRITE
        );
        assert_eq!(
            open_path_required_rights(O_CREAT | O_WRONLY, false, false),
            PATH_CREATE
        );
        assert_eq!(open_path_required_rights(O_CREAT, false, true), PATH_READ);
    }

    #[test]
    fn relative_at_fdcwd_paths_are_resolved_from_process_cwd() {
        assert_eq!(
            resolve_relative_to_cwd("/home/testuser", "hello.txt"),
            "/home/testuser/hello.txt"
        );
        assert_eq!(
            resolve_relative_to_cwd("/home/testuser/", "Documents/../hello.txt"),
            "/home/testuser/hello.txt"
        );
        assert_eq!(
            resolve_relative_to_cwd("/home/testuser", "/tmp/hello.txt"),
            "/tmp/hello.txt"
        );
    }

    #[test]
    fn access_modes_map_to_read_write_and_execute() {
        assert_eq!(access_mode_rights(0), Some(0));
        assert_eq!(access_mode_rights(4), Some(PATH_READ));
        assert_eq!(access_mode_rights(2), Some(PATH_WRITE));
        assert_eq!(access_mode_rights(1), Some(PATH_EXEC | UNIX_EXECUTE));
        assert_eq!(
            access_mode_rights(7),
            Some(PATH_READ | PATH_WRITE | PATH_EXEC | UNIX_EXECUTE)
        );
        assert_eq!(access_mode_rights(8), None);
    }

    #[test]
    fn sticky_directory_protects_files_owned_by_other_users() {
        assert!(sticky_directory_allows_delete(0o777, 0, 1001, 1000));
        assert!(sticky_directory_allows_delete(0o1777, 0, 1000, 1000));
        assert!(sticky_directory_allows_delete(0o1777, 1000, 1001, 1000));
        assert!(sticky_directory_allows_delete(0o1777, 0, 1001, 0));
        assert!(!sticky_directory_allows_delete(0o1777, 0, 1001, 1000));
    }

    #[test]
    fn identity_storage_is_scoped_to_exact_security_identity() {
        assert!(path_is_in_identity_storage(
            "/policy/identity-data/process.example.shell",
            "/policy/identity-data",
            "process.example.shell"
        ));
        assert!(path_is_in_identity_storage(
            "/policy/identity-data/process.example.shell/preferences.conf",
            "/policy/identity-data",
            "process.example.shell"
        ));
        assert!(!path_is_in_identity_storage(
            "/policy/identity-data/process.example.files/settings",
            "/policy/identity-data",
            "process.example.shell"
        ));
        assert!(!path_is_in_identity_storage(
            "/policy/identity-data/process.example.shell-extra/settings",
            "/policy/identity-data",
            "process.example.shell"
        ));
        assert!(!path_is_in_identity_storage(
            "/policy/identity-data/process.example.shell/settings",
            "/somewhere/else",
            "process.example.shell"
        ));
    }

    #[test]
    fn broad_capability_does_not_become_implicit() {
        assert!(!capability_requirement_satisfied(
            Capability::FsReadAll,
            Capability::FsReadAll,
            false,
            false,
        ));
        assert!(capability_requirement_satisfied(
            Capability::FsReadAll,
            Capability::FsReadAll,
            true,
            true,
        ));
        assert!(capability_requirement_satisfied(
            Capability::FsReadTmp,
            Capability::FsReadAll,
            false,
            true,
        ));
    }
}
