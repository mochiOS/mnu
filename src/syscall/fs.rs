//! ファイルシステム関連のシステムコール

use super::types::{
    EACCES, EAGAIN, EBADF, EFAULT, EINVAL, ENOTSUP, EPIPE,
};
use crate::capability::Capability;
use crate::capability::path::{
    self, PATH_CREATE, PATH_DELETE, PATH_EXEC, PATH_LIST, PATH_READ, PATH_WRITE, PathOwner,
};
use crate::task::fd_table::{FileHandle, FileHandleCap};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

const MAX_IO_BYTES: usize = 128 * 1024 * 1024;
const MAX_PIPES: usize = 64;
const PIPE_BUFFER_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeekBasis {
    Start,
    Current,
    End,
}

struct PipeState {
    data: Vec<u8>,
    readers: usize,
    writers: usize,
    waiters: Vec<crate::task::ThreadId>,
}

impl PipeState {
    fn signals(&self, write_end: bool) -> u64 {
        self.signals_with_capacity(write_end, 1)
    }

    fn signals_with_capacity(&self, write_end: bool, minimum: usize) -> u64 {
        let mut signals = 0;
        if write_end {
            if self.readers == 0 {
                signals |= mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            } else if PIPE_BUFFER_CAP.saturating_sub(self.data.len()) >= minimum {
                signals |= mnu_abi::HANDLE_SIGNAL_WRITABLE;
            }
        } else {
            if !self.data.is_empty() || self.writers == 0 {
                signals |= mnu_abi::HANDLE_SIGNAL_READABLE;
            }
            if self.writers == 0 {
                signals |= mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            }
        }
        signals
    }
}

static PIPE_TABLE: crate::interrupt::spinlock::SpinLock<[Option<PipeState>; MAX_PIPES]> =
    crate::interrupt::spinlock::SpinLock::new([const { None }; MAX_PIPES]);

pub(crate) fn alloc_stream_state() -> Option<usize> {
    let mut table = PIPE_TABLE.lock();
    for (index, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PipeState {
                data: Vec::new(),
                readers: 1,
                writers: 1,
                waiters: Vec::new(),
            });
            return Some(index);
        }
    }
    None
}

pub fn close_pipe_endpoint_from_kernel(pipe_id: usize, write_end: bool) {
    let waiters = {
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
        let waiters = core::mem::take(&mut pipe.waiters);
        if pipe.readers == 0 && pipe.writers == 0 {
            *slot = None;
        }
        waiters
    };
    wake_stream_waiters(waiters);
}

fn wake_stream_waiters(waiters: Vec<crate::task::ThreadId>) {
    for waiter in waiters {
        crate::task::wake_registered_waiter(waiter);
    }
}

pub(crate) fn stream_signals(handle: &FileHandle) -> Result<u64, u64> {
    stream_signals_for_capacity(handle, 0)
}

pub(crate) fn stream_signals_for_capacity(handle: &FileHandle, minimum: u32) -> Result<u64, u64> {
    let Some((stream_id, write_end)) = handle.stream_endpoint() else {
        return Err(EBADF);
    };
    if minimum != 0 && (!write_end || minimum as usize > PIPE_BUFFER_CAP) {
        return Err(EINVAL);
    }
    let table = PIPE_TABLE.lock();
    let Some(Some(stream)) = table.get(stream_id) else {
        return Err(EBADF);
    };
    Ok(if minimum == 0 {
        stream.signals(write_end)
    } else {
        stream.signals_with_capacity(write_end, minimum as usize)
    })
}

pub(crate) fn register_stream_waiter(
    handle: &FileHandle,
    waiter: crate::task::ThreadId,
) -> Result<usize, u64> {
    let Some((stream_id, _)) = handle.stream_endpoint() else {
        return Err(EBADF);
    };
    let mut table = PIPE_TABLE.lock();
    let Some(Some(stream)) = table.get_mut(stream_id) else {
        return Err(EBADF);
    };
    if !stream.waiters.contains(&waiter) {
        stream.waiters.push(waiter);
    }
    Ok(stream_id)
}

pub(crate) fn remove_stream_waiter(stream_id: usize, waiter: crate::task::ThreadId) {
    let mut table = PIPE_TABLE.lock();
    if let Some(Some(stream)) = table.get_mut(stream_id) {
        stream.waiters.retain(|candidate| *candidate != waiter);
    }
}

pub(crate) fn ensure_fs_path_executable_for_process(
    path: &str,
    pid: crate::task::ids::ProcessId,
) -> Result<(), u64> {
    // Only native authority is checked here. POSIX credentials and execute
    // permissions are userspace policy, not kernel process state.
    if crate::task::with_process(pid, |_| ()).is_none() {
        return Err(EACCES);
    }
    ensure_fs_capability_access_for_process(path, PATH_EXEC, pid.as_u64())
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

fn path_owner_allows(owner: PathOwner, pid_raw: u64) -> bool {
    match owner {
        PathOwner::Any => true,
        PathOwner::System => false,
        PathOwner::Service(owner_pid) | PathOwner::Application(owner_pid) => owner_pid == pid_raw,
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

pub(crate) fn file_handle_options(handle: &FileHandle) -> Result<u64, u64> {
    let open = handle.open.lock();
    if open.pipe_id.is_none() {
        return Err(ENOTSUP);
    }
    Ok(open.io_options)
}

pub(crate) fn set_file_handle_options(handle: &FileHandle, options: u64) -> Result<(), u64> {
    if options & !mnu_abi::HANDLE_OPTIONS_ALL != 0 {
        return Err(EINVAL);
    }
    let mut open = handle.open.lock();
    if open.pipe_id.is_none() {
        return Err(ENOTSUP);
    }
    open.io_options = options;
    Ok(())
}

pub(crate) fn read_file_handle(handle: &FileHandle, buf_ptr: u64, len: u64) -> u64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    if len == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, len) {
        return EFAULT;
    }
    if !handle.cap.contains(FileHandleCap::READ) {
        return EACCES;
    }
    let open = handle.open.lock();
    let Some(pipe_id) = open.pipe_id else {
        return ENOTSUP;
    };
    let io_options = open.io_options;
    drop(open);
    read_pipe(pipe_id, io_options, buf_ptr, len)
}

fn read_pipe(pipe_id: usize, io_options: u64, buf_ptr: u64, len: u64) -> u64 {
    let target_len = match usize::try_from(len) {
        Ok(v) => v.min(MAX_IO_BYTES),
        Err(_) => MAX_IO_BYTES,
    };
    let Some(current) = crate::task::current_thread_id() else {
        return EBADF;
    };
    loop {
        let mut table = PIPE_TABLE.lock();
        let Some(Some(pipe)) = table.get_mut(pipe_id) else {
            return EBADF;
        };
        if pipe.data.is_empty() {
            if pipe.writers == 0 {
                return 0;
            }
            if (io_options & mnu_abi::HANDLE_OPTION_NONBLOCKING) != 0 {
                return EAGAIN;
            }
            if !pipe.waiters.contains(&current) {
                pipe.waiters.push(current);
            }
            drop(table);
            if crate::task::with_thread(current, |thread| thread.has_deliverable_upcall())
                .unwrap_or(false)
            {
                remove_stream_waiter(pipe_id, current);
                return EAGAIN;
            }
            let _ = crate::task::sleep_thread_unless_woken(current);
            crate::task::yield_now();
            continue;
        }
        let take = core::cmp::min(pipe.data.len(), target_len);
        if crate::syscall::copy_to_user(buf_ptr, &pipe.data[..take]).is_err() {
            return EFAULT;
        }
        pipe.data.drain(0..take);
        pipe.waiters.retain(|waiter| *waiter != current);
        let waiters = core::mem::take(&mut pipe.waiters);
        drop(table);
        wake_stream_waiters(waiters);
        return take as u64;
    }
}

pub(crate) fn write_file_handle(handle: &FileHandle, buf_ptr: u64, len: u64) -> u64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    if len == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, len) {
        return EFAULT;
    }
    if !handle.cap.contains(FileHandleCap::WRITE) {
        return EACCES;
    }
    let open = handle.open.lock();
    let Some(pipe_id) = open.pipe_id else {
        return ENOTSUP;
    };
    let io_options = open.io_options;
    drop(open);
    write_pipe(pipe_id, io_options, buf_ptr, len, true)
}

pub(crate) fn read_stream_handle(
    handle: &FileHandle,
    buffer: u64,
    length: u64,
    options: u64,
) -> u64 {
    if !handle.cap.contains(FileHandleCap::READ) {
        return EACCES;
    }
    if length == 0 {
        return 0;
    }
    if buffer == 0 || !crate::syscall::validate_user_ptr(buffer, length) {
        return EFAULT;
    }
    let open = handle.open.lock();
    let Some(stream_id) = open.pipe_id else {
        return ENOTSUP;
    };
    if open.pipe_write {
        return EBADF;
    }
    let io_options = open.io_options
        | if options & mnu_abi::STREAM_IO_TRY != 0 {
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        } else {
            0
        };
    drop(open);
    read_pipe(stream_id, io_options, buffer, length)
}

pub(crate) fn write_stream_handle(
    handle: &FileHandle,
    buffer: u64,
    length: u64,
    options: u64,
) -> u64 {
    if !handle.cap.contains(FileHandleCap::WRITE) {
        return EACCES;
    }
    let open = handle.open.lock();
    let Some(stream_id) = open.pipe_id else {
        return ENOTSUP;
    };
    if !open.pipe_write {
        return EBADF;
    }
    let io_options = open.io_options
        | if options & mnu_abi::STREAM_IO_TRY != 0 {
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        } else {
            0
        };
    drop(open);
    write_pipe(
        stream_id,
        io_options,
        buffer,
        length,
        options & mnu_abi::STREAM_WRITE_COMPLETE != 0,
    )
}

fn write_pipe(pipe_id: usize, io_options: u64, buf_ptr: u64, len: u64, complete: bool) -> u64 {
    let Ok(len_usize) = usize::try_from(len) else {
        return EINVAL;
    };
    if complete && len_usize > PIPE_BUFFER_CAP {
        return EINVAL;
    }
    if len_usize == 0 {
        return 0;
    }
    let mut tmp = alloc::vec![0u8; len_usize.min(PIPE_BUFFER_CAP)];
    crate::performance::record_vfs_temporary_buffer(tmp.len());
    if let Err(errno) = crate::syscall::copy_from_user(buf_ptr, &mut tmp) {
        return errno;
    }
    let Some(current) = crate::task::current_thread_id() else {
        return EBADF;
    };
    loop {
        let mut table = PIPE_TABLE.lock();
        let Some(Some(pipe)) = table.get_mut(pipe_id) else {
            return EBADF;
        };
        if pipe.readers == 0 {
            return EPIPE;
        }
        let available = PIPE_BUFFER_CAP.saturating_sub(pipe.data.len());
        let count = if complete {
            if available >= tmp.len() { tmp.len() } else { 0 }
        } else {
            available.min(tmp.len())
        };
        if count != 0 {
            pipe.data.extend_from_slice(&tmp[..count]);
            pipe.waiters.retain(|waiter| *waiter != current);
            let waiters = core::mem::take(&mut pipe.waiters);
            drop(table);
            wake_stream_waiters(waiters);
            return count as u64;
        }
        if (io_options & mnu_abi::HANDLE_OPTION_NONBLOCKING) != 0 {
            return EAGAIN;
        }
        if !pipe.waiters.contains(&current) {
            pipe.waiters.push(current);
        }
        drop(table);
        if crate::task::with_thread(current, |thread| thread.has_deliverable_upcall())
            .unwrap_or(false)
        {
            remove_stream_waiter(pipe_id, current);
            return EAGAIN;
        }
        let _ = crate::task::sleep_thread_unless_woken(current);
        crate::task::yield_now();
    }
}

#[cfg(test)]
mod unix_mode_tests {
    use super::{
        PIPE_BUFFER_CAP, PipeState, capability_requirement_satisfied,
        path_is_in_identity_storage,
    };
    use crate::capability::Capability;

    #[test]
    fn stream_signals_cover_data_capacity_and_peer_closure() {
        let mut stream = PipeState {
            data: alloc::vec::Vec::new(),
            readers: 1,
            writers: 1,
            waiters: alloc::vec::Vec::new(),
        };
        assert_eq!(stream.signals(false), 0);
        assert_eq!(stream.signals(true), mnu_abi::HANDLE_SIGNAL_WRITABLE);

        stream.data.resize(PIPE_BUFFER_CAP, 0);
        assert_eq!(stream.signals(false), mnu_abi::HANDLE_SIGNAL_READABLE);
        assert_eq!(stream.signals(true), 0);

        stream.writers = 0;
        assert_eq!(
            stream.signals(false),
            mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
        );
        stream.readers = 0;
        assert_eq!(stream.signals(true), mnu_abi::HANDLE_SIGNAL_PEER_CLOSED);
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
