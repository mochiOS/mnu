//! capability 関連の syscall
//!
//! カーネルはプロセスに紐づく `CapabilitySet` を保持し、各サービスが caller を検査できるように
//! 最低限の照会 API を提供する。
//!
//! policy 判定（危険度分類、ユーザー許可 UI、manifest 解析など）は service 側へ寄せる。

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::capability::path::PathRights;
use crate::capability::{path, Capability};
use crate::syscall::types::{EACCES, EEXIST, EFAULT, EINVAL, ENOSPC, ENOSYS, SUCCESS};
use crate::syscall::{copy_from_user, copy_to_user};

/// 指定スレッドが capability を持つか確認する
///
/// - `thread_id`: 照会対象のスレッドID（IPCの sender をそのまま渡す想定）
/// - `cap_ptr` / `cap_len`: UTF-8 の capability 名（例: `fs.read.user.documents`）
///
/// 戻り値:
/// - `1` = 許可
/// - `0` = 不許可
/// - `EINVAL/EFAULT` = 不正な引数
pub fn check_thread_capability(thread_id: u64, cap_ptr: u64, cap_len: u64) -> u64 {
    // 過剰なコピーを避けるため、ここでは短い上限を設ける。
    // capability 名は固定の識別子であり、長大な文字列である必要がない。
    let max_cap_name_len = crate::config::kernel().capability.max_name_len;

    if thread_id == 0 || cap_ptr == 0 || cap_len == 0 {
        return EINVAL;
    }
    let Ok(cap_len_usize) = usize::try_from(cap_len) else {
        return EINVAL;
    };
    if cap_len_usize > max_cap_name_len {
        return EINVAL;
    }

    let mut buf = Vec::with_capacity(cap_len_usize);
    buf.resize(cap_len_usize, 0u8);
    if copy_from_user(cap_ptr, &mut buf).is_err() {
        return EFAULT;
    }

    let Ok(name) = core::str::from_utf8(&buf) else {
        return EINVAL;
    };
    let Some(cap) = Capability::from_str(name) else {
        return EINVAL;
    };

    let Some(pid) = crate::task::thread_to_process_id(thread_id) else {
        return 0;
    };
    if crate::task::process::process_has_capability(pid, cap) {
        1
    } else {
        0
    }
}

/// capability の基本照会。
///
/// いまは文字列で指定された capability を caller が持つかだけを返す。
pub fn query(cap_ptr: u64, cap_len: u64) -> u64 {
    let max_cap_name_len = crate::config::kernel().capability.max_name_len;
    if cap_ptr == 0 || cap_len == 0 {
        return EINVAL;
    }
    let Ok(cap_len_usize) = usize::try_from(cap_len) else {
        return EINVAL;
    };
    if cap_len_usize > max_cap_name_len {
        return EINVAL;
    }

    let mut buf = Vec::with_capacity(cap_len_usize);
    buf.resize(cap_len_usize, 0u8);
    if copy_from_user(cap_ptr, &mut buf).is_err() {
        return EFAULT;
    }

    let Ok(name) = core::str::from_utf8(&buf) else {
        return EINVAL;
    };
    let Some(cap) = Capability::from_str(name) else {
        return EINVAL;
    };

    if crate::syscall::security::caller_has_any_capability(&[cap]) {
        1
    } else {
        0
    }
}

pub fn clone_capability(_cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_cap_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    if crate::task::process::process_has_capability(current, cap) {
        SUCCESS
    } else {
        EACCES
    }
}

pub fn drop_capability(_cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_cap_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    if !crate::task::with_process_mut(current, |proc| proc.capabilities_mut().remove(cap))
        .unwrap_or(false)
    {
        return EACCES;
    }
    SUCCESS
}

pub fn transfer_capability(_dest: u64, _cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_cap_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    if !crate::task::process::process_has_capability(current, cap) {
        return EACCES;
    }

    let dest_process = match resolve_destination_process(_dest) {
        Some(pid) => pid,
        None => return EINVAL,
    };
    if dest_process == current {
        return SUCCESS;
    }

    if !crate::task::with_process_mut(current, |proc| proc.capabilities_mut().remove(cap))
        .unwrap_or(false)
    {
        return EACCES;
    }

    if crate::task::with_process_mut(dest_process, |proc| {
        proc.capabilities_mut().insert(cap);
    })
    .is_none()
    {
        return ENOSYS;
    }

    SUCCESS
}

pub fn restrict_capability(
    _cap_ptr: u64,
    _cap_len: u64,
    _restriction_ptr: u64,
    _restriction_len: u64,
) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_cap_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let restriction = match read_cap_from_user(_restriction_ptr, _restriction_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    if !crate::capability::capability_implies(cap, restriction) {
        return EACCES;
    }
    if !crate::task::with_process_mut(current, |proc| {
        let caps = proc.capabilities_mut();
        let _ = caps.remove(cap);
        caps.insert(restriction);
    })
    .is_some()
    {
        return ENOSYS;
    }
    SUCCESS
}

pub fn register_path(path_ptr: u64, path_len: u64, rights_bits: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    if !caller_can_manage_paths() {
        return EACCES;
    }
    if rights_bits == 0 {
        return EINVAL;
    }

    let path_len_usize = match usize::try_from(path_len) {
        Ok(v) if v > 0 => v,
        _ => return EINVAL,
    };
    let mut buf = Vec::with_capacity(path_len_usize);
    buf.resize(path_len_usize, 0u8);
    if copy_from_user(path_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let Ok(path_str) = core::str::from_utf8(&buf) else {
        return EINVAL;
    };

    let Some(privilege) = crate::task::with_process(current, |proc| proc.privilege()) else {
        return ENOSYS;
    };
    let owner = path::path_owner_for_current_process(current.as_u64(), privilege);
    let rights = PathRights::new(rights_bits as u32);
    match path::register_path(path_str, owner, rights) {
        Ok(()) => SUCCESS,
        Err(path::PathRegistryError::AlreadyRegistered) => EEXIST,
        Err(path::PathRegistryError::InvalidPath) => EINVAL,
    }
}

pub fn list_paths(buf_ptr: u64, buf_len: u64) -> u64 {
    if !caller_can_manage_paths() {
        return EACCES;
    }
    if buf_ptr == 0 || buf_len == 0 {
        return EINVAL;
    }
    let buf_len_usize = match usize::try_from(buf_len) {
        Ok(v) if v > 0 => v,
        _ => return EINVAL,
    };
    let paths = path::list_paths();
    let mut text = String::new();
    for entry in paths {
        let _ = write!(
            &mut text,
            "{}\towner={}\trights={}\ttype={:?}\n",
            entry.path,
            path::owner_to_string(entry.owner),
            path::rights_to_string(entry.rights),
            entry.path_type,
        );
    }
    let bytes = text.as_bytes();
    if bytes.len() > buf_len_usize {
        return ENOSPC;
    }
    if copy_to_user(buf_ptr, bytes).is_err() {
        return EFAULT;
    }
    bytes.len() as u64
}

fn current_process() -> Option<crate::task::ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
}

fn caller_can_manage_paths() -> bool {
    crate::syscall::security::caller_is_core()
        || (crate::syscall::security::caller_has_privilege(&[crate::task::PrivilegeLevel::Service])
            && crate::syscall::security::caller_has_any_capability(&[
                Capability::CapabilitiesManage,
            ]))
}

fn resolve_destination_process(dest: u64) -> Option<crate::task::ProcessId> {
    if let Some(pid) = crate::task::thread_to_process_id(dest) {
        return Some(pid);
    }
    if let Some(thread_id) = crate::syscall::ipc::resolve_endpoint_handle(dest) {
        return crate::task::thread_to_process_id(thread_id);
    }
    None
}

fn read_cap_from_user(cap_ptr: u64, cap_len: u64) -> Result<Capability, u64> {
    let max_cap_name_len = crate::config::kernel().capability.max_name_len;
    if cap_ptr == 0 || cap_len == 0 {
        return Err(EINVAL);
    }
    let cap_len_usize = usize::try_from(cap_len).map_err(|_| EINVAL)?;
    if cap_len_usize > max_cap_name_len {
        return Err(EINVAL);
    }
    let mut buf = Vec::with_capacity(cap_len_usize);
    buf.resize(cap_len_usize, 0u8);
    if copy_from_user(cap_ptr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let name = core::str::from_utf8(&buf).map_err(|_| EINVAL)?;
    Capability::from_str(name).ok_or(EINVAL)
}
