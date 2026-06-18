//! capability 関連の syscall
//!
//! カーネルはプロセスに紐づく `CapabilitySet` を保持し、各サービスが caller を検査できるように
//! 最低限の照会 API を提供する。
//!
//! policy 判定（危険度分類、ユーザー許可 UI、manifest 解析など）は service 側へ寄せる。

extern crate alloc;

use alloc::vec::Vec;

use crate::capability::Capability;
use crate::syscall::copy_from_user;
use crate::syscall::types::{EACCES, EFAULT, EINVAL, ENOSYS, SUCCESS};

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
    if !cap.is_delegable() {
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

fn current_process() -> Option<crate::task::ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
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
