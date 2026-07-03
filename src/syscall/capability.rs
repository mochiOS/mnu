//! capability 関連の syscall
//!
//! カーネルはプロセスに紐づく `CapabilitySet` を保持し、各サービスが caller を検査できるように
//! 最低限の照会 API を提供する。
//!
//! policy 判定（危険度分類、ユーザー許可 UI、manifest 解析など）は service 側へ寄せる。

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::capability::{
    kernel_authority_implies, parse_kernel_authority_spec, Capability, CapabilityClass, KernelAuthority,
    KernelCapability,
};
use crate::syscall::copy_from_user;
use crate::syscall::types::{EACCES, EFAULT, EINVAL, ENOSYS, SUCCESS};

#[derive(Clone, Copy)]
enum CapabilityToken {
    Plain(Capability),
    Authority(KernelAuthority),
}

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
    let Some(pid) = crate::task::thread_to_process_id(thread_id) else {
        return 0;
    };
    match parse_capability_token(name) {
        Some(CapabilityToken::Plain(cap)) => {
            if crate::task::process::process_has_capability(pid, cap) {
                1
            } else {
                0
            }
        }
        Some(CapabilityToken::Authority(authority)) => {
            if crate::task::process::process_has_kernel_authority(pid, &authority) {
                1
            } else {
                0
            }
        }
        None => EINVAL,
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
    let Some(pid) = current_process() else {
        return ENOSYS;
    };
    match parse_capability_token(name) {
        Some(CapabilityToken::Plain(cap)) => {
            if crate::task::process::process_has_capability(pid, cap)
                || (matches!(cap, Capability::MemoryPhysMap)
                    && crate::task::process::process_has_kernel_capability_authority(
                        pid,
                        KernelCapability::PhysMap,
                    ))
            {
                1
            } else {
                0
            }
        }
        Some(CapabilityToken::Authority(authority)) => {
            if crate::task::process::process_has_kernel_authority(pid, &authority) {
                1
            } else {
                0
            }
        }
        None => EINVAL,
    }
}

pub fn clone_capability(_cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_capability_token_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    match cap {
        CapabilityToken::Plain(cap) => {
            if crate::task::process::process_has_capability(current, cap) {
                SUCCESS
            } else {
                EACCES
            }
        }
        CapabilityToken::Authority(authority) => {
            if crate::task::process::process_has_kernel_authority(current, &authority) {
                SUCCESS
            } else {
                EACCES
            }
        }
    }
}

pub fn drop_capability(_cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_capability_token_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let removed = crate::task::with_process_mut(current, |proc| match cap {
        CapabilityToken::Plain(cap) => proc.capabilities_mut().remove(cap),
        CapabilityToken::Authority(authority) => {
            proc.kernel_authorities_mut().remove_exact(&authority)
        }
    })
    .unwrap_or(false);
    if !removed {
        return EACCES;
    }
    SUCCESS
}

pub fn transfer_capability(_dest: u64, _cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let cap = match read_capability_token_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let dest_process = match resolve_destination_process(_dest) {
        Some(pid) => pid,
        None => return EINVAL,
    };

    let can_manage_capabilities =
        crate::task::process::process_has_capability(current, Capability::CapabilitiesManage);

    if can_manage_capabilities {
        match cap {
            CapabilityToken::Plain(capability) => {
                if capability.class() != CapabilityClass::UserGrantable {
                    return EACCES;
                }
                let inserted = crate::task::with_process_mut(dest_process, |proc| {
                    proc.capabilities_mut().insert(capability)
                });
                return if inserted.is_some() { SUCCESS } else { ENOSYS };
            }
            CapabilityToken::Authority(_) => return EACCES,
        }
    }

    match cap {
        CapabilityToken::Plain(capability) => {
            if !crate::task::process::process_has_capability(current, capability) {
                return EACCES;
            }
            if !capability.is_delegable() {
                return EACCES;
            }
        }
        CapabilityToken::Authority(authority) => {
            if !crate::task::process::process_has_kernel_authority(current, &authority) {
                return EACCES;
            }
        }
    }
    if dest_process == current {
        return SUCCESS;
    }

    let removed = crate::task::with_process_mut(current, |proc| match cap {
        CapabilityToken::Plain(capability) => proc.capabilities_mut().remove(capability),
        CapabilityToken::Authority(authority) => {
            proc.kernel_authorities_mut().remove_exact(&authority)
        }
    })
    .unwrap_or(false);
    if !removed {
        return EACCES;
    }

    let inserted = crate::task::with_process_mut(dest_process, |proc| match cap {
        CapabilityToken::Plain(capability) => proc.capabilities_mut().insert(capability),
        CapabilityToken::Authority(authority) => proc.kernel_authorities_mut().insert(authority),
    });
    if inserted.is_none() {
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
    let cap = match read_capability_token_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let restriction = match read_capability_token_from_user(_restriction_ptr, _restriction_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    match (cap, restriction) {
        (CapabilityToken::Plain(cap), CapabilityToken::Plain(restriction)) => {
            if !crate::task::with_process(current, |proc| proc.capabilities().contains_exact(cap))
                .unwrap_or(false)
            {
                return EACCES;
            }
            if !crate::capability::capability_implies(cap, restriction) {
                return EACCES;
            }
            if crate::task::with_process_mut(current, |proc| {
                let caps = proc.capabilities_mut();
                if !caps.remove(cap) {
                    return false;
                }
                caps.insert(restriction);
                true
            })
            .unwrap_or(false)
            {
                SUCCESS
            } else {
                ENOSYS
            }
        }
        (CapabilityToken::Authority(cap), CapabilityToken::Authority(restriction)) => {
            if !crate::task::with_process(current, |proc| {
                proc.kernel_authorities().contains_exact(&cap)
            })
            .unwrap_or(false)
            {
                return EACCES;
            }
            if !kernel_authority_implies(&cap, &restriction) {
                return EACCES;
            }
            if crate::task::with_process_mut(current, |proc| {
                let authorities = proc.kernel_authorities_mut();
                if !authorities.remove_exact(&cap) {
                    return false;
                }
                authorities.insert(restriction);
                true
            })
            .unwrap_or(false)
            {
                SUCCESS
            } else {
                ENOSYS
            }
        }
        _ => EINVAL,
    }
}

fn current_process() -> Option<crate::task::ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
}

fn resolve_destination_process(dest: u64) -> Option<crate::task::ProcessId> {
    let pid = crate::task::ProcessId::from_u64(dest);
    if crate::task::with_process(pid, |_| ()).is_some() {
        return Some(pid);
    }
    if let Some(pid) = crate::task::thread_to_process_id(dest) {
        return Some(pid);
    }
    if let Some(thread_id) = crate::syscall::ipc::resolve_endpoint_handle(dest) {
        return crate::task::thread_to_process_id(thread_id);
    }
    None
}

fn read_capability_spec_from_user(cap_ptr: u64, cap_len: u64) -> Result<String, u64> {
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
    Ok(name.to_string())
}

fn parse_capability_token(spec: &str) -> Option<CapabilityToken> {
    if let Some(authority) = parse_kernel_authority_spec(spec) {
        return Some(CapabilityToken::Authority(authority));
    }
    Capability::from_str(spec).map(CapabilityToken::Plain)
}

fn read_capability_token_from_user(cap_ptr: u64, cap_len: u64) -> Result<CapabilityToken, u64> {
    let spec = read_capability_spec_from_user(cap_ptr, cap_len)?;
    parse_capability_token(spec.as_str()).ok_or(EINVAL)
}
