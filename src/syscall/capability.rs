//! capability 関連の syscall
//!
//! カーネルはプロセスに紐づく `CapabilitySet` を保持し、各サービスが caller を検査できるように
//! 最低限の照会 API を提供する。
//!
//! policy 判定（危険度分類、ユーザー許可 UI、manifest 解析など）は service 側へ寄せる。

extern crate alloc;

use alloc::string::String;
use mnu_abi::status::Error;

use crate::capability::path::{self, PathRights, PATH_CREATE, PATH_LIST, PATH_READ, PATH_WRITE};
use crate::capability::{
    kernel_authority_implies, parse_kernel_authority_spec, Capability, KernelAuthority,
    KernelCapability,
};
use crate::syscall::copy_from_user_native;
use crate::syscall::types::{EACCES, EINVAL, ENOSYS, SUCCESS};

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
/// - `status::Error` = 入力、メモリ、または確保の失敗
pub fn check_thread_capability(thread_id: u64, cap_ptr: u64, cap_len: u64) -> u64 {
    // 過剰なコピーを避けるため、ここでは短い上限を設ける。
    // capability 名は固定の識別子であり、長大な文字列である必要がない。
    let max_cap_name_len = crate::config::kernel().capability.max_name_len;

    if thread_id == 0 {
        return Error::InvalidArgument.into_raw();
    }
    let name = match read_capability_name(cap_ptr, cap_len, max_cap_name_len) {
        Ok(name) => name,
        Err(error) => return error,
    };
    let Some(resolved_thread) = crate::syscall::ipc::resolve_sender_thread_id(thread_id) else {
        return 0;
    };
    let Some(pid) = crate::task::thread_to_process_id(resolved_thread) else {
        return 0;
    };
    match parse_capability_token(&name) {
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
        None => Error::InvalidArgument.into_raw(),
    }
}

/// capability の基本照会。
///
/// いまは文字列で指定された capability を caller が持つかだけを返す。
pub fn query(cap_ptr: u64, cap_len: u64) -> u64 {
    let max_cap_name_len = crate::config::kernel().capability.max_name_len;
    let name = match read_capability_name(cap_ptr, cap_len, max_cap_name_len) {
        Ok(name) => name,
        Err(error) => return error,
    };
    let Some(pid) = current_process() else {
        return Error::NotReady.into_raw();
    };
    match parse_capability_token(&name) {
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
        None => Error::InvalidArgument.into_raw(),
    }
}

pub fn clone_capability(_cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return Error::NotReady.into_raw(),
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
                Error::AccessDenied.into_raw()
            }
        }
        CapabilityToken::Authority(authority) => {
            if crate::task::process::process_has_kernel_authority(current, &authority) {
                SUCCESS
            } else {
                Error::AccessDenied.into_raw()
            }
        }
    }
}

pub fn drop_capability(_cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return Error::NotReady.into_raw(),
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
    });
    match removed {
        Some(true) => SUCCESS,
        Some(false) => Error::AccessDenied.into_raw(),
        None => Error::NotReady.into_raw(),
    }
}

pub fn transfer_capability(_dest: u64, _cap_ptr: u64, _cap_len: u64) -> u64 {
    let current = match current_process() {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let spec = match read_capability_spec_from_user(_cap_ptr, _cap_len) {
        Ok(spec) => spec,
        Err(e) => return e,
    };
    let dest_process = match resolve_destination_process(_dest) {
        Some(pid) => pid,
        None => return EINVAL,
    };

    let can_manage_capabilities =
        crate::task::process::process_has_capability(current, Capability::CapabilitiesManage);

    if can_manage_capabilities {
        let Some((cap_spec, claimed_exe_path)) = spec.split_once('\x1f') else {
            return EACCES;
        };
        if !crate::task::with_process(dest_process, |proc| proc.exe_path() == claimed_exe_path)
            .unwrap_or(false)
        {
            return EACCES;
        }
        if let Some((selected_path, rights)) = parse_scoped_path_grant(cap_spec) {
            // A native grant is explicit authority, not a POSIX pathname lookup.
            if !selected_path.starts_with('/') {
                return EINVAL;
            }
            return match path::grant_scoped_path(dest_process.as_u64(), selected_path, rights) {
                Ok(()) => SUCCESS,
                Err(_) => EINVAL,
            };
        }
        let cap = match intern_capability_token(cap_spec) {
            Some(cap) => cap,
            None => return EINVAL,
        };
        match cap {
            CapabilityToken::Plain(capability) => {
                if !capability.is_delegable() {
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

    let cap = match parse_capability_token(spec.as_str()) {
        Some(cap) => cap,
        None => return EINVAL,
    };

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
        None => return Error::NotReady.into_raw(),
    };
    let cap = match read_capability_token_from_user(_cap_ptr, _cap_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let restriction = match read_capability_token_from_user(_restriction_ptr, _restriction_len) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let changed = match (cap, restriction) {
        (CapabilityToken::Plain(cap), CapabilityToken::Plain(restriction)) => {
            if !crate::capability::capability_implies(cap, restriction) {
                return Error::AccessDenied.into_raw();
            }
            crate::task::with_process_mut(current, |proc| {
                let caps = proc.capabilities_mut();
                if !caps.contains_exact(cap) {
                    return Err(Error::AccessDenied);
                }
                if cap != restriction {
                    // Removal leaves capacity for the replacement in this Vec.
                    // Neither step allocates or escapes the process-table lock.
                    caps.remove(cap);
                    caps.insert(restriction);
                }
                Ok(())
            })
        }
        (CapabilityToken::Authority(cap), CapabilityToken::Authority(restriction)) => {
            if !kernel_authority_implies(&cap, &restriction) {
                return Error::AccessDenied.into_raw();
            }
            crate::task::with_process_mut(current, |proc| {
                let authorities = proc.kernel_authorities_mut();
                if !authorities.contains_exact(&cap) {
                    return Err(Error::AccessDenied);
                }
                if cap != restriction {
                    authorities.remove_exact(&cap);
                    authorities.insert(restriction);
                }
                Ok(())
            })
        }
        _ => return Error::InvalidArgument.into_raw(),
    };
    match changed {
        Some(Ok(())) => SUCCESS,
        Some(Err(error)) => error.into_raw(),
        None => Error::NotReady.into_raw(),
    }
}

fn current_process() -> Option<crate::task::ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
}

fn resolve_destination_process(dest: u64) -> Option<crate::task::ProcessId> {
    if let Some(thread_id) = crate::syscall::ipc::resolve_endpoint_handle(dest) {
        return crate::task::thread_to_process_id(thread_id);
    }
    let pid = crate::task::ProcessId::from_u64(dest);
    if crate::task::with_process(pid, |_| ()).is_some() {
        return Some(pid);
    }
    if let Some(pid) = crate::task::thread_to_process_id(dest) {
        return Some(pid);
    }
    None
}

fn read_capability_spec_from_user(cap_ptr: u64, cap_len: u64) -> Result<String, u64> {
    const MAX_TRANSFER_SPEC_LEN: usize = 8 * 1024;
    let max_cap_name_len = crate::config::kernel()
        .capability
        .max_name_len
        .max(MAX_TRANSFER_SPEC_LEN);
    read_capability_name(cap_ptr, cap_len, max_cap_name_len)
}

/// Copy once, before interpreting authority or mutating any grant. Converting
/// the owned byte buffer into UTF-8 reuses its allocation.
fn read_capability_name(cap_ptr: u64, cap_len: u64, maximum: usize) -> Result<String, u64> {
    if cap_len == 0 {
        return Err(Error::InvalidArgument.into_raw());
    }
    let length = usize::try_from(cap_len)
        .ok()
        .filter(|length| *length <= maximum && *length <= isize::MAX as usize)
        .ok_or(Error::LimitExceeded.into_raw())?;
    if cap_ptr == 0 || cap_ptr.checked_add(cap_len - 1).is_none() {
        return Err(Error::InvalidAddress.into_raw());
    }
    let mut bytes = crate::util::object_snapshot::zeroed_native(length).map_err(Error::into_raw)?;
    copy_from_user_native(cap_ptr, &mut bytes).map_err(Error::into_raw)?;
    String::from_utf8(bytes).map_err(|_| Error::InvalidArgument.into_raw())
}

fn parse_scoped_path_grant(spec: &str) -> Option<(&str, PathRights)> {
    let scoped = spec.strip_prefix("fs.scope.")?;
    let (mode, path) = scoped.split_once('@')?;
    if path.is_empty() || path.as_bytes().contains(&0) {
        return None;
    }
    let bits = match mode {
        "read" => PATH_READ | PATH_LIST,
        "read-write" => PATH_READ | PATH_LIST | PATH_WRITE | PATH_CREATE,
        _ => return None,
    };
    Some((path, PathRights::new(bits)))
}

fn parse_capability_token(spec: &str) -> Option<CapabilityToken> {
    if let Some(authority) = parse_kernel_authority_spec(spec) {
        return Some(CapabilityToken::Authority(authority));
    }
    Capability::from_str(spec).map(CapabilityToken::Plain)
}

fn intern_capability_token(spec: &str) -> Option<CapabilityToken> {
    if let Some(authority) = parse_kernel_authority_spec(spec) {
        return Some(CapabilityToken::Authority(authority));
    }
    Capability::intern(spec).map(CapabilityToken::Plain)
}

fn read_capability_token_from_user(cap_ptr: u64, cap_len: u64) -> Result<CapabilityToken, u64> {
    let spec = read_capability_spec_from_user(cap_ptr, cap_len)?;
    parse_capability_token(spec.as_str()).ok_or(Error::InvalidArgument.into_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_path_specs_are_explicit_and_bounded_to_one_path() {
        let (path, rights) =
            parse_scoped_path_grant("fs.scope.read-write@/home/alice/note.txt").unwrap();
        assert_eq!(path, "/home/alice/note.txt");
        assert!(rights.contains(PATH_READ | PATH_WRITE | PATH_CREATE));
        assert!(parse_scoped_path_grant("fs.scope.read@/").is_some());
        assert!(parse_scoped_path_grant("fs.scope.all@/home/alice").is_none());
    }
}
