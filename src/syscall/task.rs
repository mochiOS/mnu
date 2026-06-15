//! タスク関連システムコール

use super::types::{EACCES, EFAULT, EINVAL, ENOMEM, ENOSYS};

pub fn yield_now() -> u64 {
    crate::task::yield_now();
    0
}

/// 現在のスレッドを終了
pub fn exit(_code: u64) -> u64 {
    if let Some(id) = crate::task::current_thread_id() {
        crate::task::terminate_thread(id);
        0
    } else {
        EINVAL
    }
}

/// 現在のスレッドIDを取得
pub fn get_thread_id() -> u64 {
    match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => EINVAL,
    }
}

/// スレッドIDからプロセスの権限レベルを取得
///
/// # 引数
/// - `tid_val`: スレッドID (u64)
///
/// # 戻り値
/// 0=Core, 1=Service, 2=User, またはエラー (#22: ディスクサービスの特権検証に使用)
pub fn get_thread_privilege(tid_val: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) && !crate::syscall::security::caller_is_core()
    {
        return super::types::EPERM;
    }

    // スレッドIDに対応するプロセスIDを探す
    let mut found_pid: Option<crate::task::ProcessId> = None;
    crate::task::for_each_thread(|t| {
        if found_pid.is_none() && t.id().as_u64() == tid_val {
            found_pid = Some(t.process_id());
        }
    });

    let pid = match found_pid {
        Some(p) => p,
        None => return EINVAL,
    };

    match crate::task::with_process(pid, |p| p.privilege()) {
        Some(crate::task::PrivilegeLevel::Core) => 0,
        Some(crate::task::PrivilegeLevel::Service) => 1,
        Some(crate::task::PrivilegeLevel::User) => 2,
        None => EINVAL,
    }
}

/// スレッド名からIDを取得
pub fn get_thread_id_by_name(name_ptr: u64, name_len: u64) -> u64 {
    const MAX_NAME_LEN: usize = 64;
    if name_ptr == 0 {
        return EINVAL;
    }
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) && !crate::syscall::security::caller_is_core()
    {
        return super::types::EPERM;
    }
    let name_len = name_len as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return EINVAL;
    }
    let mut name_buf = [0u8; MAX_NAME_LEN];
    if crate::syscall::copy_from_user(name_ptr, &mut name_buf[..name_len]).is_err() {
        return EFAULT;
    }
    let name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    let mut found: Option<u64> = None;
    crate::task::for_each_thread(|t| {
        if found.is_none() && t.name() == name {
            found = Some(t.id().as_u64());
        }
    });

    found.unwrap_or_else(|| crate::syscall::ENOENT)
}

/// thread_create syscall.
///
/// Creates a new usermode thread in the current process. Returns the new TID or an errno.
pub fn thread_create(entry: u64, stack: u64, arg0: u64) -> u64 {
    if entry == 0 || stack == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(entry, 1) || !crate::syscall::validate_user_ptr(stack, 16)
    {
        return EFAULT;
    }
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessSpawn,
    ]) && !crate::syscall::security::caller_is_core()
    {
        return EACCES;
    }

    let current_tid = match crate::task::current_thread_id() {
        Some(tid) => tid,
        None => return ENOSYS,
    };
    let pid = match crate::task::with_thread(current_tid, |t| t.process_id()) {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
    let kstack = match crate::task::allocate_kernel_stack(kstack_size) {
        Some(a) => a,
        None => return ENOMEM,
    };
    let mut thread =
        crate::task::Thread::new_usermode(pid, "thread", entry, stack, arg0, kstack, kstack_size);
    if let Some(fs_base) = crate::task::with_thread(current_tid, |t| t.fs_base()) {
        thread.set_fs_base(fs_base);
    }
    match crate::task::add_thread(thread) {
        Some(tid) => tid.as_u64(),
        None => ENOSYS,
    }
}
