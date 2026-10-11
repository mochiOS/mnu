//! タスク関連システムコール

use super::types::{EFAULT, EINVAL, ENOMEM, ENOSYS};

pub fn yield_now() -> u64 {
    crate::task::yield_now();
    0
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
pub fn thread_create(context_ptr: u64, context_len: u64) -> u64 {
    if context_ptr == 0
        || context_len != core::mem::size_of::<mnu_abi::ThreadCreateContext>() as u64
    {
        return EINVAL;
    }
    let mut context = mnu_abi::ThreadCreateContext::default();
    let context_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut context as *mut mnu_abi::ThreadCreateContext).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ThreadCreateContext>(),
        )
    };
    if crate::syscall::copy_from_user(context_ptr, context_bytes).is_err() {
        return EFAULT;
    }
    if context.entry == 0
        || context.stack_pointer < 16
        || context.flags != 0
        || context.reserved != [0; 3]
    {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(context.entry, 1)
        || !crate::syscall::validate_user_ptr(context.stack_pointer - 16, 16)
        || (context.thread_local_base != 0
            && !crate::syscall::validate_user_ptr(context.thread_local_base, 8))
    {
        return EFAULT;
    }
    let current_tid = match crate::task::current_thread_id() {
        Some(tid) => tid,
        None => return ENOSYS,
    };
    let pid = match crate::task::with_thread(current_tid, |t| t.process_id()) {
        Some(pid) => pid,
        None => return ENOSYS,
    };
    let Some(_creation) = crate::task::image_transition::begin_thread_creation(pid) else {
        return super::types::EAGAIN;
    };
    let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
    let page_table = crate::task::with_process(pid, |process| process.page_table())
        .flatten()
        .unwrap_or(0);
    let kstack = match crate::task::allocate_kernel_stack_in_table(kstack_size, page_table) {
        Some(a) => a,
        None => return ENOMEM,
    };
    let registers = context.registers;
    let user_context = crate::task::thread::SyscallUserContext {
        rip: context.entry,
        rsp: context.stack_pointer,
        rflags: 0x202,
        rdi: context.argument,
        rsi: registers.rsi,
        rdx: registers.rdx,
        r8: registers.r8,
        r9: registers.r9,
        r10: registers.r10,
        rbp: registers.rbp,
        rbx: registers.rbx,
        r12: registers.r12,
        r13: registers.r13,
        r14: registers.r14,
        r15: registers.r15,
        rcx: registers.rcx,
        r11: registers.r11,
    };
    let thread = crate::task::Thread::new_user_resume(
        pid,
        user_context,
        registers.rax,
        context.thread_local_base,
        kstack,
        kstack_size,
    );
    match crate::task::add_thread(thread) {
        Some(tid) => tid.as_u64(),
        None => {
            crate::task::free_kernel_stack(kstack);
            ENOSYS
        }
    }
}
