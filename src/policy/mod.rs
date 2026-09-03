//! 起動ポリシーと manifest のカーネル側定義
//!
//! manifest のパースは userland 側で行い、kernel は検証と最終的な強制だけを持つ。

use core::sync::atomic::{AtomicU64, Ordering};

use crate::task::{PrivilegeLevel, ProcessId};

pub mod signature;

/// ブート時にカーネルが起動した init プロセスID
/// 0 は未登録。
static INIT_PID: AtomicU64 = AtomicU64::new(0);

/// 起動に必要な最小メタデータ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootLaunch {
    pub process_name: &'static str,
    pub exec_path: &'static str,
}

pub fn init_launch() -> BootLaunch {
    BootLaunch {
        process_name: "init",
        exec_path: "/init",
    }
}

pub fn register_init_pid(pid: u64) {
    INIT_PID.store(pid, Ordering::SeqCst);
}

pub fn init_pid() -> u64 {
    INIT_PID.load(Ordering::SeqCst)
}

pub fn claim_init_pid(pid: u64) -> bool {
    INIT_PID
        .compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn release_init_pid(pid: u64) -> bool {
    INIT_PID
        .compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

fn caller_pid() -> Option<ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
}

fn caller_is_service_or_core() -> bool {
    caller_pid()
        .and_then(|pid| crate::task::with_process(pid, |p| p.privilege()))
        .is_some_and(|lvl| matches!(lvl, PrivilegeLevel::Core | PrivilegeLevel::Service))
}

fn caller_has_process_spawn_capability() -> bool {
    caller_pid().is_some_and(|pid| {
        crate::task::with_process(pid, |p| {
            p.capabilities()
                .contains(crate::capability::Capability::ProcessSpawn)
        })
        .unwrap_or(false)
    })
}

/// 特権プロセスの起動を許可するか。
pub fn caller_can_launch_privileged() -> bool {
    let Some(caller_pid) = caller_pid() else {
        // カーネルコンテキストからの起動は許可
        return true;
    };

    let init_pid_raw = init_pid();
    if init_pid_raw != 0 && caller_pid.as_u64() == init_pid_raw {
        let init_pid = ProcessId::from_u64(init_pid_raw);
        return crate::task::with_process(init_pid, |p| {
            let state = p.state();
            let alive = state != crate::task::ProcessState::Zombie
                && state != crate::task::ProcessState::Terminated;
            let privileged = matches!(
                p.privilege(),
                PrivilegeLevel::Service | PrivilegeLevel::Core
            );
            alive && privileged
        })
        .unwrap_or(false);
    }

    caller_is_service_or_core() && caller_has_process_spawn_capability()
}

/// exec 時に capability を付与できるか
pub fn caller_can_grant_capabilities_on_exec() -> bool {
    caller_pid().is_none() || caller_is_service_or_core()
}

/// 呼び出し元が Service/Core か
pub fn caller_is_service_or_core_process() -> bool {
    caller_is_service_or_core()
}

/// exec に対して明示された privilege を最終的に決定する
///
/// カーネルは path から Service 権限を推測しない。
/// Service 権限を付与したい場合は、呼び出し側が明示的に要求する必要がある。
#[inline]
pub fn resolve_exec_privilege(requested_privilege: Option<PrivilegeLevel>) -> PrivilegeLevel {
    requested_privilege.unwrap_or(PrivilegeLevel::User)
}
