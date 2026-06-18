//! 起動ポリシーと manifest のカーネル側定義
//!
//! manifest のパースは userland 側で行い、kernel は検証と最終的な強制だけを持つ。

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::task::{PrivilegeLevel, ProcessId};

pub mod signature;

/// `.service` 実行を許可するサービスマネージャープロセスID
/// 0 は未登録。
static SERVICE_MANAGER_PID: AtomicU64 = AtomicU64::new(0);

/// manifest 上の役割
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestRole {
    CoreService,
    Service,
    Application,
    Driver,
    Tool,
    Unknown,
}

/// インストール元
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Initfs,
    Rootfs,
    BuiltIn,
    PackageStore,
    RemovableMedia,
    Network,
    Debug,
    Unknown,
}

/// userland が manifest を解釈して kernel に渡す起動情報
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub package_id: String,
    pub publisher_id: String,
    pub signature_trusted: bool,
    pub manifest_role: ManifestRole,
    pub file_digest: [u8; 32],
    pub install_source: InstallSource,
}

/// launch policy の最終結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchPolicy {
    pub privilege: PrivilegeLevel,
    pub priority: u8,
    pub foreground: bool,
}

/// 起動に必要な最小メタデータ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootLaunch {
    pub process_name: &'static str,
    pub exec_path: &'static str,
    pub manifest_role: ManifestRole,
}

pub fn service_manager_launch() -> BootLaunch {
    BootLaunch {
        process_name: "core.service",
        exec_path: "core.service",
        manifest_role: ManifestRole::CoreService,
    }
}

#[inline]
fn role_priority(role: ManifestRole) -> u8 {
    match role {
        ManifestRole::Application => 0,
        ManifestRole::Tool => 2,
        ManifestRole::Service => 64,
        ManifestRole::CoreService => 24,
        ManifestRole::Driver => 160,
        ManifestRole::Unknown => 8,
    }
}

/// サービスマネージャーPIDを登録する（IDベース認可）
pub fn register_service_manager_pid(pid: u64) {
    SERVICE_MANAGER_PID.store(pid, Ordering::SeqCst);
}

/// サービスマネージャーPIDを取得する
pub fn service_manager_pid() -> u64 {
    SERVICE_MANAGER_PID.load(Ordering::SeqCst)
}

/// 既存の登録がない場合のみサービスマネージャーPIDを確保する
pub fn claim_service_manager_pid(pid: u64) -> bool {
    SERVICE_MANAGER_PID
        .compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// 登録済みのサービスマネージャーPIDを解除する
pub fn release_service_manager_pid(pid: u64) -> bool {
    SERVICE_MANAGER_PID
        .compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

fn caller_pid() -> Option<ProcessId> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
}

fn caller_is_core() -> bool {
    caller_pid()
        .and_then(|pid| crate::task::with_process(pid, |p| p.privilege()))
        .is_some_and(|lvl| lvl == PrivilegeLevel::Core)
}

fn caller_is_service_or_core() -> bool {
    caller_pid()
        .and_then(|pid| crate::task::with_process(pid, |p| p.privilege()))
        .is_some_and(|lvl| matches!(lvl, PrivilegeLevel::Core | PrivilegeLevel::Service))
}

/// `.service` 実行を許可するか
pub fn caller_can_launch_service() -> bool {
    let Some(caller_pid) = caller_pid() else {
        // カーネルコンテキストからの起動は許可
        return true;
    };

    let manager_pid_raw = service_manager_pid();
    if manager_pid_raw == 0 || caller_pid.as_u64() != manager_pid_raw {
        return false;
    }
    let manager_pid = ProcessId::from_u64(manager_pid_raw);
    crate::task::with_process(manager_pid, |p| {
        let state = p.state();
        let alive = state != crate::task::ProcessState::Zombie
            && state != crate::task::ProcessState::Terminated;
        let privileged = matches!(
            p.privilege(),
            PrivilegeLevel::Service | PrivilegeLevel::Core
        );
        alive && privileged
    })
    .unwrap_or(false)
}

/// exec 時に capability を付与できるか
pub fn caller_can_grant_capabilities_on_exec() -> bool {
    let Some(caller_pid) = caller_pid() else {
        // カーネルコンテキストは許可
        return true;
    };

    let manager_pid_raw = service_manager_pid();
    manager_pid_raw != 0 && caller_pid.as_u64() == manager_pid_raw
}

/// manifest role を privilege に落とす
#[inline]
pub fn resolve_launch_privilege(
    _role: ManifestRole,
    _install_source: InstallSource,
) -> PrivilegeLevel {
    PrivilegeLevel::User
}

/// manifest role を priority に落とす
#[inline]
pub fn resolve_launch_priority(
    role: ManifestRole,
    _install_source: InstallSource,
    _parent_pid: Option<ProcessId>,
) -> u8 {
    role_priority(role)
}

/// manifest role を foreground 判定に落とす
#[inline]
pub fn resolve_launch_foreground(
    role: ManifestRole,
    privilege: PrivilegeLevel,
    _parent_pid: Option<ProcessId>,
) -> bool {
    privilege == PrivilegeLevel::User
        && matches!(role, ManifestRole::Application | ManifestRole::Tool)
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

/// 現行の exec policy を priority に落とす
#[inline]
pub fn resolve_exec_priority(
    process_name: &str,
    exec_path: &str,
    parent_pid: Option<ProcessId>,
) -> u8 {
    let is_driver_path =
        exec_path.starts_with("/bin/drivers/") || exec_path.starts_with("bin/drivers/");
    let is_application_path =
        exec_path.starts_with("/applications/") || exec_path.starts_with("applications/");
    let is_regular_bin_path = exec_path.starts_with("/bin/") || exec_path.starts_with("bin/");

    if is_application_path {
        return 0;
    }
    if is_regular_bin_path && !is_driver_path {
        return 2;
    }
    if is_driver_path {
        return 160;
    }
    if process_name.ends_with(".service") {
        return 64;
    }

    if let Some(parent) = parent_pid {
        let parent_name = crate::task::with_process(parent, |process| {
            let mut name = String::new();
            name.push_str(process.name());
            name
        });
        if parent_name.is_some() {
            return 8;
        }
    }

    8
}

/// 現行の exec policy を foreground 判定に落とす
#[inline]
pub fn resolve_exec_foreground(
    process_name: &str,
    exec_path: &str,
    privilege: PrivilegeLevel,
    parent_pid: Option<ProcessId>,
) -> bool {
    if privilege != PrivilegeLevel::User {
        return false;
    }

    let is_application_path =
        exec_path.starts_with("/applications/") || exec_path.starts_with("applications/");
    let is_regular_bin_path = (exec_path.starts_with("/bin/") || exec_path.starts_with("bin/"))
        && !exec_path.starts_with("/bin/drivers/")
        && !exec_path.starts_with("bin/drivers/");

    if is_application_path || is_regular_bin_path {
        return true;
    }

    let Some(parent) = parent_pid else {
        return false;
    };
    crate::task::with_process(parent, |process| process.is_foreground()).unwrap_or(false)
}
