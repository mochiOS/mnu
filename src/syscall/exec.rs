use crate::capability::{
    parse_kernel_authority_spec, Capability, CapabilitySet, KernelAuthoritySet,
};
use crate::policy::{
    caller_can_grant_capabilities_on_exec, claim_init_pid, release_init_pid,
    resolve_exec_privilege, ManifestRole,
};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

mod image;

use image::{map_elf_image, ElfImageLayout};

use mnu_abi::exec::{ENVIRONMENT_PREFIX, SECURITY_IDENTITY_PREFIX};
static EXEC_ASLR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct InitialUserStack {
    stack_base_vaddr: u64,
    stack_end_vaddr: u64,
    initial_rsp: u64,
    page_data: Vec<u8>,
}

struct ExecMeasurement {
    #[cfg(feature = "performance-instrumentation")]
    started: u64,
    #[cfg(feature = "performance-instrumentation")]
    parse_cycles: u64,
    #[cfg(feature = "performance-instrumentation")]
    load_cycles: u64,
}

impl ExecMeasurement {
    #[inline]
    fn start() -> Self {
        Self {
            #[cfg(feature = "performance-instrumentation")]
            started: crate::performance::timestamp(),
            #[cfg(feature = "performance-instrumentation")]
            parse_cycles: 0,
            #[cfg(feature = "performance-instrumentation")]
            load_cycles: 0,
        }
    }

    #[inline]
    fn parse<T>(&mut self, operation: impl FnOnce() -> T) -> T {
        #[cfg(feature = "performance-instrumentation")]
        let started = crate::performance::timestamp();
        let result = operation();
        #[cfg(feature = "performance-instrumentation")]
        {
            self.parse_cycles = self
                .parse_cycles
                .saturating_add(crate::performance::elapsed_cycles(started));
        }
        result
    }

    #[inline]
    fn load<T>(&mut self, operation: impl FnOnce() -> T) -> T {
        #[cfg(feature = "performance-instrumentation")]
        let started = crate::performance::timestamp();
        let result = operation();
        #[cfg(feature = "performance-instrumentation")]
        {
            self.load_cycles = self
                .load_cycles
                .saturating_add(crate::performance::elapsed_cycles(started));
        }
        result
    }

    #[inline]
    fn finish(self, result: u64) -> u64 {
        if result & (1 << 63) == 0 {
            self.record();
        }
        result
    }

    #[inline]
    fn record(self) {
        #[cfg(feature = "performance-instrumentation")]
        {
            crate::performance::record_latency_cycles(
                crate::performance::LatencyMetric::ExecParse,
                self.parse_cycles,
            );
            crate::performance::record_latency_cycles(
                crate::performance::LatencyMetric::ExecLoad,
                self.load_cycles,
            );
            crate::performance::record_latency(
                crate::performance::LatencyMetric::ExecEntry,
                self.started,
            );
        }
    }
}

struct UserPageTableGuard(Option<u64>);

impl UserPageTableGuard {
    fn new(table_phys: u64) -> Self {
        Self(Some(table_phys))
    }

    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for UserPageTableGuard {
    fn drop(&mut self) {
        if let Some(table_phys) = self.0.take() {
            let _ = crate::mem::paging::destroy_user_page_table(table_phys);
        }
    }
}

fn mapping_error_errno(error: crate::Kernel) -> u64 {
    match error {
        crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => crate::syscall::types::ENOMEM,
        _ => crate::syscall::types::EINVAL,
    }
}

#[inline]
fn aslr_mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

pub(crate) fn next_aslr_seed(tag: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for b in tag.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    if EXEC_ASLR_COUNTER.load(Ordering::Relaxed) == 0 {
        let mut init = crate::cpu::boot_entropy_u64() ^ 0x7c4a_7f73_d3e1_9b1d;
        if init == 0 {
            init = 1;
        }
        let _ = EXEC_ASLR_COUNTER.compare_exchange(0, init, Ordering::SeqCst, Ordering::Relaxed);
    }
    let ctr = EXEC_ASLR_COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let ticks = crate::interrupt::timer::get_ticks();
    let tid = crate::task::current_thread_id()
        .map(|t| t.as_u64())
        .unwrap_or(0);
    let hw = crate::cpu::hw_random_u64().unwrap_or(0);
    let boot = crate::cpu::boot_entropy_u64();
    aslr_mix64(hash ^ ctr ^ ticks.rotate_left(17) ^ tid.rotate_left(7) ^ hw.rotate_left(29) ^ boot)
}

#[inline]
fn aslr_offset_pages(seed: u64, max_pages: u64) -> u64 {
    if max_pages == 0 {
        0
    } else {
        aslr_mix64(seed) % max_pages
    }
}

fn read_nul_args_from_user(
    args_ptr: u64,
    max_total_bytes: usize,
    max_args: usize,
) -> Result<Vec<String>, u64> {
    use crate::syscall::types::EINVAL;

    if args_ptr == 0 {
        return Ok(Vec::new());
    }
    let mut storage = alloc::vec![0u8; max_total_bytes];
    crate::syscall::copy_from_user(args_ptr, &mut storage)?;
    if let Some(end) = storage.windows(2).position(|w| w == [0, 0]) {
        storage.truncate(end + 2);
    }

    let mut out = Vec::new();
    for s in storage.split(|&b| b == 0) {
        if s.is_empty() {
            continue;
        }
        let text = core::str::from_utf8(s).map_err(|_| EINVAL)?;
        out.push(String::from(text));
        if out.len() >= max_args {
            break;
        }
    }
    Ok(out)
}

fn read_nul_caps_from_user(caps_ptr: u64, caps_total_len: u64) -> Result<Vec<String>, u64> {
    use crate::syscall::types::EINVAL;

    if caps_total_len == 0 {
        return Ok(Vec::new());
    }
    if caps_ptr == 0 {
        return Err(EINVAL);
    }
    let Ok(len) = usize::try_from(caps_total_len) else {
        return Err(EINVAL);
    };
    if len > 1024 {
        return Err(EINVAL);
    }

    let mut storage = alloc::vec![0u8; len];
    crate::syscall::copy_from_user(caps_ptr, &mut storage)?;

    // cap 名は NUL 区切りで渡す。末尾の NUL は任意だが、無くても split が動くようにする。
    let mut out = Vec::new();
    for s in storage.split(|&b| b == 0) {
        if s.is_empty() {
            continue;
        }
        let text = core::str::from_utf8(s).map_err(|_| EINVAL)?;
        out.push(text.to_string());
        if out.len() >= 128 {
            break;
        }
    }
    Ok(out)
}

fn caller_has_process_spawn_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[Capability::ProcessSpawn])
}

fn current_process_capabilities() -> Option<CapabilitySet> {
    let pid = crate::syscall::security::current_process_id()?;
    crate::task::with_process(pid, |proc| proc.capabilities().clone())
}

fn current_process_kernel_authorities() -> Option<KernelAuthoritySet> {
    let pid = crate::syscall::security::current_process_id()?;
    crate::task::with_process(pid, |proc| proc.kernel_authorities().clone())
}

fn parse_requested_exec_grants(
    caps_list: &[String],
) -> Result<(CapabilitySet, KernelAuthoritySet), u64> {
    use crate::syscall::types::EINVAL;

    let mut caps = CapabilitySet::empty();
    let mut authorities = KernelAuthoritySet::empty();
    for spec in caps_list {
        if let Some(authority) = parse_kernel_authority_spec(spec.as_str()) {
            authorities.insert(authority);
            continue;
        }
        let Some(cap) = Capability::from_str(spec.as_str()) else {
            return Err(EINVAL);
        };
        if matches!(cap, Capability::MemoryPhysMap) {
            return Err(EINVAL);
        }
        caps.insert(cap);
    }
    Ok((caps, authorities))
}

fn validate_requested_exec_capabilities(
    caps: &CapabilitySet,
    authorities: &KernelAuthoritySet,
) -> Result<(), u64> {
    use crate::syscall::types::{EINVAL, EPERM};

    for cap in caps.iter() {
        if !cap.is_kernel_enforced() {
            return Err(EINVAL);
        }
    }

    let Some(caller_caps) = current_process_capabilities() else {
        return Ok(());
    };
    let caller_authorities = current_process_kernel_authorities().unwrap_or_default();

    let caller_can_manage_capabilities =
        caller_caps.contains(crate::capability::Capability::CapabilitiesManage);
    if !caller_can_manage_capabilities && !caps.is_subset_of(&caller_caps) {
        return Err(EPERM);
    }
    if !authorities.is_subset_of(&caller_authorities) {
        return Err(EPERM);
    }
    Ok(())
}

fn parse_manifest_role(raw: u64) -> Option<ManifestRole> {
    ManifestRole::from_raw(raw)
}

/// カーネル内から実行可能ファイルを読み込み実行するシステムコール
/// args_ptr: ヌル区切り引数文字列へのポインタ（"arg1\0arg2\0\0"形式）、0 なら引数なし
pub fn exec_kernel(path_ptr: u64, args_ptr: u64) -> u64 {
    if !caller_has_process_spawn_capability() {
        return crate::syscall::types::EPERM;
    }

    let mut provided_path: Option<String> = None;
    if path_ptr != 0 {
        let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
            Ok(s) => s,
            Err(_) => return crate::syscall::types::EINVAL,
        };
        provided_path = Some(path);
    }
    let path = provided_path.as_deref().unwrap_or("/tmp/hello.bin");

    let extra_args_owned = match read_nul_args_from_user(args_ptr, 512, 64) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let extra_args: Vec<&str> = extra_args_owned.iter().map(|s| s.as_str()).collect();
    exec_internal(
        path,
        None,
        &extra_args,
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        true,
    )
}

/// exec 時に capability を付与して起動する
///
/// この syscall は「プロセスの capability を外部から設定できる経路」になるため、
/// 呼び出し元は信頼済みの起動経路に限定する。
///
/// `caps_ptr` は NUL 区切りの capability 名列（例: `b"fs.read.user\\0window.create\\0"`）を指す。
pub fn exec_with_capabilities_syscall(
    path_ptr: u64,
    args_ptr: u64,
    caps_ptr: u64,
    caps_total_len: u64,
) -> u64 {
    use crate::syscall::types::{EINVAL, EPERM};

    if !caller_can_grant_capabilities_on_exec() {
        return EPERM;
    }
    if !caller_has_process_spawn_capability() {
        return EPERM;
    }

    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    // 引数は通常 exec と同じ形式
    let extra_args_owned = match read_nul_args_from_user(args_ptr, 512, 64) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let extra_args: Vec<&str> = extra_args_owned.iter().map(|s| s.as_str()).collect();

    // capability リストを読み取り、カーネル内の enum へ変換する
    let caps_list = match read_nul_caps_from_user(caps_ptr, caps_total_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (caps, authorities) = match parse_requested_exec_grants(&caps_list) {
        Ok(grants) => grants,
        Err(errno) => return errno,
    };

    if let Err(errno) = validate_requested_exec_capabilities(&caps, &authorities) {
        return errno;
    }

    // capability はプロセス生成時に設定する必要がある。
    // 後付けだと、スケジューラ有効時に起動直後の IPC 等が cap 無しで走り得る。
    exec_internal(
        path.as_str(),
        None,
        &extra_args,
        &[],
        Some(caps),
        Some(authorities),
        None,
        None,
        None,
        None,
        None,
        true,
    )
}

pub fn exec_manifest_syscall(
    path_ptr: u64,
    args_ptr: u64,
    caps_ptr: u64,
    caps_total_len: u64,
    role_raw: u64,
) -> u64 {
    exec_manifest_common(
        path_ptr,
        args_ptr,
        caps_ptr,
        caps_total_len,
        role_raw,
        None,
        None,
    )
}

pub fn exec_manifest_with_credentials_syscall(
    path_ptr: u64,
    args_ptr: u64,
    caps_ptr: u64,
    caps_total_len: u64,
    request_ptr: u64,
) -> u64 {
    use crate::syscall::types::{EFAULT, EINVAL, EPERM};

    const REQUEST_LEN: u64 = 24;
    if request_ptr == 0 || !crate::syscall::validate_user_ptr(request_ptr, REQUEST_LEN) {
        return EFAULT;
    }
    let mut request = [0u8; REQUEST_LEN as usize];
    if let Err(errno) = crate::syscall::copy_from_user(request_ptr, &mut request) {
        return errno;
    }
    let role_raw = u64::from_le_bytes([
        request[0], request[1], request[2], request[3], request[4], request[5], request[6],
        request[7],
    ]);
    let uid = u32::from_le_bytes([request[8], request[9], request[10], request[11]]);
    let gid = u32::from_le_bytes([request[12], request[13], request[14], request[15]]);
    let reserved = u64::from_le_bytes([
        request[16],
        request[17],
        request[18],
        request[19],
        request[20],
        request[21],
        request[22],
        request[23],
    ]);
    if reserved != 0 {
        return EINVAL;
    }
    if !caller_has_process_spawn_capability()
        || !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::CapabilitiesManage,
        ])
    {
        return EPERM;
    }

    exec_manifest_common(
        path_ptr,
        args_ptr,
        caps_ptr,
        caps_total_len,
        role_raw,
        Some(crate::task::ProcessCredentials::user(uid, gid)),
        None,
    )
}

pub fn exec_manifest_for_requester_syscall(
    path_ptr: u64,
    args_ptr: u64,
    caps_ptr: u64,
    caps_total_len: u64,
    request_ptr: u64,
) -> u64 {
    use crate::syscall::types::{EFAULT, EINVAL, EPERM};

    const REQUEST_LEN: u64 = 24;
    if request_ptr == 0 || !crate::syscall::validate_user_ptr(request_ptr, REQUEST_LEN) {
        return EFAULT;
    }
    let mut request = [0u8; REQUEST_LEN as usize];
    if let Err(errno) = crate::syscall::copy_from_user(request_ptr, &mut request) {
        return errno;
    }
    let role_raw = u64::from_le_bytes([
        request[0], request[1], request[2], request[3], request[4], request[5], request[6],
        request[7],
    ]);
    let requester_tid = u64::from_le_bytes([
        request[8],
        request[9],
        request[10],
        request[11],
        request[12],
        request[13],
        request[14],
        request[15],
    ]);
    let reserved = u64::from_le_bytes([
        request[16],
        request[17],
        request[18],
        request[19],
        request[20],
        request[21],
        request[22],
        request[23],
    ]);
    if requester_tid == 0 || reserved != 0 {
        return EINVAL;
    }
    if !caller_has_process_spawn_capability()
        || !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::CapabilitiesManage,
        ])
    {
        return EPERM;
    }

    let Some(requester_tid) = crate::syscall::ipc::resolve_sender_thread_id(requester_tid) else {
        return EINVAL;
    };
    let requester = crate::task::ThreadId::from_u64(requester_tid);
    let Some(requester_pid) = crate::task::with_thread(requester, |thread| thread.process_id())
    else {
        return EINVAL;
    };
    if !crate::task::process::process_has_capability(
        requester_pid,
        crate::capability::Capability::ProcessSpawn,
    ) {
        return EPERM;
    }
    let Some(credentials) =
        crate::task::with_process(requester_pid, |process| process.credentials())
    else {
        return EINVAL;
    };

    exec_manifest_common(
        path_ptr,
        args_ptr,
        caps_ptr,
        caps_total_len,
        role_raw,
        Some(credentials),
        Some(requester_pid),
    )
}

fn exec_manifest_common(
    path_ptr: u64,
    args_ptr: u64,
    caps_ptr: u64,
    caps_total_len: u64,
    role_raw: u64,
    credentials: Option<crate::task::ProcessCredentials>,
    parent_override: Option<crate::task::ProcessId>,
) -> u64 {
    use crate::syscall::types::{EACCES, EINVAL, EPERM};

    let Some(role) = parse_manifest_role(role_raw) else {
        return EINVAL;
    };
    let allowed = match role {
        ManifestRole::CoreService | ManifestRole::Service => {
            crate::policy::caller_can_launch_service()
        }
        ManifestRole::Driver => crate::policy::caller_can_launch_driver(),
        ManifestRole::Application | ManifestRole::Tool | ManifestRole::Unknown => {
            caller_has_process_spawn_capability()
        }
    };
    if !allowed {
        crate::warn!(
            "exec_manifest denied role={:?} caller.service_or_core={} caller.process.spawn={}",
            role,
            crate::policy::caller_is_service_or_core_process(),
            caller_has_process_spawn_capability()
        );
        return EACCES;
    }

    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    let extra_args_owned = match read_nul_args_from_user(args_ptr, 512, 64) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut extra_args: Vec<&str> = Vec::new();
    let mut envp: Vec<&str> = Vec::new();
    let mut security_identity: Option<&str> = None;
    for item in &extra_args_owned {
        if let Some(env) = item.strip_prefix(ENVIRONMENT_PREFIX) {
            if env.is_empty() || !env.contains('=') {
                return EINVAL;
            }
            envp.push(env);
        } else if let Some(value) = item.strip_prefix(SECURITY_IDENTITY_PREFIX) {
            if security_identity.is_some() || !valid_security_identity(value) {
                return EINVAL;
            }
            security_identity = Some(value);
        } else {
            extra_args.push(item.as_str());
        }
    }

    if !caller_can_grant_capabilities_on_exec() {
        crate::warn!(
            "exec_manifest capability grant denied role={:?} caller.service_or_core={} caller.process.spawn={}",
            role,
            crate::policy::caller_is_service_or_core_process(),
            caller_has_process_spawn_capability()
        );
        return EPERM;
    }
    let caps_list = match read_nul_caps_from_user(caps_ptr, caps_total_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (caps, authorities) = match parse_requested_exec_grants(&caps_list) {
        Ok(grants) => grants,
        Err(errno) => return errno,
    };
    if let Err(errno) = validate_requested_exec_capabilities(&caps, &authorities) {
        crate::warn!(
            "exec_manifest capability validation failed requested_caps={} requested_authorities={} caller_caps={} caller_authorities={}",
            caps.len(),
            authorities.len(),
            current_process_capabilities().map(|c| c.len()).unwrap_or(0),
            current_process_kernel_authorities()
                .map(|a| a.len())
                .unwrap_or(0)
        );
        return errno;
    }

    let requested_privilege = match role {
        ManifestRole::CoreService | ManifestRole::Service => {
            Some(crate::task::PrivilegeLevel::Service)
        }
        _ => Some(crate::task::PrivilegeLevel::User),
    };

    exec_internal(
        path.as_str(),
        None,
        &extra_args,
        &envp,
        Some(caps),
        Some(authorities),
        credentials,
        requested_privilege,
        Some(role),
        parent_override,
        security_identity,
        true,
    )
}

fn valid_security_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

/// 名前を指定してカーネル内から実行可能ファイルを実行する（カーネル内部用）
pub fn exec_kernel_with_name(path: &str, name: &str) -> u64 {
    exec_internal(
        path,
        Some(name),
        &[],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
    )
}

/// 名前と初期 capability を指定してカーネル内から実行可能ファイルを実行する（カーネル内部用）
pub fn exec_kernel_with_name_and_caps(
    path: &str,
    name: &str,
    initial_caps: CapabilitySet,
    requested_privilege: crate::task::PrivilegeLevel,
) -> u64 {
    exec_kernel_with_name_caps_and_authorities(
        path,
        name,
        initial_caps,
        KernelAuthoritySet::empty(),
        requested_privilege,
    )
}

pub fn exec_kernel_with_name_caps_and_authorities(
    path: &str,
    name: &str,
    initial_caps: CapabilitySet,
    initial_kernel_authorities: KernelAuthoritySet,
    requested_privilege: crate::task::PrivilegeLevel,
) -> u64 {
    let manifest_role = match requested_privilege {
        crate::task::PrivilegeLevel::Core => Some(ManifestRole::CoreService),
        crate::task::PrivilegeLevel::Service => Some(ManifestRole::Service),
        _ => Some(ManifestRole::Unknown),
    };
    exec_internal(
        path,
        Some(name),
        &[],
        &[],
        Some(initial_caps),
        Some(initial_kernel_authorities),
        None,
        Some(requested_privilege),
        manifest_role,
        None,
        None,
        false,
    )
}

fn exec_internal(
    path: &str,
    name_override: Option<&str>,
    args: &[&str],
    envp: &[&str],
    initial_caps: Option<CapabilitySet>,
    initial_kernel_authorities: Option<KernelAuthoritySet>,
    requested_credentials: Option<crate::task::ProcessCredentials>,
    requested_privilege: Option<crate::task::PrivilegeLevel>,
    manifest_role: Option<ManifestRole>,
    parent_override: Option<crate::task::ProcessId>,
    security_identity: Option<&str>,
    enforce_path_access: bool,
) -> u64 {
    let mut measurement = ExecMeasurement::start();
    let mut process_name = name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| derive_process_name(path));
    if let Some(alias) = crate::task::process::process_alias_for_executable(path) {
        process_name = alias;
    }
    let role = manifest_role.unwrap_or(ManifestRole::Unknown);
    if enforce_path_access {
        let access_process = parent_override.or_else(|| {
            crate::task::current_thread_id()
                .and_then(|tid| crate::task::with_thread(tid, |thread| thread.process_id()))
        });
        if let Some(pid) = access_process {
            if let Err(errno) = crate::syscall::fs::ensure_fs_path_executable_for_process(path, pid)
            {
                return errno;
            }
        }
    }
    if let Some((data, source)) = load_exec_image(path, role) {
        if enforce_path_access && !crate::policy::signature::verify_exec(path, &data) {
            crate::warn!("exec: signature verification failed for '{}'", path);
            return crate::syscall::types::EPERM;
        }
        crate::info!(
            "exec: loaded '{}' from {} ({} bytes)",
            path,
            source,
            data.len()
        );
        let result = exec_with_data(
            &data,
            &process_name,
            path,
            args,
            envp,
            parent_override,
            initial_caps,
            initial_kernel_authorities,
            requested_credentials,
            requested_privilege,
            security_identity,
            &mut measurement,
        );
        measurement.finish(result)
    } else {
        crate::warn!("exec: file not found: {}", path);
        crate::syscall::types::ENOENT
    }
}

fn load_exec_image(path: &str, role: ManifestRole) -> Option<(Vec<u8>, &'static str)> {
    let loaded = load_regular_exec_image(path, role)?;
    crate::performance::increment(
        crate::performance::CounterMetric::ExecutableBytesRead,
        loaded.0.len() as u64,
    );
    Some(loaded)
}

fn load_regular_exec_image(path: &str, role: ManifestRole) -> Option<(Vec<u8>, &'static str)> {
    if matches!(role, ManifestRole::CoreService | ManifestRole::Service) {
        if let Some(data) = crate::init::fs::read_initfs(path) {
            return Some((data, "initfs"));
        }
        if let Some(data) = crate::cext::fs::read_all(path) {
            return Some((data, "cext"));
        }
        if let Some(data) = crate::init::fs::read_rootfs(path) {
            return Some((data, "rootfs"));
        }
        if let Some(data) = crate::init::fs::read(path) {
            return Some((data, "fallback"));
        }
        None
    } else {
        if let Some(data) = crate::init::fs::read_rootfs(path) {
            return Some((data, "rootfs"));
        }
        if let Some(data) = crate::cext::fs::read_all(path) {
            return Some((data, "cext"));
        }
        if let Some(data) = crate::init::fs::read(path) {
            return Some((data, "fallback"));
        }
        None
    }
}

fn derive_process_name(path: &str) -> String {
    let normalized = path.trim_end_matches('/');
    normalized
        .rsplit('/')
        .next()
        .unwrap_or(normalized)
        .to_string()
}

/// Exec by streaming image with zero-copy frame transfer when possible.
pub fn exec_from_fs_stream(path_ptr: u64, args_ptr: u64) -> u64 {
    let mut measurement = ExecMeasurement::start();
    if !caller_has_process_spawn_capability() {
        return crate::syscall::types::EPERM;
    }

    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(_) => return crate::syscall::types::EINVAL,
    };

    let extra_args_owned = match read_nul_args_from_user(args_ptr, 512, 64) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let extra_args: Vec<&str> = extra_args_owned.iter().map(|s| s.as_str()).collect();

    let Some(pid) = crate::syscall::security::current_process_id() else {
        return crate::syscall::types::EACCES;
    };
    if let Err(errno) = crate::syscall::fs::ensure_fs_path_executable_for_process(&path, pid) {
        return errno;
    }

    if let Some(data) =
        crate::init::fs::read_rootfs(&path).or_else(|| crate::cext::fs::read_all(&path))
    {
        let result = exec_with_data(
            &data,
            &path,
            &path,
            &extra_args,
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            &mut measurement,
        );
        return measurement.finish(result);
    }

    crate::syscall::types::ENOENT
}

pub(crate) fn map_initial_tls(table_phys: u64, aslr_seed: u64) -> Result<u64, u64> {
    let exec = crate::config::kernel().exec;
    let tls_base = exec
        .tls_base_min
        .saturating_add(aslr_offset_pages(aslr_seed ^ 0x19d7_3c6a, exec.tls_aslr_max_pages) * 4096);
    let mut tls_data = vec![0u8; exec.initial_tls_size as usize];
    tls_data[..8].copy_from_slice(&tls_base.to_ne_bytes());
    match crate::mem::paging::map_and_copy_segment_to(
        table_phys,
        tls_base,
        exec.initial_tls_size,
        exec.initial_tls_size,
        &tls_data,
        true,
        false,
    ) {
        Ok(()) => Ok(tls_base),
        Err(e) => {
            crate::warn!(
                "Failed to map initial TLS block at {:#x}: {:?}",
                tls_base,
                e
            );
            Err(mapping_error_errno(e))
        }
    }
}

#[inline(never)]
fn build_initial_user_stack(
    aslr_seed: u64,
    argv: &[&str],
    envp: &[&str],
    execfn: &str,
    auxv_entries: &[(u64, u64)],
) -> Result<InitialUserStack, u64> {
    let exec = crate::config::kernel().exec;
    let stack_end_vaddr = exec.stack_top_base.saturating_sub(
        aslr_offset_pages(aslr_seed ^ 0x53a9_1e2d, exec.stack_aslr_max_pages) * 4096,
    );
    let stack_base_vaddr = stack_end_vaddr - (exec.user_stack_size_pages as u64 * 4096);

    let mut string_block = Vec::new();
    let mut argv_offsets = Vec::new();
    for arg in argv {
        argv_offsets.push(string_block.len());
        string_block.extend_from_slice(arg.as_bytes());
        string_block.push(0);
    }

    let mut envp_offsets = Vec::new();
    for env in envp {
        envp_offsets.push(string_block.len());
        string_block.extend_from_slice(env.as_bytes());
        string_block.push(0);
    }

    let random_offset = string_block.len();
    let mut rng = aslr_seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    for _ in 0..16 {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        string_block.push((rng >> 33) as u8);
    }

    let execfn_offset = string_block.len();
    string_block.extend_from_slice(execfn.as_bytes());
    string_block.push(0);

    let string_area_len = string_block.len();
    let pointers_bytes =
        8 + (argv.len() * 8) + 8 + (envp.len() * 8) + 8 + (auxv_entries.len() * 16) + 16;
    let total_data_needed = string_area_len + pointers_bytes;
    let padding_len = (16 - (total_data_needed % 16)) % 16;
    let total_size = total_data_needed + padding_len;

    if total_size > 4096 {
        crate::warn!("Arguments too large for single page stack setup");
        return Err(crate::syscall::types::EINVAL);
    }

    let string_area_base = stack_end_vaddr - string_area_len as u64;
    let random_addr = string_area_base + random_offset as u64;
    let execfn_addr = string_area_base + execfn_offset as u64;
    let initial_rsp = stack_end_vaddr - total_size as u64;

    let mut page_data = Vec::new();
    let page_offset = total_size % 4096;
    let unused_space = if page_offset == 0 {
        0
    } else {
        4096 - page_offset
    };
    page_data.resize(unused_space, 0);

    page_data.extend_from_slice(&(argv.len() as u64).to_ne_bytes());
    for off in argv_offsets {
        let ptr = string_area_base + off as u64;
        page_data.extend_from_slice(&ptr.to_ne_bytes());
    }
    page_data.extend_from_slice(&0u64.to_ne_bytes());

    for off in envp_offsets {
        let ptr = string_area_base + off as u64;
        page_data.extend_from_slice(&ptr.to_ne_bytes());
    }
    page_data.extend_from_slice(&0u64.to_ne_bytes());

    for (key, value) in auxv_entries {
        let resolved_value = match *key {
            25 => random_addr, // AT_RANDOM
            31 => execfn_addr, // AT_EXECFN
            _ => *value,
        };
        page_data.extend_from_slice(&key.to_ne_bytes());
        page_data.extend_from_slice(&resolved_value.to_ne_bytes());
    }
    page_data.extend_from_slice(&0u64.to_ne_bytes());
    page_data.extend_from_slice(&0u64.to_ne_bytes());

    page_data.resize(page_data.len() + padding_len, 0);
    page_data.extend_from_slice(&string_block);

    if page_data.len() != 4096 {
        crate::warn!("internal: page_data.len() != 4096: {}", page_data.len());
        return Err(crate::syscall::types::EINVAL);
    }

    Ok(InitialUserStack {
        stack_base_vaddr,
        stack_end_vaddr,
        initial_rsp,
        page_data,
    })
}

/// メモリ上の ELF バッファからプロセスを生成する（内部共通実装）
fn delegated_parent_pid() -> Option<crate::task::ProcessId> {
    None
}

fn exec_with_data(
    data: &[u8],
    process_name: &str,
    exec_path: &str,
    args: &[&str],
    envp: &[&str],
    parent_override: Option<crate::task::ProcessId>,
    initial_caps: Option<CapabilitySet>,
    initial_kernel_authorities: Option<KernelAuthoritySet>,
    requested_credentials: Option<crate::task::ProcessCredentials>,
    requested_privilege: Option<crate::task::PrivilegeLevel>,
    security_identity: Option<&str>,
    measurement: &mut ExecMeasurement,
) -> u64 {
    crate::debug!("exec: name={}", process_name);
    let aslr_seed = next_aslr_seed(process_name);

    {
        let data: &[u8] = data;
        // Disable SMAP/SMEP for the duration of the exec mapping operations.
        // Many helper functions perform direct physical/HHDM accesses; re-enabling
        // SMAP/SMEP during execution can cause page faults when touching user
        // page tables. Hold the guard for the whole scope so it's restored on drop.
        let _smap_guard = crate::cpu::SmapSmepGuard::new();

        let new_pt_phys = match crate::mem::paging::create_user_page_table() {
            Ok(phys) => phys,
            Err(e) => {
                crate::warn!(
                    "Failed to create user page table for {}: {:?}",
                    process_name,
                    e
                );
                return mapping_error_errno(e);
            }
        };
        let mut new_pt_guard = UserPageTableGuard::new(new_pt_phys);
        crate::debug!("Created user page table at {:#x}", new_pt_phys);

        // Note: SMAP/SMEP are already disabled globally during kernel initialization
        // and are kept disabled for all exec operations. See src/core/mem/mod.rs:66

        let ElfImageLayout {
            entry,
            phdr_vaddr,
            phentsize,
            phnum,
            deferred_zero_regions,
        } = match map_elf_image(data, new_pt_phys, measurement) {
            Ok(layout) => layout,
            Err(errno) => {
                crate::warn!("exec: invalid or unmappable ELF image '{}': {}", exec_path, errno);
                return errno;
            }
        };

        let base_name = exec_path.rsplit('/').next().unwrap_or(process_name);
        let argv0 = base_name.strip_suffix(".elf").unwrap_or(base_name);
        let mut all_args: Vec<&str> = Vec::new();
        all_args.push(argv0);
        for a in args {
            all_args.push(a);
        }
        if process_name.ends_with("busybox.elf") {
            let argv1 = all_args.get(1).copied().unwrap_or("");
            crate::info!(
                "busybox argv: argc={}, argv0='{}', argv1='{}'",
                all_args.len(),
                argv0,
                argv1
            );
        }
        let auxv_entries = [
            (3u64, phdr_vaddr),
            (4u64, phentsize),
            (5u64, phnum),
            (6u64, 4096u64),
            (7u64, 0u64),
            (8u64, 0u64),
            (9u64, entry),
            (11u64, 0u64),
            (12u64, 0u64),
            (13u64, 0u64),
            (14u64, 0u64),
            (16u64, 0u64),
            (17u64, 100u64),
            (23u64, 0u64),
            (25u64, 0u64),
            (31u64, 0u64),
            (0u64, 0u64),
        ];
        let InitialUserStack {
            stack_base_vaddr,
            stack_end_vaddr,
            initial_rsp,
            page_data,
        } = match build_initial_user_stack(aslr_seed, &all_args, envp, exec_path, &auxv_entries) {
            Ok(stack) => stack,
            Err(errno) => return errno,
        };
        let exec = crate::config::kernel().exec;

        crate::debug!(
            "Allocating user stack: base={:#x}, top={:#x}, size={} pages, rsp={:#x}",
            stack_base_vaddr,
            stack_end_vaddr,
            exec.user_stack_size_pages,
            initial_rsp
        );

        // Map the lower 7 pages as zero-filled (writable, non-executable stack)
        if let Err(e) = crate::mem::paging::map_and_copy_segment_to(
            new_pt_phys,
            stack_base_vaddr,
            0,
            (exec.user_stack_size_pages - 1) as u64 * 4096,
            &[],
            true,
            false,
        ) {
            crate::warn!("Failed to allocate user stack lower: {:?}", e);
            return mapping_error_errno(e);
        }
        // Map the top page with args (writable, non-executable stack)
        let top_page_vaddr = stack_end_vaddr - 4096;
        if let Err(e) = crate::mem::paging::map_and_copy_segment_to(
            new_pt_phys,
            top_page_vaddr,
            4096,
            4096,
            &page_data,
            true,
            false,
        ) {
            crate::warn!("Failed to allocate user stack top: {:?}", e);
            return mapping_error_errno(e);
        }

        crate::debug!("User stack allocated successfully");

        // Pre-map initial heap pages to avoid immediate page faults from user allocations.
        // Map two pages at the default heap base so small early allocations won't fault.
        let exec_cfg = crate::config::kernel().exec;
        let default_heap_base = exec_cfg.brk_heap_base_min.saturating_add(
            aslr_offset_pages(aslr_seed ^ 0x4a11_6b5c, exec_cfg.brk_heap_aslr_max_pages) * 4096,
        );
        let heap_map_size: u64 = 4096 * 2;
        let mut heap_pre_mapped = false;
        if let Err(e) = crate::mem::paging::map_and_copy_segment_to(
            new_pt_phys,
            default_heap_base,
            0,
            heap_map_size,
            &[],
            true,
            false,
        ) {
            crate::warn!(
                "Failed to pre-map initial heap pages at {:#x}: {:?}",
                default_heap_base,
                e
            );
        } else {
            crate::debug!(
                "Pre-mapped {} bytes for heap at {:#x} for {}",
                heap_map_size,
                default_heap_base,
                process_name
            );
            heap_pre_mapped = true;
        }

        // プロセスを作成してページテーブルをセット
        let parent_pid = parent_override.or_else(|| {
            crate::task::current_thread_id()
                .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
        });
        let privilege = resolve_exec_privilege(requested_privilege);
        let boot_init = crate::policy::init_launch();
        let is_boot_init = privilege == crate::task::PrivilegeLevel::Service
            && exec_path == boot_init.exec_path
            && process_name == boot_init.process_name;
        const DEFAULT_PROCESS_PRIORITY: u8 = 8;
        let priority = DEFAULT_PROCESS_PRIORITY;
        let mut proc = crate::task::Process::new(process_name, privilege, parent_pid, priority);
        if let Some(identity) = security_identity {
            proc.set_security_identity(identity);
        }
        if let Some(credentials) =
            parent_pid.and_then(|pid| crate::task::with_process(pid, |parent| parent.credentials()))
        {
            proc.set_credentials_for_exec(credentials);
        }
        if let Some(credentials) = requested_credentials {
            proc.set_credentials_for_exec(credentials);
        }
        proc.set_foreground(false);
        if let Some(caps) = initial_caps {
            // capability はプロセス開始前にセットする必要がある。
            // スケジューラが有効だと `add_thread()` の直後に動き出すため、
            // syscall 後付けだと競合して「cap不足」になる。
            proc.set_capabilities_for_exec(caps);
        }
        if let Some(authorities) = initial_kernel_authorities {
            proc.set_kernel_authorities_for_exec(authorities);
        }
        proc.set_page_table(new_pt_phys);
        proc.set_mmap_regions(deferred_zero_regions);
        proc.set_stack_bottom(stack_base_vaddr);
        proc.set_stack_top(stack_end_vaddr + 4096);
        proc.set_exe_path(exec_path);
        crate::debug!(
            "[STACK_INIT] {}: stack_base={:#x}, stack_end={:#x}, stack_top={:#x}",
            proc.name(),
            stack_base_vaddr,
            stack_end_vaddr,
            stack_end_vaddr + 4096
        );
        // 親プロセスの CWD を子プロセスに継承する
        if let Some(ppid) = parent_pid {
            let parent_cwd = crate::task::with_process(ppid, |p| {
                let mut s = String::new();
                s.push_str(p.cwd());
                s
            });
            if let Some(cwd_str) = parent_cwd {
                proc.set_cwd(&cwd_str);
            }
        }
        if heap_pre_mapped {
            proc.set_heap_start(default_heap_base);
            proc.set_heap_end(default_heap_base + heap_map_size);
        }
        let initial_fs_base = match map_initial_tls(new_pt_phys, aslr_seed) {
            Ok(base) => base,
            Err(errno) => return errno,
        };
        let pid = proc.id();
        if is_boot_init && !claim_init_pid(pid.as_u64()) {
            crate::warn!("init is already running, rejecting duplicate launch");
            return crate::syscall::types::EINVAL;
        }
        if crate::task::add_process(proc).is_none() {
            if is_boot_init {
                let _ = release_init_pid(pid.as_u64());
            }
            return crate::syscall::types::EINVAL;
        }
        // allocate kernel stack for the new thread
        let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
        let kstack = match crate::task::thread::allocate_kernel_stack_in_table(
            kstack_size,
            new_pt_phys,
        ) {
            Some(a) => a,
            None => {
                crate::warn!("Failed to allocate kernel stack for thread");
                let _ = crate::task::remove_process(pid);
                if is_boot_init {
                    let _ = release_init_pid(pid.as_u64());
                }
                let _ = crate::mem::paging::destroy_user_page_table(new_pt_phys);
                return crate::syscall::types::ENOMEM;
            }
        };
        new_pt_guard.disarm();

        // ユーザーモードスレッドを作成
        // RSP に initial_rsp を設定
        let mut thread = crate::task::Thread::new_usermode(
            pid,
            process_name,
            entry,
            initial_rsp,
            0,
            kstack,
            kstack_size,
        );
        thread.set_fs_base(initial_fs_base);

        crate::debug!(
            "exec: loaded '{}', entry={:#x}, pid={:?}",
            process_name,
            entry,
            pid
        );

        let add_res = crate::task::add_thread(thread);
        crate::debug!("exec: add_thread returned: {:?}", add_res);
        if add_res.is_none() {
            crate::warn!("Failed to add thread");
            crate::task::free_kernel_stack(kstack);
            let _ = crate::task::remove_process(pid);
            if is_boot_init {
                let _ = release_init_pid(pid.as_u64());
            }
            let _ = crate::mem::paging::destroy_user_page_table(new_pt_phys);
            return crate::syscall::types::EINVAL;
        }

        // report scheduling state
        crate::debug!(
            "exec: scheduler_enabled={} thread_count={}",
            crate::task::is_scheduler_enabled(),
            crate::task::thread_count()
        );
        if let Some(next) = crate::task::peek_next_thread() {
            crate::debug!("exec: peek_next_thread -> {:?}", next);
        } else {
            crate::debug!("exec: peek_next_thread -> None");
        }

        // log current thread and thread-state counts
        crate::debug!(
            "exec: current_thread={:?}",
            crate::task::current_thread_id()
        );
        crate::debug!(
            "exec: ready_count={} running_count={}",
            crate::task::count_threads_by_state(crate::task::ThreadState::Ready),
            crate::task::count_threads_by_state(crate::task::ThreadState::Running)
        );
        if let Some(tid) = add_res {
            crate::debug!("exec: new_thread_id={:?}", tid);
        }

        // Return the child identifier to the caller before the child can run.
        // Timer-driven scheduling will pick up the ready thread after the spawn
        // caller has completed its registration and handshake setup.

        crate::debug!(
            "exec: created usermode process '{}' (pid={:?}, entry={:#x})",
            process_name,
            pid,
            entry
        );

        let launched_tid = add_res.expect("add_thread succeeded after non-None check");
        launched_tid.as_u64()
    }
}

/// ユーザー空間の null 終端ポインタ配列（char**）を読み取る
///
/// 各エントリは 64 ビットポインタ。NULL で終端。
/// max_entries を超えた場合は切り捨てる。
fn read_user_ptr_array(array_ptr: u64, max_entries: usize) -> Vec<String> {
    if array_ptr == 0 {
        return Vec::new();
    }
    let mut result = Vec::new();
    for i in 0..=max_entries {
        let ptr_addr = match (i as u64)
            .checked_mul(8)
            .and_then(|o| array_ptr.checked_add(o))
        {
            Some(a) => a,
            None => break,
        };
        if !crate::syscall::validate_user_ptr(ptr_addr, 8) {
            break;
        }
        let entry_ptr = match crate::syscall::read_user_u64(ptr_addr) {
            Ok(ptr) => ptr,
            Err(_) => break,
        };
        if entry_ptr == 0 {
            break;
        }
        let s = match crate::syscall::read_user_cstring(entry_ptr, 4096) {
            Ok(s) => s,
            Err(_) => break,
        };
        result.push(s);
        if result.len() >= max_entries {
            break;
        }
    }
    result
}

/// execve システムコール
///
/// 現在のプロセスイメージを新しいプログラムで置き換える
///
/// # 引数
/// - `path_ptr`: 実行ファイルパスのポインタ (null 終端)
/// - `argv`: 引数ポインタ配列 (char*[]) — null 終端、0 の場合は [path] を使用
/// - `envp`: 環境変数ポインタ配列 (char*[]) — null 終端、0 の場合は空
pub fn execve_syscall(path_ptr: u64, argv: u64, envp: u64) -> u64 {
    use crate::syscall::types::{EINVAL, ENOENT, EPERM};

    let mut measurement = ExecMeasurement::start();
    if path_ptr == 0 {
        crate::warn!("execve: null path pointer");
        return EINVAL;
    }
    if !caller_has_process_spawn_capability() {
        crate::warn!("execve: missing process spawn capability");
        return EPERM;
    }

    let path_owned = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(err) => {
            crate::warn!("execve: read path failed errno={}", err);
            return EINVAL;
        }
    };
    let Some(pid) = crate::syscall::security::current_process_id() else {
        return crate::syscall::types::EACCES;
    };
    if let Err(errno) =
        crate::syscall::fs::ensure_fs_path_executable_for_process(&path_owned, pid)
    {
        return errno;
    }

    let aslr_seed = next_aslr_seed(&path_owned);
    let (data_vec, source) = match load_exec_image(&path_owned, ManifestRole::Unknown) {
        Some(loaded) => loaded,
        None => return ENOENT,
    };
    if !crate::policy::signature::verify_exec(&path_owned, &data_vec) {
        crate::warn!("execve: signature verification failed for '{}'", path_owned);
        return EPERM;
    }
    crate::info!(
        "execve: loaded '{}' from {} ({} bytes)",
        path_owned,
        source,
        data_vec.len()
    );
    let data: &[u8] = &data_vec;

    // 新しいページテーブルを作成
    let new_pt_phys = match crate::mem::paging::create_user_page_table() {
        Ok(p) => p,
        Err(error) => return mapping_error_errno(error),
    };
    let mut new_pt_guard = UserPageTableGuard::new(new_pt_phys);

    let ElfImageLayout {
        entry,
        phdr_vaddr,
        phentsize,
        phnum,
        deferred_zero_regions,
    } = match map_elf_image(data, new_pt_phys, &mut measurement) {
        Ok(layout) => layout,
        Err(errno) => return errno,
    };

    // ユーザースタックをセットアップ (Linux x86_64 ABI: argc, argv[], NULL, envp[], NULL, auxv[])
    // argv / envp をユーザー空間から読み込む
    let argv_strings = read_user_ptr_array(argv, 256);
    let envp_strings = read_user_ptr_array(envp, 1024);
    let mut argv_refs: Vec<&str> = argv_strings.iter().map(|s| s.as_str()).collect();
    if argv_refs.is_empty() {
        argv_refs.push(&path_owned);
    }
    let envp_refs: Vec<&str> = envp_strings.iter().map(|s| s.as_str()).collect();
    let auxv_entries = [
        (3u64, phdr_vaddr),
        (4u64, phentsize),
        (5u64, phnum),
        (6u64, 4096u64),
        (7u64, 0u64),
        (8u64, 0u64),
        (9u64, entry),
        (11u64, 0u64),
        (12u64, 0u64),
        (13u64, 0u64),
        (14u64, 0u64),
        (16u64, 0u64),
        (17u64, 100u64),
        (23u64, 0u64),
        (25u64, 0u64),
        (31u64, 0u64),
        (0u64, 0u64),
    ];
    let InitialUserStack {
        stack_base_vaddr,
        stack_end_vaddr,
        initial_rsp,
        page_data,
    } = match build_initial_user_stack(
        aslr_seed,
        &argv_refs,
        &envp_refs,
        &path_owned,
        &auxv_entries,
    )
    {
        Ok(stack) => stack,
        Err(errno) => return errno,
    };

    if let Err(error) = crate::mem::paging::map_and_copy_segment_to(
        new_pt_phys,
        stack_base_vaddr,
        0,
        (crate::config::kernel().exec.user_stack_size_pages - 1) as u64 * 4096,
        &[],
        true,
        false,
    ) {
        return mapping_error_errno(error);
    }
    let top_page_vaddr = stack_end_vaddr - 4096;
    if let Err(error) = crate::mem::paging::map_and_copy_segment_to(
        new_pt_phys,
        top_page_vaddr,
        4096,
        4096,
        &page_data,
        true,
        false,
    ) {
        return mapping_error_errno(error);
    }

    // 初期ヒープをASLR付きで確保
    let exec_cfg = crate::config::kernel().exec;
    let heap_base = exec_cfg.mmap_heap_base_min.saturating_add(
        aslr_offset_pages(aslr_seed ^ 0x4a11_6b5c, exec_cfg.mmap_heap_aslr_max_pages) * 4096,
    );
    let heap_map_size: u64 = 4096 * 2;
    if let Err(error) = crate::mem::paging::map_and_copy_segment_to(
        new_pt_phys,
        heap_base,
        0,
        heap_map_size,
        &[],
        true,
        false,
    ) {
        return mapping_error_errno(error);
    }
    let initial_fs_base = match map_initial_tls(new_pt_phys, aslr_seed) {
        Ok(base) => base,
        Err(errno) => return errno,
    };

    // 現在のプロセスのページテーブルとヒープを更新
    let current_tid = match crate::task::current_thread_id() {
        Some(t) => t,
        None => return EINVAL,
    };
    let pid = match crate::task::with_thread(current_tid, |t| t.process_id()) {
        Some(p) => p,
        None => return EINVAL,
    };
    let kernel_stack = match crate::task::with_thread(current_tid, |thread| {
        thread.kernel_stack_base()
    }) {
        Some(base) => base,
        None => return EINVAL,
    };
    if !crate::task::remap_kernel_stack_user_table(kernel_stack, new_pt_phys) {
        return crate::syscall::types::ENOMEM;
    }
    crate::task::release_process_mmio_mappings(pid);
    crate::task::release_process_dma_buffers(pid);
    crate::task::with_thread_mut(current_tid, |t| t.set_fs_base(initial_fs_base));
    let old_pt_phys = crate::task::with_process_mut(pid, |p| {
        let prev = p.page_table();
        p.set_page_table(new_pt_phys);
        p.set_heap_start(heap_base);
        p.set_heap_end(heap_base + heap_map_size);
        p.set_ipc_mapping_end(0);
        p.set_mmap_regions(deferred_zero_regions);
        p.set_stack_bottom(stack_base_vaddr);
        p.set_stack_top(stack_end_vaddr + 4096);
        p.set_exe_path(&path_owned);
        crate::debug!(
            "[STACK_INIT] {}: stack_base={:#x}, stack_end={:#x}, stack_top={:#x}",
            p.name(),
            stack_base_vaddr,
            stack_end_vaddr,
            stack_end_vaddr + 4096
        );
        prev
    })
    .flatten();
    if let Some(old) = old_pt_phys {
        if old != new_pt_phys {
            let _ = crate::mem::paging::destroy_user_page_table(old);
        }
    }
    new_pt_guard.disarm();

    // FD_CLOEXEC が設定された FD を exec 時に閉じる
    crate::task::with_process_mut(pid, |p| p.fd_table_mut().close_cloexec_fds());

    // 新しいページテーブルに切り替えてジャンプ
    measurement.record();
    unsafe {
        crate::mem::paging::switch_page_table(new_pt_phys);
        crate::task::jump_to_usermode(entry, initial_rsp, 0);
    }
}

/// メモリ上の ELF バッファから新プロセスを起動するシステムコール
///
/// # 引数
/// - `buf_ptr`: ユーザー空間の ELF データへのポインタ
/// - `buf_len`: バッファのバイト数
pub fn exec_from_buffer_syscall(buf_ptr: u64, buf_len: u64) -> u64 {
    use crate::syscall::types::{EFAULT, EINVAL, EPERM};

    let mut measurement = ExecMeasurement::start();
    if !caller_has_process_spawn_capability() {
        return EPERM;
    }

    if buf_ptr == 0 || buf_len == 0 || buf_len > 32 * 1024 * 1024 {
        return EINVAL;
    }

    // ポインタの範囲がユーザー空間内かつ現在のプロセスのページテーブルにマップ済みか検証
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }

    let mut owned = alloc::vec![0u8; buf_len as usize];
    if let Err(e) = crate::syscall::copy_from_user(buf_ptr, &mut owned) {
        return e;
    }

    let result = exec_with_data(
        &owned,
        "user_exec",
        "user_exec",
        &[],
        &[],
        delegated_parent_pid(),
        None,
        None,
        None,
        None,
        None,
        &mut measurement,
    );
    measurement.finish(result)
}

/// メモリ上の ELF バッファと実行パス名から新プロセスを起動するシステムコール
///
/// # 引数
/// - `buf_ptr`: ユーザー空間の ELF データへのポインタ
/// - `buf_len`: バッファのバイト数
/// - `path_ptr`: ユーザー空間の null 終端パス文字列
pub fn exec_from_buffer_named_syscall(buf_ptr: u64, buf_len: u64, path_ptr: u64) -> u64 {
    use crate::syscall::types::{EFAULT, EINVAL, EPERM};

    let mut measurement = ExecMeasurement::start();
    if !caller_has_process_spawn_capability() {
        return EPERM;
    }
    if buf_ptr == 0 || buf_len == 0 || buf_len > 32 * 1024 * 1024 || path_ptr == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }

    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let process_name = path.rsplit('/').next().unwrap_or(path.as_str());

    let mut owned = alloc::vec![0u8; buf_len as usize];
    if let Err(e) = crate::syscall::copy_from_user(buf_ptr, &mut owned) {
        return e;
    }

    let result = exec_with_data(
        &owned,
        process_name,
        path.as_str(),
        &[],
        &[],
        delegated_parent_pid(),
        None,
        None,
        None,
        None,
        None,
        &mut measurement,
    );
    measurement.finish(result)
}

/// メモリ上の ELF バッファと実行パス名・引数から新プロセスを起動するシステムコール
///
/// # 引数
/// - `buf_ptr`: ユーザー空間の ELF データへのポインタ
/// - `buf_len`: バッファのバイト数
/// - `path_ptr`: ユーザー空間の null 終端パス文字列
/// - `args_ptr`: ユーザー空間の null 区切り引数列（"arg1\0arg2\0\0"）
pub fn exec_from_buffer_named_args_syscall(
    buf_ptr: u64,
    buf_len: u64,
    path_ptr: u64,
    args_ptr: u64,
) -> u64 {
    use crate::syscall::types::{EFAULT, EINVAL, EPERM};

    let mut measurement = ExecMeasurement::start();
    if !caller_has_process_spawn_capability() {
        return EPERM;
    }
    if buf_ptr == 0 || buf_len == 0 || buf_len > 32 * 1024 * 1024 || path_ptr == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }

    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let process_name = path.rsplit('/').next().unwrap_or(path.as_str());

    let args_owned = match read_nul_args_from_user(args_ptr, 512, 64) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

    let mut owned = alloc::vec![0u8; buf_len as usize];
    if let Err(e) = crate::syscall::copy_from_user(buf_ptr, &mut owned) {
        return e;
    }

    let result = exec_with_data(
        &owned,
        process_name,
        path.as_str(),
        &args_refs,
        &[],
        delegated_parent_pid(),
        None,
        None,
        None,
        None,
        None,
        &mut measurement,
    );
    measurement.finish(result)
}

/// メモリ上の ELF バッファと実行パス名・引数・要求元スレッドIDから新プロセスを起動するシステムコール
pub fn exec_from_buffer_named_args_with_requester_syscall(
    buf_ptr: u64,
    buf_len: u64,
    path_ptr: u64,
    args_ptr: u64,
    requester_tid: u64,
) -> u64 {
    use crate::syscall::types::{EFAULT, EINVAL, EPERM};

    let mut measurement = ExecMeasurement::start();
    if !caller_has_process_spawn_capability() {
        return EPERM;
    }
    if buf_ptr == 0 || buf_len == 0 || buf_len > 32 * 1024 * 1024 || path_ptr == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, buf_len) {
        return EFAULT;
    }

    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let process_name = path.rsplit('/').next().unwrap_or(path.as_str());

    let args_owned = match read_nul_args_from_user(args_ptr, 512, 64) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

    let mut owned = alloc::vec![0u8; buf_len as usize];
    if let Err(e) = crate::syscall::copy_from_user(buf_ptr, &mut owned) {
        return e;
    }

    let parent_override = if requester_tid != 0 {
        let requester = crate::task::ThreadId::from_u64(requester_tid);
        let caller_pid = match crate::task::current_thread_id()
            .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
        {
            Some(pid) => pid,
            None => return EPERM,
        };
        match crate::task::with_thread(requester, |t| t.process_id()) {
            Some(pid) => {
                let caller_is_core = crate::task::with_process(caller_pid, |p| {
                    p.privilege() == crate::task::PrivilegeLevel::Core
                })
                .unwrap_or(false);

                if pid != caller_pid && !caller_is_core {
                    return EPERM;
                }
                Some(pid)
            }
            None => return EINVAL,
        }
    } else {
        None
    };

    let result = exec_with_data(
        &owned,
        process_name,
        path.as_str(),
        &args_refs,
        &[],
        parent_override.or_else(delegated_parent_pid),
        None,
        None,
        None,
        None,
        None,
        &mut measurement,
    );
    measurement.finish(result)
}
