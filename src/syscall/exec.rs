use crate::capability::{
    parse_kernel_authority_spec, Capability, CapabilitySet, KernelAuthoritySet,
};
use crate::policy::{
    claim_init_pid, release_init_pid, resolve_exec_privilege,
};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

mod image;
mod launch;
mod captured_handles;
mod storage;
mod initial_mappings;
mod bootstrap_stack;

use image::{map_elf_image, ElfImageLayout};
use launch::ImageLaunch;

use mnu_abi::exec::{
    ExecutionClass, APPLICATION_DEVELOPER_ID_PREFIX, APPLICATION_PACKAGE_ID_PREFIX,
    APPLICATION_PROVENANCE_PREFIX, APPLICATION_SUBJECT_KEY_ID_PREFIX,
    EXECUTABLE_DIGEST_PREFIX, EXEC_AUTHORIZATION_CLASS_PREFIX,
    EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE, EXEC_AUTHORIZATION_KIND_PREFIX,
    EXEC_AUTHORIZATION_KIND_SPAWN,
};
use sha2::{Digest, Sha256};
static EXEC_ASLR_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InheritedHandleSpec {
    key: u64,
    source: crate::task::ObjectHandle,
    target: u32,
    rights: crate::task::HandleRights,
}

#[derive(Clone, Debug)]
struct InheritedHandleGrant {
    key: u64,
    target: u32,
    entry: crate::task::ObjectHandleEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InheritedValueSpec {
    key: u64,
    value: u64,
}

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

enum GuardedTable {
    Raw(u64),
    Image(Arc<crate::mem::detached_roots::Root>),
}
struct UserPageTableGuard(Option<GuardedTable>);

struct CreatedProcessHandle(Option<u64>);

impl Drop for CreatedProcessHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = crate::syscall::handle::close(handle);
        }
    }
}

impl UserPageTableGuard {
    fn new(table_phys: u64) -> Self {
        Self(Some(GuardedTable::Raw(table_phys)))
    }

    fn for_image(root: Arc<crate::mem::detached_roots::Root>) -> Self {
        Self(Some(GuardedTable::Image(root)))
    }

    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for UserPageTableGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(GuardedTable::Raw(table)) => {
                let _ = crate::mem::paging::destroy_user_page_table(table);
            }
            Some(GuardedTable::Image(root)) if root.published() => {
                let _ = crate::mem::paging::destroy_user_page_table(root.table());
            }
            // Before publication, Root's final owning reference does cleanup.
            _ => {}
        }
    }
}

fn mapping_error_native(error: crate::Kernel) -> mnu_abi::status::Error {
    match error {
        crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => {
            mnu_abi::status::Error::ResourceUnavailable
        }
        _ => mnu_abi::status::Error::InvalidArgument,
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

fn read_nul_identity_fields(
    fields_ptr: u64,
    max_total_bytes: usize,
    max_fields: usize,
) -> Result<Vec<String>, mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    if fields_ptr == 0 {
        return Ok(Vec::new());
    }
    let mut storage = storage::from_user_native(fields_ptr, max_total_bytes)?;
    if let Some(end) = storage.windows(2).position(|w| w == [0, 0]) {
        storage.truncate(end + 2);
    }

    let mut out = Vec::new();
    for s in storage.split(|&b| b == 0) {
        if s.is_empty() {
            continue;
        }
        let text = core::str::from_utf8(s).map_err(|_| Error::InvalidArgument)?;
        let text = storage::text(text)?;
        out.try_reserve(1).map_err(|_| Error::ResourceUnavailable)?;
        out.push(text);
        if out.len() >= max_fields {
            break;
        }
    }
    Ok(out)
}

fn read_nul_caps_from_user(
    caps_ptr: u64,
    caps_total_len: u64,
) -> Result<Vec<String>, mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    if caps_total_len == 0 {
        return Ok(Vec::new());
    }
    if caps_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let Ok(len) = usize::try_from(caps_total_len) else {
        return Err(Error::InvalidArgument);
    };
    if len > 1024 {
        return Err(Error::InvalidArgument);
    }

    let storage = storage::from_user_native(caps_ptr, len)?;

    // cap 名は NUL 区切りで渡す。末尾の NUL は任意だが、無くても split が動くようにする。
    let mut out = Vec::new();
    for s in storage.split(|&b| b == 0) {
        if s.is_empty() {
            continue;
        }
        let text = core::str::from_utf8(s).map_err(|_| Error::InvalidArgument)?;
        let text = storage::text(text)?;
        out.try_reserve(1).map_err(|_| Error::ResourceUnavailable)?;
        out.push(text);
        if out.len() >= 128 {
            break;
        }
    }
    Ok(out)
}

fn caller_has_process_spawn_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[Capability::ProcessSpawn])
}

fn parse_requested_exec_grants(
    caps_list: &[String],
) -> Result<(CapabilitySet, KernelAuthoritySet), mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    let mut caps = CapabilitySet::empty();
    let mut authorities = KernelAuthoritySet::empty();
    for spec in caps_list {
        if let Some(authority) = parse_kernel_authority_spec(spec.as_str()) {
            authorities.try_insert(authority)?;
            continue;
        }
        // Canonical capabilities are safe to intern even while consuming an
        // authorization: the policy authority has already evaluated their
        // policy classification, and the ABI registry prevents arbitrary
        // names from creating kernel capability IDs here.
        let cap = if mnu_abi::capability::metadata(spec.as_str()).is_some() {
            Some(Capability::try_intern(spec.as_str())?)
        } else {
            Capability::from_str(spec.as_str())
        };
        let Some(cap) = cap else {
            return Err(Error::InvalidArgument);
        };
        if matches!(cap, Capability::MemoryPhysMap) {
            return Err(Error::InvalidArgument);
        }
        caps.try_insert(cap)?;
    }
    Ok((caps, authorities))
}

fn export_inherited_handles(
    source_process: Option<crate::task::ProcessId>,
    specs: &[InheritedHandleSpec],
) -> Result<Vec<InheritedHandleGrant>, mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let source_process = source_process.ok_or(Error::NotReady)?;
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(specs.len())
        .map_err(|_| Error::ResourceUnavailable)?;
    crate::task::with_process(source_process, |process| {
        for spec in specs {
            let source = process
                .object_handles()
                .get(spec.source)
                .ok_or(Error::InvalidArgument)?;
            if !source
                .rights()
                .contains(crate::task::HandleRights::TRANSFER)
                || !source.rights().contains(spec.rights)
            {
                return Err(Error::AccessDenied);
            }
            let entry = process
                .object_handles()
                .export_restricted(spec.source, spec.rights)
                .ok_or(Error::AccessDenied)?;
            grants.push(InheritedHandleGrant {
                key: spec.key,
                target: spec.target,
                entry,
            });
        }
        Ok(grants)
    })
    .ok_or(Error::NotReady)?
}

fn install_inherited_handles(
    process: &mut crate::task::Process,
    grants: &[InheritedHandleGrant],
) -> Result<(), mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    // Reserve explicit slots before allocating automatic ones. Wire record
    // order must not make an automatic allocation collide with a later slot.
    for grant in grants
        .iter()
        .filter(|grant| grant.target != 0)
        .chain(grants.iter().filter(|grant| grant.target == 0))
    {
        if process.launch_context().get(grant.key).is_some() {
            return Err(Error::AlreadyExists);
        }
        let handle = if grant.target == 0 {
            process
                .object_handles_mut()
                .insert(grant.entry.clone())
                .ok_or(Error::ResourceUnavailable)?
        } else {
            if grant.target > crate::task::handle_table::PROCESS_MAX_OBJECT_HANDLES as u32 {
                return Err(Error::InvalidArgument);
            }
            let handle =
                crate::task::ObjectHandle::from_raw(grant.target).ok_or(Error::InvalidArgument)?;
            if process.object_handles().get(handle).is_some() {
                return Err(Error::AlreadyExists);
            }
            if !process
                .object_handles_mut()
                .insert_at(handle, grant.entry.clone())
            {
                return Err(Error::ResourceUnavailable);
            }
            handle
        };
        process.launch_context_mut().install(grant.key, handle)?;
    }
    Ok(())
}

fn install_inherited_values(
    process: &mut crate::task::Process,
    values: &[InheritedValueSpec],
) -> Result<(), mnu_abi::status::Error> {
    for value in values {
        process
            .launch_context_mut()
            .install_value(value.key, value.value)?;
    }
    Ok(())
}

fn valid_security_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

fn decode_subject_key_id(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex(pair[0])?;
        let low = decode_hex(pair[1])?;
        output[index] = high << 4 | low;
    }
    Some(output)
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub fn authorize_exec_syscall(
    requester_endpoint: u64,
    path_ptr: u64,
    identity_ptr: u64,
    caps_ptr: u64,
    caps_total_len: u64,
) -> u64 {
    use mnu_abi::status::Error;
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::CapabilitiesManage,
    ]) {
        return Error::AccessDenied.into_raw();
    }
    let path = match crate::syscall::read_user_cstring(path_ptr, 256) {
        Ok(path) => path,
        Err(error) => return error.into_raw(),
    };
    let identity_items = match read_nul_identity_fields(identity_ptr, 1024, 7) {
        Ok(items) => items,
        Err(error) => return error.into_raw(),
    };
    let mut package = None;
    let mut developer = None;
    let mut subject_key = None;
    let mut provenance = None;
    let mut executable_digest = None;
    let mut authorization_kind = None;
    let mut execution_class = None;
    for item in &identity_items {
        if let Some(value) = item.strip_prefix(APPLICATION_PACKAGE_ID_PREFIX) {
            package = Some(value);
        } else if let Some(value) = item.strip_prefix(APPLICATION_DEVELOPER_ID_PREFIX) {
            developer = Some(value);
        } else if let Some(value) = item.strip_prefix(APPLICATION_SUBJECT_KEY_ID_PREFIX) {
            subject_key = decode_subject_key_id(value);
        } else if let Some(value) = item.strip_prefix(APPLICATION_PROVENANCE_PREFIX) {
            provenance = match value {
                "built-in" => Some(crate::task::process::ApplicationProvenance::BuiltIn),
                "verified-package" => {
                    Some(crate::task::process::ApplicationProvenance::VerifiedPackage)
                }
                "development" => Some(crate::task::process::ApplicationProvenance::Development),
                _ => None,
            };
        } else if let Some(value) = item.strip_prefix(EXECUTABLE_DIGEST_PREFIX) {
            if executable_digest.is_some() {
                return Error::InvalidArgument.into_raw();
            }
            executable_digest = decode_subject_key_id(value);
        } else if let Some(value) = item.strip_prefix(EXEC_AUTHORIZATION_KIND_PREFIX) {
            if authorization_kind.is_some() {
                return Error::InvalidArgument.into_raw();
            }
            authorization_kind = match value {
                EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE => {
                    Some(crate::task::process::PendingExecKind::ImageReplace)
                }
                EXEC_AUTHORIZATION_KIND_SPAWN => Some(crate::task::process::PendingExecKind::Spawn),
                _ => None,
            };
        } else if let Some(value) = item.strip_prefix(EXEC_AUTHORIZATION_CLASS_PREFIX) {
            if execution_class.is_some() {
                return Error::InvalidArgument.into_raw();
            }
            execution_class = match value {
                "privileged" => Some(ExecutionClass::Privileged),
                "unprivileged" => Some(ExecutionClass::Unprivileged),
                _ => None,
            };
        } else {
            return Error::InvalidArgument.into_raw();
        }
    }
    let (
        Some(package),
        Some(developer),
        Some(subject_key),
        Some(provenance),
        Some(executable_digest),
        Some(authorization_kind),
        Some(execution_class),
    ) = (
        package,
        developer,
        subject_key,
        provenance,
        executable_digest,
        authorization_kind,
        execution_class,
    )
    else {
        return Error::InvalidArgument.into_raw();
    };
    if !valid_security_identity(package) || !valid_security_identity(developer) {
        return Error::InvalidArgument.into_raw();
    }
    let caps_list = match read_nul_caps_from_user(caps_ptr, caps_total_len) {
        Ok(caps) => caps,
        Err(error) => return error.into_raw(),
    };
    let (capabilities, kernel_authorities) = match parse_requested_exec_grants(&caps_list) {
        Ok(grants) => grants,
        Err(error) => return error.into_raw(),
    };
    let (target_thread, target_pid) = if requester_endpoint == 0 {
        let Some(thread) = crate::task::current_thread_id() else {
            return Error::NotReady.into_raw();
        };
        let Some(pid) = crate::syscall::security::current_process_id() else {
            return Error::NotReady.into_raw();
        };
        (thread, pid)
    } else {
        let Some(requester_tid) = crate::syscall::ipc::resolve_sender_thread_id(requester_endpoint)
        else {
            return Error::InvalidArgument.into_raw();
        };
        let thread = crate::task::ThreadId::from_u64(requester_tid);
        let Some(pid) = crate::task::with_thread(thread, |thread| thread.process_id()) else {
            return Error::NotReady.into_raw();
        };
        (thread, pid)
    };
    let allowed = match crate::task::with_process(target_pid, |process| match authorization_kind {
        crate::task::process::PendingExecKind::ImageReplace => {
            capabilities.is_subset_of(process.capabilities())
                && kernel_authorities.is_subset_of(process.kernel_authorities())
        }
        crate::task::process::PendingExecKind::Spawn => process
            .capabilities()
            .contains(crate::capability::Capability::ProcessSpawn),
    }) {
        Some(allowed) => allowed,
        None => return Error::NotReady.into_raw(),
    };
    if !allowed {
        return Error::AccessDenied.into_raw();
    }
    let package = match storage::text(package) {
        Ok(package) => package,
        Err(error) => return error.into_raw(),
    };
    let developer = match storage::text(developer) {
        Ok(developer) => developer,
        Err(error) => return error.into_raw(),
    };
    let authorization = crate::task::process::PendingExecSecurity {
        path,
        authorized_thread: target_thread,
        executable_digest,
        capabilities,
        kernel_authorities,
        identity: crate::task::process::ApplicationIdentity::new(
            package,
            developer,
            subject_key,
            provenance,
        ),
        kind: authorization_kind,
        execution_class,
    };
    if crate::task::with_process_mut(target_pid, |process| {
        process.authorize_next_exec(authorization)
    })
    .is_none()
    {
        return Error::NotReady.into_raw();
    }
    0
}

/// Launches only the byte range selected by the authenticated boot module.
/// There is no filename lookup or fallback selection in the kernel.
pub(crate) fn launch_bootstrap_image(
    initial_caps: CapabilitySet,
    initial_kernel_authorities: KernelAuthoritySet,
    requested_privilege: crate::task::PrivilegeLevel,
) -> u64 {
    use mnu_abi::status::Error;

    let selected = match mnu_abi::boot_module::decode(crate::init::boot_data::boot_module_bytes()) {
        Ok(selected) => selected,
        Err(mnu_abi::boot_module::Error::ImageTooLarge) => return Error::LimitExceeded.into_raw(),
        Err(_) => return Error::InvalidArgument.into_raw(),
    };
    let data = selected.initial_image;
    crate::performance::increment(
        crate::performance::CounterMetric::ExecutableBytesRead,
        data.len() as u64,
    );
    crate::util::log::release_boot_marker(format_args!(
        "exec: boot-selected initial image ({} bytes)",
        data.len()
    ));
    let mut measurement = ExecMeasurement::start();
    let result = exec_with_data(
        data,
        // Userspace chooses names and executable identities for later images.
        "",
        "",
        Some(initial_caps),
        Some(initial_kernel_authorities),
        Some(requested_privilege),
        None,
        &[],
        &[],
        ImageLaunch::Bootstrap,
        &mut measurement,
    );
    measurement.finish(result)
}

pub(crate) fn map_initial_tls(table_phys: u64, aslr_seed: u64) -> Result<u64, mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    let exec = crate::config::kernel().exec;
    let tls_base = exec
        .tls_base_min
        .saturating_add(aslr_offset_pages(aslr_seed ^ 0x19d7_3c6a, exec.tls_aslr_max_pages) * 4096);
    let length = usize::try_from(exec.initial_tls_size)
        .ok()
        .filter(|&length| length >= core::mem::size_of::<u64>())
        .ok_or(Error::InvalidArgument)?;
    let mut tls_data = crate::util::object_snapshot::zeroed_native(length)?;
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
            Err(mapping_error_native(e))
        }
    }
}

fn build_relocatable_user_stack(
    aslr_seed: u64,
    startup: mnu_abi::process_image::StartupImage<'_>,
    phdr_vaddr: u64,
    phentsize: u64,
    phnum: u64,
    entry: u64,
) -> Result<InitialUserStack, mnu_abi::status::Error> {
    use mnu_abi::process_image::RelocationKind;
    use mnu_abi::status::Error;

    let exec = crate::config::kernel().exec;
    let stack_end_vaddr = exec.stack_top_base.saturating_sub(
        aslr_offset_pages(aslr_seed ^ 0x53a9_1e2d, exec.stack_aslr_max_pages) * 4096,
    );
    let stack_size = u64::try_from(exec.user_stack_size_pages)
        .ok()
        .and_then(|pages| pages.checked_mul(4096))
        .ok_or(Error::InvalidArgument)?;
    let stack_base_vaddr = stack_end_vaddr
        .checked_sub(stack_size)
        .ok_or(Error::InvalidArgument)?;
    let image_offset = 4096usize
        .checked_sub(startup.stack().len())
        .ok_or(Error::InvalidArgument)?;
    let image_base = stack_end_vaddr
        .checked_sub(startup.stack().len() as u64)
        .ok_or(Error::InvalidArgument)?;
    let mut page_data = crate::util::object_snapshot::zeroed_native(4096)?;
    page_data[image_offset..].copy_from_slice(startup.stack());
    for relocation in startup.relocations() {
        let offset = image_offset + relocation.offset as usize;
        let stored = u64::from_le_bytes(
            page_data[offset..offset + 8]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let value = match relocation.kind {
            RelocationKind::StackAddress => image_base
                .checked_add(stored)
                .ok_or(Error::InvalidArgument)?,
            RelocationKind::ElfProgramHeaders => phdr_vaddr,
            RelocationKind::ElfProgramHeaderSize => phentsize,
            RelocationKind::ElfProgramHeaderCount => phnum,
            RelocationKind::ElfEntry => entry,
            RelocationKind::PageSize => 4096,
        };
        page_data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let initial_rsp = image_base
        .checked_add(u64::from(startup.initial_stack_pointer()))
        .ok_or(Error::InvalidArgument)?;
    Ok(InitialUserStack {
        stack_base_vaddr,
        stack_end_vaddr,
        initial_rsp,
        page_data,
    })
}

fn exec_with_data(
    data: &[u8],
    process_name: &str,
    exec_path: &str,
    initial_caps: Option<CapabilitySet>,
    initial_kernel_authorities: Option<KernelAuthoritySet>,
    requested_privilege: Option<crate::task::PrivilegeLevel>,
    application_identity: Option<crate::task::process::ApplicationIdentity>,
    inherited_handles: &[InheritedHandleGrant],
    inherited_values: &[InheritedValueSpec],
    launch: ImageLaunch<'_>,
    measurement: &mut ExecMeasurement,
) -> u64 {
    use mnu_abi::status::Error;

    let is_boot_init = launch.is_bootstrap();
    let native_startup = launch.startup();
    let owned_identity = match storage::text(exec_path) {
        Ok(identity) => identity,
        Err(error) => return error.into_raw(),
    };
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
                crate::kernel::early_serial("exec: create page table failed\n");
                crate::warn!(
                    "Failed to create user page table for {}: {:?}",
                    process_name,
                    e
                );
                return mapping_error_native(e).into_raw();
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
            Err(error) => {
                crate::kernel::early_serial("exec: map ELF failed\n");
                crate::warn!(
                    "exec: invalid or unmappable ELF image '{}': {}",
                    exec_path,
                    error.into_raw()
                );
                return error.into_raw();
            }
        };

        let stack = if let Some(startup) = native_startup {
            build_relocatable_user_stack(aslr_seed, startup, phdr_vaddr, phentsize, phnum, entry)
        } else {
            let exec = crate::config::kernel().exec;
            let end = exec.stack_top_base.saturating_sub(
                aslr_offset_pages(aslr_seed ^ 0x53a9_1e2d, exec.stack_aslr_max_pages) * 4096,
            );
            bootstrap_stack::empty(end, exec.user_stack_size_pages)
        };
        let InitialUserStack {
            stack_base_vaddr,
            stack_end_vaddr,
            initial_rsp,
            page_data,
        } = match stack {
            Ok(stack) => stack,
            Err(error) => {
                crate::kernel::early_serial("exec: build stack failed\n");
                return error.into_raw();
            }
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
            crate::kernel::early_serial("exec: map stack lower failed\n");
            crate::warn!("Failed to allocate user stack lower: {:?}", e);
            return mapping_error_native(e).into_raw();
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
            crate::kernel::early_serial("exec: map stack top failed\n");
            crate::warn!("Failed to allocate user stack top: {:?}", e);
            return mapping_error_native(e).into_raw();
        }

        crate::debug!("User stack allocated successfully");

        // プロセスを作成してページテーブルをセット
        let privilege = resolve_exec_privilege(requested_privilege);
        const DEFAULT_PROCESS_PRIORITY: u8 = 8;
        let priority = DEFAULT_PROCESS_PRIORITY;
        let mut proc = match crate::task::Process::try_new(process_name, privilege, priority) {
            Ok(process) => process,
            Err(error) => return error.into_raw(),
        };
        proc.set_image_digest(Sha256::digest(data).into());
        if let Some(identity) = application_identity {
            proc.set_application_identity(identity);
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
        if let Err(error) = install_inherited_handles(&mut proc, inherited_handles) {
            return error.into_raw();
        }
        if let Err(error) = install_inherited_values(&mut proc, inherited_values) {
            return error.into_raw();
        }
        proc.set_page_table(new_pt_phys);
        proc.set_memory_regions(deferred_zero_regions);
        proc.set_stack_bottom(stack_base_vaddr);
        proc.set_stack_top(stack_end_vaddr + 4096);
        proc.set_exe_path(owned_identity);
        crate::debug!(
            "[STACK_INIT] {}: stack_base={:#x}, stack_end={:#x}, stack_top={:#x}",
            proc.name(),
            stack_base_vaddr,
            stack_end_vaddr,
            stack_end_vaddr + 4096
        );
        let initial_fs_base = match map_initial_tls(new_pt_phys, aslr_seed) {
            Ok(base) => base,
            Err(error) => {
                crate::kernel::early_serial("exec: map TLS failed\n");
                return error.into_raw();
            }
        };
        let pid = proc.id();
        // Allocate the creator's reference before publishing any runnable thread.
        let mut created_handle = CreatedProcessHandle(if native_startup.is_some() {
            match crate::syscall::handle::retain_created_process(&proc) {
                Ok(handle) => Some(handle),
                Err(error) => return error.into_raw(),
            }
        } else {
            None
        });
        if is_boot_init && !claim_init_pid(pid.as_u64()) {
            crate::kernel::early_serial("exec: init claim failed\n");
            crate::warn!("init is already running, rejecting duplicate launch");
            return Error::AlreadyExists.into_raw();
        }
        if crate::task::add_process(proc).is_none() {
            crate::kernel::early_serial("exec: add process failed\n");
            if is_boot_init {
                let _ = release_init_pid(pid.as_u64());
            }
            return Error::ResourceUnavailable.into_raw();
        }
        // allocate kernel stack for the new thread
        let kstack_size = crate::config::kernel().exec.kernel_thread_stack_size;
        let kstack =
            match crate::task::thread::allocate_kernel_stack_in_table(kstack_size, new_pt_phys) {
                Some(a) => a,
                None => {
                    crate::warn!("Failed to allocate kernel stack for thread");
                    let _ = crate::task::remove_process(pid);
                    if is_boot_init {
                        let _ = release_init_pid(pid.as_u64());
                    }
                    // The page-table guard still owns this table on this path.
                    return Error::ResourceUnavailable.into_raw();
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
        if native_startup.is_some() {
            thread.suspend();
        }

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
            return Error::ResourceUnavailable.into_raw();
        }

        crate::info!(
            "exec: started: {} pid={:?} entry={:#x}",
            exec_path,
            pid,
            entry
        );
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

        // Bootstrap returns the claimed process identity, not a thread ID.
        // Native creation returns a retained object while scheduling remains suspended.

        crate::debug!(
            "exec: created usermode process '{}' (pid={:?}, entry={:#x})",
            process_name,
            pid,
            entry
        );

        if let Some(handle) = created_handle.0.take() {
            handle
        } else {
            pid.as_u64()
        }
    }
}

fn check_image_byte_ceiling(
    table: u64,
    reservations: &[crate::task::MemoryRegion],
    byte_ceiling: u64,
) -> Result<(), mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    if byte_ceiling == u64::MAX {
        return Ok(());
    }
    use crate::mem::mapping_usage;
    // This detached root is privately owned by the preparation guard. No
    // process, fault handler or sibling can edit it during admission.
    let used = mapping_usage::bytes(
        reservations
            .iter()
            .map(|region| (region.start(), region.end().unwrap_or(u64::MAX))),
        |start, end| unsafe { crate::mem::paging::next_user_page_entry(table, start, end) },
    )
    .map_err(|error| match error {
        mapping_usage::Error::InvalidRange => Error::InvalidAddress,
        mapping_usage::Error::Backend(_) => Error::BackingFailure,
    })?;
    if !mapping_usage::permits(used, 0, byte_ceiling) {
        return Err(Error::ResourceUnavailable);
    }
    Ok(())
}

fn replace_current_process_image(
    data: &[u8],
    identity: &str,
    authorization: crate::task::process::PendingExecSecurity,
    startup: mnu_abi::process_image::StartupImage<'_>,
    byte_ceiling: u64,
    mut measurement: ExecMeasurement,
) -> Result<(u64, u64, u64), u64> {
    use mnu_abi::status::Error;

    let Some(process_id) = crate::syscall::security::current_process_id() else {
        return Err(Error::NotReady.into_raw());
    };
    let Some(transition) = crate::task::image_transition::begin_image_transition(process_id) else {
        return Err(Error::NotReady.into_raw());
    };

    let aslr_seed = next_aslr_seed(identity);
    let new_pt_phys = match crate::mem::paging::create_user_page_table() {
        Ok(page_table) => page_table,
        Err(error) => return Err(mapping_error_native(error).into_raw()),
    };
    let mut new_pt_guard = UserPageTableGuard::new(new_pt_phys);
    let ElfImageLayout {
        entry,
        phdr_vaddr,
        phentsize,
        phnum,
        mut deferred_zero_regions,
    } = match map_elf_image(data, new_pt_phys, &mut measurement) {
        Ok(layout) => layout,
        Err(error) => return Err(error.into_raw()),
    };
    let stack =
        build_relocatable_user_stack(aslr_seed, startup, phdr_vaddr, phentsize, phnum, entry);
    let InitialUserStack {
        stack_base_vaddr,
        stack_end_vaddr,
        initial_rsp,
        page_data,
    } = match stack {
        Ok(stack) => stack,
        Err(error) => return Err(error.into_raw()),
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
        return Err(mapping_error_native(error).into_raw());
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
        return Err(mapping_error_native(error).into_raw());
    }
    let initial_fs_base = match map_initial_tls(new_pt_phys, aslr_seed) {
        Ok(base) => base,
        Err(error) => return Err(error.into_raw()),
    };
    initial_mappings::prepare(new_pt_phys, startup, &mut deferred_zero_regions)
        .map_err(mnu_abi::status::Error::into_raw)?;
    // Admission precedes every destructive old-image operation, including
    // sibling retirement, borrowed mapping revocation, TLS/context edits and
    // launch-Handle retention. Failed preparation drops only the new root.
    check_image_byte_ceiling(new_pt_phys, &deferred_zero_regions, byte_ceiling)
        .map_err(mnu_abi::status::Error::into_raw)?;
    let current_tid = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return Err(Error::NotReady.into_raw()),
    };
    let pid = match crate::task::with_thread(current_tid, |thread| thread.process_id()) {
        Some(process) => process,
        None => return Err(Error::NotReady.into_raw()),
    };
    let kernel_stack =
        match crate::task::with_thread(current_tid, |thread| thread.kernel_stack_base()) {
            Some(base) => base,
            None => return Err(Error::NotReady.into_raw()),
        };
    let stack_mapping = crate::task::prepare_kernel_stack_user_table(kernel_stack, new_pt_phys)
        .ok_or(Error::ResourceUnavailable.into_raw())?;
    // Quiescence is reversible. In particular, a failed borrowed-PTE/TLB
    // transaction must resume siblings and keep the old stack alias/owner.
    let quiescence = crate::task::scheduler::quiesce_image_siblings(pid, current_tid);
    // Copy opaque metadata only after sibling Handle/context mutation stops.
    // Preparation is fallible and leaves the live context entirely untouched.
    let next_context = if startup.context_updates().next().is_some() {
        Some(
            crate::task::with_process(pid, |process| {
                process
                    .launch_context()
                    .patched(startup.context_updates(), |handle| {
                        process.object_handles().get(handle).is_some()
                    })
            })
            .ok_or_else(|| mnu_abi::status::Error::NotReady.into_raw())?
            .map_err(mnu_abi::status::Error::into_raw)?,
        )
    } else {
        None
    };
    let next_image_revision = crate::task::with_process(pid, |process| {
        process.process_object().next_image_revision()
    })
    .ok_or_else(|| Error::NotReady.into_raw())?
    .ok_or_else(|| Error::LimitExceeded.into_raw())?;
    let next_ipc_generation = crate::task::ipc_generation::reserve()
        .ok_or_else(|| Error::LimitExceeded.into_raw())?;
    crate::task::release_process_borrowed_mappings(pid)?;
    crate::task::scheduler::retire_image_siblings(pid, current_tid);
    stack_mapping.commit();
    crate::task::with_thread_mut(current_tid, |thread| thread.set_fs_base(initial_fs_base));
    let old_pt_phys = crate::task::with_process_mut(pid, |process| {
        let previous = process.page_table();
        process.set_page_table(new_pt_phys);
        process.set_mapping_cursor(0);
        process.set_ipc_mapping_end(0);
        process.set_memory_regions(deferred_zero_regions);
        process.set_stack_bottom(stack_base_vaddr);
        process.set_stack_top(stack_end_vaddr + 4096);
        process.set_exe_path(authorization.path);
        process.set_capabilities_for_exec(authorization.capabilities);
        process.set_kernel_authorities_for_exec(crate::capability::KernelAuthoritySet::empty());
        process.set_application_identity(authorization.identity);
        process.set_image_digest(authorization.executable_digest);
        if let Some(context) = next_context {
            *process.launch_context_mut() = context;
        }
        process.retain_launch_context_handles_for_exec();
        process
            .process_object()
            .commit_image_revision(next_image_revision);
        previous
    })
    .flatten();
    crate::syscall::ipc::replace_thread_image_endpoint(current_tid, next_ipc_generation);
    // The new address space is committed. No old upcall entry, stack or saved
    // user context may be used when this native thread enters the new image.
    crate::task::with_thread_mut(current_tid, |thread| {
        thread.clear_upcall_for_image_replace();
    });
    if let Some(old) = old_pt_phys {
        if old != new_pt_phys {
            let _ = crate::mem::paging::destroy_user_page_table(old);
        }
    }
    new_pt_guard.disarm();
    measurement.record();
    drop(quiescence);
    drop(transition);
    Ok((new_pt_phys, entry, initial_rsp))
}

/// Replaces the current process image from an already-authorized object
/// handle. The kernel treats `identity` as an opaque authorization key and the
/// startup image as an opaque byte layout plus a small set of ELF relocations;
/// POSIX argv/envp construction remains entirely in user space.
pub fn process_image_replace_syscall(
    image_handle: u64,
    identity_ptr: u64,
    identity_len: u64,
    startup_ptr: u64,
    startup_len: u64,
) -> u64 {
    process_image_replace_impl(
        image_handle,
        identity_ptr,
        identity_len,
        startup_ptr,
        startup_len,
        u64::MAX,
    )
}

pub fn process_image_replace_bounded_syscall(
    image_handle: u64,
    identity_ptr: u64,
    identity_len: u64,
    startup_ptr: u64,
    startup_len: u64,
    byte_ceiling: u64,
) -> u64 {
    process_image_replace_impl(
        image_handle,
        identity_ptr,
        identity_len,
        startup_ptr,
        startup_len,
        byte_ceiling,
    )
}

fn process_image_replace_impl(
    image_handle: u64,
    identity_ptr: u64,
    identity_len: u64,
    startup_ptr: u64,
    startup_len: u64,
    byte_ceiling: u64,
) -> u64 {
    use mnu_abi::status::Error;

    const MAX_IDENTITY_BYTES: usize = 256;
    const MAX_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;
    const MAX_STARTUP_IMAGE_BYTES: usize = mnu_abi::process_image::MAX_IMAGE_BYTES;

    if !caller_has_process_spawn_capability() {
        return Error::AccessDenied.into_raw();
    }
    let Ok(identity_len) = usize::try_from(identity_len) else {
        return Error::InvalidArgument.into_raw();
    };
    let Ok(startup_len) = usize::try_from(startup_len) else {
        return Error::InvalidArgument.into_raw();
    };
    if identity_len == 0
        || identity_len > MAX_IDENTITY_BYTES
        || startup_len == 0
        || startup_len > MAX_STARTUP_IMAGE_BYTES
    {
        return Error::InvalidArgument.into_raw();
    }

    let identity_bytes = match storage::from_user_native(identity_ptr, identity_len) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    if identity_bytes.contains(&0) {
        return Error::InvalidArgument.into_raw();
    }
    let identity = match core::str::from_utf8(&identity_bytes) {
        Ok(identity) => identity,
        Err(_) => return Error::InvalidArgument.into_raw(),
    };

    let startup_bytes = match storage::from_user_native(startup_ptr, startup_len) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    let startup = match mnu_abi::process_image::decode(&startup_bytes) {
        Ok(startup) => startup,
        Err(_) => return Error::InvalidArgument.into_raw(),
    };

    let Some(pid) = crate::syscall::security::current_process_id() else {
        return Error::NotReady.into_raw();
    };
    let Some(thread) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    let authorization = match crate::task::with_process_mut(pid, |process| {
        process.take_exec_authorization(identity, thread)
    }) {
        Some(Some(authorization)) => authorization,
        Some(None) => return Error::AccessDenied.into_raw(),
        None => return Error::NotReady.into_raw(),
    };
    if authorization.kind != crate::task::process::PendingExecKind::ImageReplace
        || authorization.execution_class != ExecutionClass::Unprivileged
    {
        return Error::AccessDenied.into_raw();
    }

    let executable = match crate::syscall::handle::read_all(image_handle, MAX_EXECUTABLE_BYTES) {
        Ok(executable) => executable,
        Err(errno) => return errno,
    };
    let digest: [u8; 32] = Sha256::digest(&executable).into();
    if digest != authorization.executable_digest {
        return Error::AccessDenied.into_raw();
    }

    let (page_table, entry, stack_pointer) = match replace_current_process_image(
        &executable,
        identity,
        authorization,
        startup,
        byte_ceiling,
        ExecMeasurement::start(),
    ) {
        Ok(image) => image,
        Err(errno) => return errno,
    };
    // Entering the image abandons this kernel stack rather than unwinding it.
    // The preparation frame has returned (dropping page_data and its guards);
    // release every owning input buffer before the non-returning transition.
    drop(executable);
    drop(startup_bytes);
    drop(identity_bytes);
    unsafe {
        x86_64::instructions::interrupts::disable();
        crate::mem::paging::switch_page_table(page_table);
        crate::task::jump_to_usermode(entry, stack_pointer, 0);
    }
}

/// Creates a stopped process from an authorized image object. No path lookup,
/// argv/envp convention, credentials, child relationship, or service discovery
/// is supplied by this entry point. The caller explicitly resumes the result.
pub fn process_create_syscall(image_handle: u64, request_ptr: u64, request_len: u64) -> u64 {
    use mnu_abi::status::Error;

    if !caller_has_process_spawn_capability() {
        return Error::AccessDenied.into_raw();
    }
    let length = match usize::try_from(request_len) {
        Ok(length) if length > 0 && length <= mnu_abi::process_create::MAX_REQUEST_BYTES => length,
        _ => return Error::InvalidArgument.into_raw(),
    };
    let bytes = match storage::from_user_native(request_ptr, length) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    let request = match mnu_abi::process_create::decode(&bytes) {
        Ok(request) => request,
        Err(_) => return Error::InvalidArgument.into_raw(),
    };
    let Some(owner) = crate::syscall::security::current_process_id() else {
        return Error::NotReady.into_raw();
    };
    let Some(thread) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    let authorization = match crate::task::with_process_mut(owner, |process| {
        process.take_exec_authorization(request.identity, thread)
    }) {
        Some(Some(authorization)) => authorization,
        Some(None) => return Error::AccessDenied.into_raw(),
        None => return Error::NotReady.into_raw(),
    };
    if authorization.kind != crate::task::process::PendingExecKind::Spawn {
        return Error::AccessDenied.into_raw();
    }
    let mut specs = Vec::new();
    if specs.try_reserve_exact(request.handles().count()).is_err() {
        return Error::ResourceUnavailable.into_raw();
    }
    for grant in request.handles() {
        let Some(source) = crate::task::ObjectHandle::from_raw(grant.source) else {
            return Error::InvalidArgument.into_raw();
        };
        let Some(rights) = crate::task::HandleRights::from_bits(grant.rights) else {
            return Error::InvalidArgument.into_raw();
        };
        specs.push(InheritedHandleSpec {
            key: grant.key,
            source,
            target: grant.target,
            rights,
        });
    }
    let grants = match if let Some(capture) = request.handle_capture {
        captured_handles::export(u64::from(capture), &specs)
    } else {
        export_inherited_handles(Some(owner), &specs)
    } {
        Ok(grants) => grants,
        Err(error) => return error.into_raw(),
    };
    let mut values = Vec::new();
    if values.try_reserve_exact(request.values().count()).is_err() {
        return Error::ResourceUnavailable.into_raw();
    }
    values.extend(request.values().map(|value| InheritedValueSpec {
        key: value.key,
        value: value.value,
    }));
    let startup = match request.startup {
        mnu_abi::process_create::InitialState::Image(startup) => {
            // Mapping plans are currently an image-replacement operation.
            // Never accept and silently ignore a requested initial mapping.
            if startup.mappings().next().is_some() || startup.context_updates().next().is_some() {
                return Error::InvalidArgument.into_raw();
            }
            startup
        }
        mnu_abi::process_create::InitialState::Context(context) => {
            return create_from_address_space(
                image_handle,
                &request,
                context,
                authorization,
                &grants,
                &values,
            );
        }
    };
    let executable = match crate::syscall::handle::read_all(image_handle, 64 * 1024 * 1024) {
        Ok(executable) => executable,
        Err(errno) => return errno,
    };
    let digest: [u8; 32] = Sha256::digest(&executable).into();
    if digest != authorization.executable_digest {
        return Error::AccessDenied.into_raw();
    }
    let privilege = match authorization.execution_class {
        ExecutionClass::Privileged => crate::task::PrivilegeLevel::Service,
        ExecutionClass::Unprivileged => crate::task::PrivilegeLevel::User,
    };
    let mut measurement = ExecMeasurement::start();
    let result = exec_with_data(
        &executable,
        request.label,
        request.identity,
        Some(authorization.capabilities),
        Some(authorization.kernel_authorities),
        Some(privilege),
        Some(authorization.identity),
        &grants,
        &values,
        ImageLaunch::Created(startup),
        &mut measurement,
    );
    measurement.finish(result)
}

fn consume_address_space_for_create(
    image: &crate::mem::address_space::AddressSpaceObject,
    authorization: &crate::task::process::PendingExecSecurity,
    context: &mnu_abi::ThreadCreateContext,
) -> Result<crate::mem::address_space::AddressSpaceImage, mnu_abi::status::Error> {
    use crate::mem::address_space::ConsumeError;
    use mnu_abi::status::Error;
    let pid = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
    // Detached roots are pinned by the image, but resize may still revoke
    // their PTEs. Follow PROC -> image lock order through context validation
    // and one-shot ownership transfer, then prepare the new container outside.
    crate::task::with_process(pid, |_| image.consume(authorization, context))
        .ok_or(Error::NotReady)?
        .map_err(|error| match error {
            ConsumeError::Consumed => Error::NotReady,
            ConsumeError::Backing(error) => error,
            ConsumeError::Authorization => Error::AccessDenied,
            ConsumeError::Context => Error::InvalidAddress,
        })
}

fn create_from_address_space(
    image_handle: u64,
    request: &mnu_abi::process_create::Request<'_>,
    context: mnu_abi::ThreadCreateContext,
    authorization: crate::task::process::PendingExecSecurity,
    grants: &[InheritedHandleGrant],
    values: &[InheritedValueSpec],
) -> u64 {
    use mnu_abi::status::Error;
    let image =
        match crate::syscall::handle::object_native(image_handle, crate::task::HandleRights::CONTROL) {
            Ok(crate::task::KernelObject::AddressSpace(image)) => image,
            Ok(_) => return Error::InvalidArgument.into_raw(),
            Err(error) => return error.into_raw(),
        };
    let privilege = match authorization.execution_class {
        ExecutionClass::Privileged => crate::task::PrivilegeLevel::Service,
        ExecutionClass::Unprivileged => crate::task::PrivilegeLevel::User,
    };
    let mut process = match crate::task::Process::try_new(request.label, privilege, 8) {
        Ok(process) => process,
        Err(error) => return error.into_raw(),
    };
    // Only the explicit grants are installed. No creator table, relationship,
    // resource policy, or execution identity is implicitly inherited.
    if let Err(error) = install_inherited_handles(&mut process, grants) {
        return error.into_raw();
    }
    if let Err(error) = install_inherited_values(&mut process, values) {
        return error.into_raw();
    }
    let image = match consume_address_space_for_create(&image, &authorization, &context) {
        Ok(image) => image,
        Err(error) => return error.into_raw(),
    };
    process.set_capabilities_for_exec(authorization.capabilities);
    process.set_kernel_authorities_for_exec(authorization.kernel_authorities);
    process.set_application_identity(authorization.identity);
    process.set_image_digest(authorization.executable_digest);
    process.set_exe_path(authorization.path);
    if image.install(&mut process).is_err() {
        return Error::InvalidArgument.into_raw();
    }
    let Some(table) = process.page_table() else {
        return Error::NotReady.into_raw();
    };
    // From installation until publication the guard owns the table. It also
    // reclaims it on any creator-handle, kernel-stack, or thread failure.
    let Some(root) = process.pending_image_root().cloned() else {
        return Error::NotReady.into_raw();
    };
    let mut table_guard = UserPageTableGuard::for_image(root);
    let mut handle = match crate::syscall::handle::retain_created_process(&process) {
        Ok(handle) => CreatedProcessHandle(Some(handle)),
        Err(error) => return error.into_raw(),
    };
    let stack_size = crate::config::kernel().exec.kernel_thread_stack_size;
    let stack = match crate::task::allocate_kernel_stack_in_table(stack_size, table) {
        Some(stack) => stack,
        None => return Error::ResourceUnavailable.into_raw(),
    };
    let r = context.registers;
    let state = crate::task::thread::SyscallUserContext {
        rip: context.entry,
        rsp: context.stack_pointer,
        rflags: 0x202,
        rdi: context.argument,
        rsi: r.rsi,
        rdx: r.rdx,
        rbp: r.rbp,
        rbx: r.rbx,
        rcx: r.rcx,
        r11: r.r11,
        r8: r.r8,
        r9: r.r9,
        r10: r.r10,
        r12: r.r12,
        r13: r.r13,
        r14: r.r14,
        r15: r.r15,
    };
    let pid = process.id();
    let mut thread = crate::task::Thread::new_user_resume(
        pid,
        state,
        r.rax,
        context.thread_local_base,
        stack,
        stack_size,
    );
    thread.suspend();
    if crate::task::add_process(process).is_none() {
        crate::task::free_kernel_stack(stack);
        return Error::ResourceUnavailable.into_raw();
    }
    if crate::task::add_thread(thread).is_none() {
        let _ = crate::task::remove_process(pid);
        crate::task::free_kernel_stack(stack);
        return Error::ResourceUnavailable.into_raw();
    }
    table_guard.disarm();
    handle.0.take().unwrap_or_else(|| Error::NotReady.into_raw())
}
