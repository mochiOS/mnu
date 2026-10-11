//! システムコール

pub mod address_wait;
pub mod capability;
pub mod dma;
pub mod event;
pub mod exec;
pub mod execution;
pub mod fs;
pub mod handle;
pub mod io;
pub mod ipc;
pub mod performance;
pub mod memory;
pub mod process;
pub mod security;
pub mod storage;
pub mod syscall_entry;
pub mod task;
pub mod time;
pub mod upcall;

mod types;

use crate::capability::{KernelAuthority, KernelCapability, KernelObjectRef};
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

const FIRMWARE_PRESENT_MAX: usize = mnu_abi::hypervisor::FIRMWARE_FRAMEBUFFER_MAX_TRANSFER;
static FIRMWARE_PRESENT_BUFFER: crate::interrupt::spinlock::SpinLock<[u8; FIRMWARE_PRESENT_MAX]> =
    crate::interrupt::spinlock::SpinLock::new([0; FIRMWARE_PRESENT_MAX]);
const PLATFORM_PRESENT_MAX: usize = 1024 * 1024;
static PLATFORM_PRESENT_BUFFER: crate::interrupt::spinlock::SpinLock<Vec<u8>> =
    crate::interrupt::spinlock::SpinLock::new(Vec::new());

/// ユーザー空間ポインタの有効性を検証する
///
/// ポインタが null でなく、ユーザー空間のアドレス範囲内にあること、
/// かつ `ptr + len` がオーバーフローしないことを確認する。
///
/// x86-64 canonical ユーザー空間上限: 0x0000_7FFF_FFFF_FFFF
pub fn validate_user_ptr(ptr: u64, len: u64) -> bool {
    if !is_canonical_user_range(ptr, len) {
        return false;
    }
    if len == 0 {
        return true;
    }

    let pid = match crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |thread| thread.process_id()))
    {
        Some(pid) => pid,
        None => return false,
    };
    crate::task::with_process(pid, |process| {
        let Some(table_phys) = process.page_table() else {
            return false;
        };
        if crate::mem::paging::is_user_range_mapped_in_table(table_phys, ptr, len) {
            return true;
        }
        let end = ptr + len;
        let mut address = ptr;
        while address < end {
            let next_page = (address | 0xfff).saturating_add(1).min(end);
            let chunk_len = next_page - address;
            let resident =
                crate::mem::paging::is_user_range_mapped_in_table(table_phys, address, chunk_len);
            if !resident {
                let valid_region = process.find_memory_region(address).is_some_and(|region| {
                    region.allows_read_at(address)
                        && region
                            .end()
                            .is_some_and(|region_end| next_page <= region_end)
                });
                if !valid_region {
                    return false;
                }
            }
            address = next_page;
        }
        true
    })
    .unwrap_or(false)
}

fn current_user_page_table() -> Option<u64> {
    crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |t| t.process_id()))
        .and_then(|pid| crate::task::with_process(pid, |p| p.page_table()))
        .flatten()
}

fn is_canonical_user_range(addr: u64, len: u64) -> bool {
    const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
    if addr == 0 || addr > USER_SPACE_END {
        return false;
    }
    let end_inclusive = if len == 0 {
        addr
    } else {
        match addr.checked_add(len - 1) {
            Some(end) => end,
            None => return false,
        }
    };
    end_inclusive <= USER_SPACE_END
}

fn current_process_name_for_log() -> Option<String> {
    let pid = crate::syscall::security::current_process_id()?;
    crate::task::with_process(pid, |p| p.name().to_string())
}

/// ユーザー空間の null 終端文字列を最大長付きで読み取り、カーネル所有の `String` を返す。
pub fn read_user_cstring(ptr: u64, max_len: usize) -> Result<String, u64> {
    if ptr == 0 || max_len == 0 {
        return Err(EINVAL);
    }

    let mut bytes = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let addr = ptr.checked_add(i as u64).ok_or(EFAULT)?;
        let mut one = [0u8; 1];
        copy_from_user(addr, &mut one)?;
        let b = one[0];
        if b == 0 {
            return String::from_utf8(bytes).map_err(|_| EINVAL);
        }
        bytes.push(b);
    }
    Err(EINVAL)
}

pub fn map_physical_range(virt_addr: u64, phys_addr: u64, size: u64) -> u64 {
    use crate::syscall::types::{EACCES, EINVAL, ENOMEM, EPERM, SUCCESS};
    if virt_addr == 0
        || size == 0
        || (virt_addr & 0xfff) != 0
        || (phys_addr & 0xfff) != 0
        || (size & 0xfff) != 0
    {
        return EINVAL;
    }
    if !is_canonical_user_range(virt_addr, size) {
        return EINVAL;
    }
    if !crate::mem::frame::is_allowed_mmio_range(phys_addr, size) {
        crate::audit::log(
            crate::audit::AuditEventKind::Policy,
            "MapPhysicalRange rejected non-MMIO or allocator-owned physical range",
        );
        return EPERM;
    }

    let pid = match crate::syscall::security::current_process_id() {
        Some(pid) => pid,
        None => return ENOMEM,
    };
    let requested_authority = KernelAuthority::new(
        KernelCapability::PhysMap,
        KernelObjectRef::MmioRegion {
            base: phys_addr,
            size,
        },
    );
    let has_mmio_device = crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::DeviceGpu,
        crate::capability::Capability::DeviceNet,
        crate::capability::Capability::SerialAccess,
    ]);
    if !has_mmio_device && !crate::task::process_has_kernel_authority(pid, &requested_authority) {
        return EACCES;
    }
    let pt_phys = match crate::task::with_process(pid, |proc| proc.page_table()).flatten() {
        Some(pt) => pt,
        None => return ENOMEM,
    };

    let writable = true;
    let mapping = crate::task::MmioMapping::new(virt_addr, size, phys_addr, writable);
    let admitted = crate::task::with_process_mut(pid, |proc| {
        if proc.mmio_mapping_count() >= proc.resource_limits().max_mmio_ranges {
            return Err(ENOMEM);
        }
        if !proc.add_mmio_mapping(mapping.clone()) {
            return Err(EINVAL);
        }
        Ok(())
    });
    match admitted {
        Some(Ok(())) => {}
        Some(Err(errno)) => return errno,
        None => return ENOMEM,
    }

    if crate::mem::paging::map_physical_range_to_user(
        pt_phys,
        virt_addr,
        phys_addr,
        size,
        crate::mem::paging::MappingCache::Uncached,
    )
    .is_err()
    {
        let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(pt_phys, virt_addr, size);
        let _ =
            crate::task::with_process_mut(pid, |proc| proc.remove_mmio_mapping(virt_addr, size));
        return ENOMEM;
    }

    SUCCESS
}

pub fn get_physical_addr(virt_addr: u64) -> u64 {
    use crate::capability::Capability;
    use crate::syscall::types::{EACCES, EFAULT, ENOMEM};

    if !crate::syscall::security::caller_has_any_capability(&[Capability::MemoryPhysTranslate]) {
        return EACCES;
    }
    if !validate_user_ptr(virt_addr, 1) {
        return EFAULT;
    }
    let pt_phys = match current_user_page_table() {
        Some(pt) => pt,
        None => return ENOMEM,
    };
    crate::mem::paging::virt_to_phys_in_table(pt_phys, virt_addr).unwrap_or(EFAULT)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserFramebufferInfo {
    addr: u64,
    size: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
}

pub fn get_framebuffer_info(out_ptr: u64) -> u64 {
    use crate::syscall::types::{ENXIO, SUCCESS};

    let mediated = crate::hypervisor_guest::is_active();
    let out = if let Some(info) = crate::util::vga::get_info() {
        UserFramebufferInfo {
            addr: if mediated { 0 } else { info.addr },
            size: info.size as u64,
            width: info.width as u32,
            height: info.height as u32,
            stride: info.stride as u32,
            format: 1 | if mediated {
                mnu_abi::hypervisor::FRAMEBUFFER_FORMAT_MEDIATED
            } else {
                0
            },
        }
    } else if let Some(info) = mediated
        .then(crate::platform::display_info)
        .transpose()
        .ok()
        .flatten()
    {
        UserFramebufferInfo {
            addr: info.surface_address,
            size: if info.shared_surface {
                info.surface_size
            } else {
                u64::from(info.stride)
                    .saturating_mul(u64::from(info.height))
                    .saturating_mul(4)
            },
            width: info.width,
            height: info.height,
            stride: info.stride,
            format: 1 | if info.shared_surface {
                mnu_abi::hypervisor::FRAMEBUFFER_FORMAT_SHARED_SURFACE
            } else {
                0
            },
        }
    } else {
        return ENXIO;
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&out as *const UserFramebufferInfo).cast::<u8>(),
            core::mem::size_of::<UserFramebufferInfo>(),
        )
    };
    match copy_to_user(out_ptr, bytes) {
        Ok(()) => SUCCESS,
        Err(err) => err,
    }
}

pub fn present_framebuffer(position: u64, size: u64, pixels_ptr: u64, pixels_len: u64) -> u64 {
    use crate::capability::Capability;
    use crate::syscall::types::{EACCES, EFAULT, EINVAL, EIO, SUCCESS};

    if !crate::syscall::security::caller_has_any_capability(&[Capability::DisplayRead]) {
        return EACCES;
    }
    let x = position as u32;
    let y = (position >> 32) as u32;
    let width = size as u32;
    let height = (size >> 32) as u32;
    let Some(expected) = usize::try_from(width)
        .ok()
        .and_then(|width| {
            usize::try_from(height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
    else {
        return EINVAL;
    };
    if pixels_ptr == 0 || pixels_len != expected as u64 || expected == 0 {
        return EINVAL;
    }
    if crate::hypervisor_guest::is_active() && crate::util::vga::get_info().is_some() {
        if expected > FIRMWARE_PRESENT_MAX {
            return EINVAL;
        }
        let mut buffer = FIRMWARE_PRESENT_BUFFER.lock();
        if copy_from_user(pixels_ptr, &mut buffer[..expected]).is_err() {
            return EFAULT;
        }
        let result = crate::hypervisor_guest::invoke(
            mnu_abi::hypervisor::HypercallNumber::FirmwareFramebufferPresent,
            position,
            size,
            buffer.as_ptr() as u64,
        );
        return if result == mnu_abi::hypervisor::HYPERCALL_SUCCESS {
            SUCCESS
        } else {
            EIO
        };
    }
    let transfer_limit = match crate::platform::display_transfer_limit() {
        Ok(limit) if limit != 0 && limit <= PLATFORM_PRESENT_MAX => limit,
        _ => return EIO,
    };
    if expected > transfer_limit {
        return EINVAL;
    }
    let mut pixels = PLATFORM_PRESENT_BUFFER.lock();
    if expected > pixels.len() {
        let additional = expected - pixels.len();
        if pixels.try_reserve_exact(additional).is_err() {
            return crate::syscall::types::ENOMEM;
        }
        pixels.resize(expected, 0);
    }
    if copy_from_user(pixels_ptr, &mut pixels[..expected]).is_err() {
        return EFAULT;
    }
    match crate::platform::present_display(x, y, width, height, &pixels[..expected]) {
        Ok(()) => SUCCESS,
        Err(_) => EIO,
    }
}

pub fn framebuffer_transfer_limit() -> u64 {
    use crate::capability::Capability;
    use crate::syscall::types::{EACCES, EIO};

    if !crate::syscall::security::caller_has_any_capability(&[Capability::DisplayRead]) {
        return EACCES;
    }
    if crate::hypervisor_guest::is_active() && crate::util::vga::get_info().is_some() {
        return FIRMWARE_PRESENT_MAX as u64;
    }
    match crate::platform::display_transfer_limit() {
        Ok(limit) if limit != 0 && limit <= PLATFORM_PRESENT_MAX => limit as u64,
        _ => EIO,
    }
}

pub fn commit_framebuffer(position: u64, size: u64) -> u64 {
    use crate::capability::Capability;
    use crate::syscall::types::{EACCES, EINVAL, EIO, SUCCESS};

    if !crate::syscall::security::caller_has_any_capability(&[Capability::DisplayRead]) {
        return EACCES;
    }
    let x = position as u32;
    let y = (position >> 32) as u32;
    let width = size as u32;
    let height = (size >> 32) as u32;
    if width == 0 || height == 0 {
        return EINVAL;
    }
    match crate::platform::commit_display(x, y, width, height) {
        Ok(()) => SUCCESS,
        Err(_) => EIO,
    }
}

pub fn map_framebuffer(virt_addr: u64, size: u64) -> u64 {
    use crate::capability::Capability;
    use crate::syscall::types::{EACCES, EINVAL, ENOMEM, ENXIO, SUCCESS};

    if !crate::syscall::security::caller_has_any_capability(&[Capability::DisplayRead]) {
        return EACCES;
    }
    if virt_addr == 0 || size == 0 || (virt_addr & 0xfff) != 0 || (size & 0xfff) != 0 {
        return EINVAL;
    }
    let shared_surface = crate::platform::display_info()
        .ok()
        .filter(|info| info.shared_surface && info.surface_address != 0 && info.surface_size != 0);
    let (fb_base, fb_offset, framebuffer_size, mmio) = if let Some(info) = shared_surface {
        (
            info.surface_address & !0xfff,
            info.surface_address & 0xfff,
            info.surface_size,
            false,
        )
    } else if let Some(info) = crate::util::vga::get_info() {
        (
            info.addr & !0xfff,
            info.addr & 0xfff,
            info.size as u64,
            true,
        )
    } else {
        return ENXIO;
    };
    let required = match framebuffer_size.checked_add(fb_offset) {
        Some(v) => (v + 0xfff) & !0xfff,
        None => return EINVAL,
    };
    if size < required {
        return EINVAL;
    }
    if mmio && !crate::mem::frame::is_allowed_mmio_range(fb_base, required) {
        return EACCES;
    }
    let Some(pid) = crate::syscall::security::current_process_id() else {
        return ENOMEM;
    };
    let Some(pt_phys) = crate::task::with_process(pid, |proc| proc.page_table()).flatten() else {
        return ENOMEM;
    };
    let cache = if mmio {
        crate::mem::paging::MappingCache::Uncached
    } else {
        crate::mem::paging::MappingCache::WriteBack
    };
    if crate::mem::paging::map_physical_range_to_user(pt_phys, virt_addr, fb_base, required, cache)
        .is_err()
    {
        return ENOMEM;
    }
    SUCCESS
}

/// ユーザー空間からバイト列をコピーする（コピー先はカーネル空間）。
pub fn copy_from_user(src_ptr: u64, dst: &mut [u8]) -> Result<(), u64> {
    if dst.is_empty() {
        return Ok(());
    }
    let user_pt = match current_user_page_table() {
        Some(pt) => pt,
        None => return Err(EFAULT),
    };
    if src_ptr == 0 {
        return Err(EFAULT);
    }
    let mut result = crate::mem::paging::copy_from_user_in_table(user_pt, src_ptr, dst);
    if result.is_err() && fault_in_user_range(user_pt, src_ptr, dst.len() as u64, false) {
        result = crate::mem::paging::copy_from_user_in_table(user_pt, src_ptr, dst);
    }
    result.map_err(|err| {
        let (syscall_num, syscall_args) = last_syscall_snapshot();
        let pid = crate::syscall::security::current_process_id()
            .map(|pid| pid.as_u64())
            .unwrap_or(0);
        let process_name = current_process_name_for_log().unwrap_or_else(|| "?".to_string());
        crate::audit::log(
            crate::audit::AuditEventKind::Usercopy,
            &format!(
                "copy_from_user rejected unmapped or unreadable range pid={} process={} src={:#x} len={} last_syscall={} args=[{:#x},{:#x},{:#x},{:#x},{:#x}]",
                pid,
                process_name,
                src_ptr,
                dst.len(),
                syscall_num,
                syscall_args[0],
                syscall_args[1],
                syscall_args[2],
                syscall_args[3],
                syscall_args[4]
            ),
        );
        match err {
            crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::PermissionDenied) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::InvalidAddress) => EFAULT,
            _ => EFAULT,
        }
    })
}

#[inline(never)]
fn fault_in_user_range(table_phys: u64, address: u64, len: u64, write: bool) -> bool {
    if !is_canonical_user_range(address, len) {
        return false;
    }

    let end = address + len - 1;
    let mut page = address & !0xfff;
    let end_page = end & !0xfff;
    loop {
        let resident = if write {
            crate::mem::paging::is_user_range_writable_in_table(table_phys, page, 1)
        } else {
            crate::mem::paging::is_user_range_mapped_in_table(table_phys, page, 1)
        };
        if !resident && !process::handle_user_memory_fault(page, write, false) {
            return false;
        }
        if page == end_page {
            return true;
        }
        page += 4096;
    }
}

/// バイト列をユーザー空間へコピーする（コピー元はカーネル空間）。
pub fn copy_to_user(dst_ptr: u64, src: &[u8]) -> Result<(), u64> {
    if src.is_empty() {
        return Ok(());
    }
    let user_pt = match current_user_page_table() {
        Some(pt) => pt,
        None => return Err(EFAULT),
    };
    if dst_ptr == 0 {
        return Err(EFAULT);
    }
    let mut result = crate::mem::paging::copy_to_user_in_table(user_pt, dst_ptr, src);
    if result.is_err() && fault_in_user_range(user_pt, dst_ptr, src.len() as u64, true) {
        result = crate::mem::paging::copy_to_user_in_table(user_pt, dst_ptr, src);
    }
    result.map_err(|err| {
        let (syscall_num, syscall_args) = last_syscall_snapshot();
        let pid = crate::syscall::security::current_process_id()
            .map(|pid| pid.as_u64())
            .unwrap_or(0);
        let process_name = current_process_name_for_log().unwrap_or_else(|| "?".to_string());
        crate::audit::log(
            crate::audit::AuditEventKind::Usercopy,
            &format!(
                "copy_to_user rejected unmapped or unwritable range pid={} process={} dst={:#x} len={} last_syscall={} args=[{:#x},{:#x},{:#x},{:#x},{:#x}]",
                pid,
                process_name,
                dst_ptr,
                src.len(),
                syscall_num,
                syscall_args[0],
                syscall_args[1],
                syscall_args[2],
                syscall_args[3],
                syscall_args[4]
            ),
        );
        match err {
            crate::Kernel::Memory(crate::result::Memory::OutOfMemory) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::PermissionDenied) => EFAULT,
            crate::Kernel::Memory(crate::result::Memory::InvalidAddress) => EFAULT,
            _ => EFAULT,
        }
    })
}

pub fn read_user_u64(ptr: u64) -> Result<u64, u64> {
    let mut buf = [0u8; 8];
    copy_from_user(ptr, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

pub fn read_user_u32(ptr: u64) -> Result<u32, u64> {
    let mut buf = [0u8; 4];
    copy_from_user(ptr, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

pub fn read_user_i64(ptr: u64) -> Result<i64, u64> {
    let mut buf = [0u8; 8];
    copy_from_user(ptr, &mut buf)?;
    Ok(i64::from_ne_bytes(buf))
}

pub fn read_user_i32(ptr: u64) -> Result<i32, u64> {
    let mut buf = [0u8; 4];
    copy_from_user(ptr, &mut buf)?;
    Ok(i32::from_ne_bytes(buf))
}

pub fn read_user_u16(ptr: u64) -> Result<u16, u64> {
    let mut buf = [0u8; 2];
    copy_from_user(ptr, &mut buf)?;
    Ok(u16::from_ne_bytes(buf))
}

pub fn write_user_u64(ptr: u64, value: u64) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub fn write_user_u32(ptr: u64, value: u32) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub fn write_user_i32(ptr: u64, value: i32) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub fn write_user_u16(ptr: u64, value: u16) -> Result<(), u64> {
    copy_to_user(ptr, &value.to_ne_bytes())
}

pub use types::*;

const _: () = {
    assert!(
        mochios_filesystem_protocol::SYS_FILESYSTEM_REGISTER
            == mnu_abi::SyscallNumber::FilesystemRegister as u64
    );
    assert!(
        mochios_filesystem_protocol::SYS_FILESYSTEM_MOUNT
            == mnu_abi::SyscallNumber::FilesystemMount as u64
    );
};

use core::sync::atomic::{AtomicU64, Ordering};

static LAST_SYSCALL_NUM: AtomicU64 = AtomicU64::new(0);
static LAST_SYSCALL_ARG0: AtomicU64 = AtomicU64::new(0);
static LAST_SYSCALL_ARG1: AtomicU64 = AtomicU64::new(0);
static LAST_SYSCALL_ARG2: AtomicU64 = AtomicU64::new(0);
static LAST_SYSCALL_ARG3: AtomicU64 = AtomicU64::new(0);
static LAST_SYSCALL_ARG4: AtomicU64 = AtomicU64::new(0);

fn record_syscall(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) {
    LAST_SYSCALL_ARG0.store(arg0, Ordering::Relaxed);
    LAST_SYSCALL_ARG1.store(arg1, Ordering::Relaxed);
    LAST_SYSCALL_ARG2.store(arg2, Ordering::Relaxed);
    LAST_SYSCALL_ARG3.store(arg3, Ordering::Relaxed);
    LAST_SYSCALL_ARG4.store(arg4, Ordering::Relaxed);
    LAST_SYSCALL_NUM.store(num, Ordering::Relaxed);
}

pub fn last_syscall_snapshot() -> (u64, [u64; 5]) {
    (
        LAST_SYSCALL_NUM.load(Ordering::Relaxed),
        [
            LAST_SYSCALL_ARG0.load(Ordering::Relaxed),
            LAST_SYSCALL_ARG1.load(Ordering::Relaxed),
            LAST_SYSCALL_ARG2.load(Ordering::Relaxed),
            LAST_SYSCALL_ARG3.load(Ordering::Relaxed),
            LAST_SYSCALL_ARG4.load(Ordering::Relaxed),
        ],
    )
}

/// システムコールのディスパッチ
pub fn dispatch(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    handle::flush_provider_releases();
    crate::task::flush_deferred_process_reclaims();
    record_syscall(num, arg0, arg1, arg2, arg3, arg4);
    #[cfg(feature = "performance-instrumentation")]
    let _allocation_scope =
        crate::performance::AllocationScope::enter(allocation_subsystem_for_syscall(num));
    #[cfg(feature = "performance-instrumentation")]
    let latency = vfs_latency_metric(num).map(|metric| (metric, crate::performance::timestamp()));

    let result = match num {
        x if x == SyscallNumber::ProcessExit as u64 => process::exit(arg0),
        x if x == SyscallNumber::ProcessClone as u64 => process::clone_process(arg0),
        x if x == SyscallNumber::AddressSpaceClone as u64 => process::clone_address_space(),
        x if x == SyscallNumber::DmaAlloc as u64 => dma::alloc(arg0, arg1),
        x if x == SyscallNumber::DmaFree as u64 => dma::free(arg0),
        x if x == SyscallNumber::ExecManifest as u64 => {
            exec::exec_manifest_syscall(arg0, arg1, arg2, arg3, arg4)
        }
        x if x == SyscallNumber::AuthorizeExec as u64 => {
            exec::authorize_exec_syscall(arg0, arg1, arg2, arg3, arg4)
        }
        x if x == SyscallNumber::GetThreadSecurityContext as u64 => {
            process::get_thread_security_context(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::ExecutionIdentityRead as u64 => {
            execution::identity_read(arg0, arg1)
        }
        x if x == SyscallNumber::IpcEndpointIdentityRead as u64 => {
            execution::endpoint_identity_read(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::FindProcessByName as u64 => {
            process::find_process_by_name(arg0, arg1)
        }
        x if x == SyscallNumber::ListProcesses as u64 => process::list_processes(arg0, arg1),
        x if x == SyscallNumber::RandomFill as u64 => process::random_fill(arg0, arg1),
        x if x == SyscallNumber::ThreadCreate as u64 => task::thread_create(arg0, arg1),
        x if x == SyscallNumber::ThreadExit as u64 => crate::task::exit_current_task(arg0),
        x if x == SyscallNumber::ThreadYield as u64 => {
            task::yield_now();
            SUCCESS
        }
        x if x == SyscallNumber::MemoryMap as u64 => {
            process::memory_map(arg0, arg1, arg2, arg3, arg4, arg5)
        }
        x if x == SyscallNumber::GetFramebufferInfo as u64 => get_framebuffer_info(arg0),
        x if x == SyscallNumber::MapFramebuffer as u64 => map_framebuffer(arg0, arg1),
        x if x == SyscallNumber::PresentFramebuffer as u64 => {
            present_framebuffer(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::FramebufferTransferLimit as u64 => framebuffer_transfer_limit(),
        x if x == SyscallNumber::CommitFramebuffer as u64 => commit_framebuffer(arg0, arg1),
        x if x == SyscallNumber::StorageControl as u64 => storage::control(arg0, arg1),
        x if x == SyscallNumber::BlockRead as u64 => storage::block_read(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::BlockWrite as u64 => storage::block_write(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::BlockFlush as u64 => storage::block_flush(arg0),
        x if x == SyscallNumber::FilesystemRegister as u64 => fs::filesystem_register(arg0),
        x if x == SyscallNumber::FilesystemMount as u64 => {
            fs::filesystem_mount(arg0, arg1, arg2, arg3, arg4)
        }
        x if x == SyscallNumber::HandleClose as u64 => handle::close(arg0),
        x if x == SyscallNumber::HandleDuplicate as u64 => handle::duplicate(arg0, arg1),
        x if x == SyscallNumber::LaunchHandleGet as u64 => handle::launch_get(arg0),
        x if x == SyscallNumber::LaunchValueGet as u64 => handle::launch_value_get(arg0, arg1),
        x if x == SyscallNumber::HandleRead as u64 => handle::read(arg0, arg1, arg2),
        x if x == SyscallNumber::HandleWrite as u64 => handle::write(arg0, arg1, arg2),
        x if x == SyscallNumber::HandleSeek as u64 => handle::seek(arg0, arg1, arg2),
        x if x == SyscallNumber::HandleControl as u64 => {
            handle::control(arg0, arg1, arg2, arg3, arg4, arg5)
        }
        x if x == SyscallNumber::ProcessHandleOpen as u64 => handle::process_open(arg0, arg1),
        x if x == SyscallNumber::ProcessHandleStatus as u64 => handle::process_status(arg0, arg1),
        x if x == SyscallNumber::ProcessHandleWait as u64 => handle::process_wait(arg0, arg1, arg2),
        x if x == SyscallNumber::ProcessHandleResume as u64 => handle::process_resume(arg0),
        x if x == SyscallNumber::ProcessHandleSuspend as u64 => handle::process_suspend(arg0),
        x if x == SyscallNumber::ProcessSuspendCurrent as u64 => {
            process::suspend_current_process()
        }
        x if x == SyscallNumber::ProcessHandleTerminate as u64 => {
            handle::process_terminate(arg0, arg1)
        }
        x if x == SyscallNumber::HandleWaitMany as u64 => handle::wait_many(arg0, arg1, arg2),
        x if x == SyscallNumber::ContextHandleSet as u64 => {
            handle::context_handle_set(arg0, arg1)
        }
        x if x == SyscallNumber::ContextHandleRemove as u64 => {
            handle::context_handle_remove(arg0)
        }
        x if x == SyscallNumber::ContextValueSet as u64 => handle::context_value_set(arg0, arg1),
        x if x == SyscallNumber::ContextValueRemove as u64 => handle::context_value_remove(arg0),
        x if x == SyscallNumber::HandleRightsGet as u64 => handle::rights_get(arg0),
        x if x == SyscallNumber::HandleSameObject as u64 => handle::same_object(arg0, arg1),
        x if x == SyscallNumber::StreamPairCreate as u64 => handle::stream_pair_create(arg0),
        x if x == SyscallNumber::HandleOptionsGet as u64 => handle::options_get(arg0),
        x if x == SyscallNumber::HandleOptionsSet as u64 => handle::options_set(arg0, arg1),
        x if x == SyscallNumber::WaitOnAddress as u64 => address_wait::wait(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::WakeAddress as u64 => address_wait::wake(arg0, arg1),
        x if x == SyscallNumber::ThreadUpcallInstall as u64 => upcall::install(arg0, arg1),
        x if x == SyscallNumber::ThreadUpcallReturn as u64 => upcall::return_from(arg0),
        x if x == SyscallNumber::ThreadHandleCreate as u64 => upcall::create_thread_handle(),
        x if x == SyscallNumber::ThreadInterrupt as u64 => upcall::interrupt(arg0, arg1),
        x if x == SyscallNumber::ThreadHandleStatus as u64 => upcall::thread_status(arg0, arg1),
        x if x == SyscallNumber::ProcessHandleOpenById as u64 => {
            handle::process_open_by_id(arg0, arg1)
        }
        x if x == SyscallNumber::ProviderObjectCreate as u64 => {
            handle::provider_object_create(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::ProviderObjectIdentify as u64 => {
            handle::provider_object_identify(arg0)
        }
        x if x == SyscallNumber::ProviderObjectSignal as u64 => {
            handle::provider_object_signal(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::BootSystemSlot as u64 => boot_system_slot(),
        x if x == SyscallNumber::BootEspGuid as u64 => boot_esp_guid(arg0, arg1),
        x if x == SyscallNumber::DeviceControl as u64 => {
            storage::device_control(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::PerformanceSnapshot as u64 => performance::snapshot(arg0, arg1),
        x if x == SyscallNumber::MapPhysicalRange as u64 => map_physical_range(arg0, arg1, arg2),
        x if x == SyscallNumber::MemoryUnmap as u64 => process::memory_unmap(arg0, arg1),
        x if x == SyscallNumber::MemoryProtect as u64 => memory::protect(arg0, arg1, arg2),
        x if x == SyscallNumber::MemoryShare as u64 => process::memory_share(arg0, arg1, arg2),
        x if x == SyscallNumber::MemoryObjectCreate as u64 => handle::memory_object_create(arg0, arg1),
        x if x == SyscallNumber::MemoryObjectLength as u64 => handle::memory_object_length(arg0),
        x if x == SyscallNumber::HandleReadAt as u64 => handle::read_at(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::HandleWriteAt as u64 => handle::write_at(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::StreamWrite as u64 => handle::stream_write(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::MemorySync as u64 => process::memory_sync(arg0, arg1, arg2),
        x if x == SyscallNumber::AllocSharedPages as u64 => {
            process::alloc_shared_pages(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::IpcCreate as u64 => ipc::create(arg0, arg1),
        x if x == SyscallNumber::IpcCreateHandle as u64 => ipc::create_handle(arg0, arg1),
        x if x == SyscallNumber::IpcSend as u64 => ipc::send(arg0, arg1, arg2),
        x if x == SyscallNumber::IpcSendObjectHandles as u64 => {
            ipc::send_object_handles(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::IpcSendPages as u64 => ipc::send_pages(arg0, arg1, arg2, arg3),
        x if x == SyscallNumber::IpcRecv as u64 => ipc::recv(arg0, arg1),
        x if x == SyscallNumber::IpcRecvWait as u64 => ipc::recv_blocking(arg0, arg1),
        x if x == SyscallNumber::IpcCall as u64 => ipc::call(arg0, arg1, arg2, arg3, arg4),
        x if x == SyscallNumber::IpcCallObjectHandles as u64 => {
            ipc::call_object_handles(arg0, arg1, arg2, arg3, arg4, arg5)
        }
        x if x == SyscallNumber::IpcReply as u64 => ipc::reply(arg0, arg1, arg2),
        x if x == SyscallNumber::IpcReplyObjectHandles as u64 => {
            ipc::reply_object_handles(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::IpcWait as u64 => ipc::wait(arg0, arg1, arg2),
        x if x == SyscallNumber::IpcRecvObjectHandles as u64 => {
            ipc::recv_object_handles(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::IpcEndpointAlive as u64 => ipc::endpoint_alive(arg0),
        x if x == SyscallNumber::IpcEndpointOwner as u64 => ipc::endpoint_owner_process(arg0),
        x if x == SyscallNumber::CapClone as u64 => capability::clone_capability(arg0, arg1),
        x if x == SyscallNumber::CapDrop as u64 => capability::drop_capability(arg0, arg1),
        x if x == SyscallNumber::CapTransfer as u64 => {
            capability::transfer_capability(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::CapQuery as u64 => capability::query(arg0, arg1),
        x if x == SyscallNumber::CheckThreadCapability as u64 => {
            capability::check_thread_capability(arg0, arg1, arg2)
        }
        x if x == SyscallNumber::CapRestrict as u64 => {
            capability::restrict_capability(arg0, arg1, arg2, arg3)
        }
        x if x == SyscallNumber::EventCreate as u64 => event::create(arg0, arg1),
        x if x == SyscallNumber::EventWait as u64 => event::wait(arg0, arg1, arg2),
        x if x == SyscallNumber::EventSignal as u64 => event::signal(arg0, arg1, arg2),
        x if x == SyscallNumber::EventPoll as u64 => event::poll(arg0, arg1, arg2),
        x if x == SyscallNumber::TimeNow as u64 => time::get_ticks(),
        x if x == SyscallNumber::ClockRead as u64 => time::clock_read(arg0, arg1),
        x if x == SyscallNumber::Sleep as u64 => process::sleep(arg0),
        x if x == SyscallNumber::DebugWrite as u64 => io::debug_write(arg0, arg1),
        x if x == SyscallNumber::PortIn as u64 => io::port_in(arg0, arg1),
        x if x == SyscallNumber::PortOut as u64 => io::port_out(arg0, arg1, arg2),
        x if x == SyscallNumber::ProcessImageReplace as u64 => {
            exec::process_image_replace_syscall(arg0, arg1, arg2, arg3, arg4)
        }
        x if x == SyscallNumber::ProcessCreate as u64 => {
            exec::process_create_syscall(arg0, arg1, arg2)
        }
        _ => ENOSYS,
    };

    #[cfg(feature = "performance-instrumentation")]
    if let Some((metric, start)) = latency {
        crate::performance::record_latency(metric, start);
    }

    crate::task::flush_deferred_process_reclaims();

    result
}

/// Read-only boot identity. Legacy images report 0; A/B images report 1 or 2.
fn boot_system_slot() -> u64 {
    let Some(info) = crate::smp::boot_info() else {
        return 0;
    };
    if (info.feature_flags & crate::BOOT_FEATURE_SYSTEM_SLOT) == 0 {
        return 0;
    }
    info.system_slot as u64
}

/// Copies the unique GPT GUID of the ESP that launched mBoot. The value is
/// unavailable on legacy images and is never guessed from disk ordering.
fn boot_esp_guid(destination: u64, length: u64) -> u64 {
    if length != 16 {
        return EINVAL;
    }
    let Some(info) = crate::smp::boot_info() else {
        return ENOSYS;
    };
    if (info.feature_flags & crate::BOOT_FEATURE_BOOT_ESP_GUID) == 0
        || info.boot_esp_guid == [0; 16]
    {
        return ENOSYS;
    }
    match copy_to_user(destination, &info.boot_esp_guid) {
        Ok(()) => SUCCESS,
        Err(error) => error,
    }
}

#[cfg(feature = "performance-instrumentation")]
fn allocation_subsystem_for_syscall(num: u64) -> crate::performance::AllocationSubsystem {
    use crate::performance::AllocationSubsystem;

    if is_ipc_syscall(num) {
        AllocationSubsystem::Ipc
    } else if is_vfs_syscall(num) {
        AllocationSubsystem::Vfs
    } else if is_process_creation_syscall(num) {
        AllocationSubsystem::ProcessCreation
    } else if num == SyscallNumber::ThreadCreate as u64 {
        AllocationSubsystem::ThreadCreation
    } else if num == SyscallNumber::BlockRead as u64
        || num == SyscallNumber::BlockWrite as u64
        || num == SyscallNumber::StorageControl as u64
    {
        AllocationSubsystem::BlockIo
    } else {
        AllocationSubsystem::Syscall
    }
}

#[cfg(feature = "performance-instrumentation")]
fn is_ipc_syscall(num: u64) -> bool {
    num == SyscallNumber::IpcSend as u64
        || num == SyscallNumber::IpcRecv as u64
        || num == SyscallNumber::IpcRecvWait as u64
        || num == SyscallNumber::IpcSendPages as u64
        || num == SyscallNumber::IpcSendObjectHandles as u64
        || num == SyscallNumber::IpcRecvObjectHandles as u64
        || num == SyscallNumber::IpcCallObjectHandles as u64
        || num == SyscallNumber::IpcReplyObjectHandles as u64
        || num == SyscallNumber::IpcEndpointAlive as u64
        || num == SyscallNumber::IpcEndpointOwner as u64
        || num == SyscallNumber::IpcCreate as u64
        || num == SyscallNumber::IpcCreateHandle as u64
        || num == SyscallNumber::IpcCall as u64
        || num == SyscallNumber::IpcReply as u64
        || num == SyscallNumber::IpcWait as u64
}

#[cfg(feature = "performance-instrumentation")]
fn is_vfs_syscall(num: u64) -> bool {
    num == SyscallNumber::HandleRead as u64
        || num == SyscallNumber::HandleWrite as u64
        || num == SyscallNumber::HandleReadAt as u64
        || num == SyscallNumber::HandleWriteAt as u64
        || num == SyscallNumber::HandleSeek as u64
}

#[cfg(feature = "performance-instrumentation")]
fn is_process_creation_syscall(num: u64) -> bool {
    num == SyscallNumber::ProcessImageReplace as u64
        || num == SyscallNumber::ProcessCreate as u64
        || num == SyscallNumber::ProcessClone as u64
        || num == SyscallNumber::ExecManifest as u64
}

#[cfg(feature = "performance-instrumentation")]
fn vfs_latency_metric(num: u64) -> Option<crate::performance::LatencyMetric> {
    use crate::performance::LatencyMetric;

    match num {
        x if x == SyscallNumber::HandleRead as u64 || x == SyscallNumber::HandleReadAt as u64 => Some(LatencyMetric::VfsRead),
        _ => None,
    }
}

#[repr(C)]
pub struct SavedSyscallFrame {
    pub(crate) user_rsp: u64,
    pub(crate) r15: u64,
    pub(crate) r14: u64,
    pub(crate) r13: u64,
    pub(crate) r12: u64,
    pub(crate) rbx: u64,
    pub(crate) rbp: u64,
    pub(crate) user_rflags: u64,
    pub(crate) user_rip: u64,
    pub(crate) arg5: u64,
    pub(crate) arg4: u64,
    pub(crate) arg3: u64,
    pub(crate) arg2: u64,
    pub(crate) arg1: u64,
    pub(crate) arg0: u64,
    pub(crate) num: u64,
}

#[no_mangle]
pub extern "sysv64" fn prepare_thread_upcall_for_sysret(frame: *mut SavedSyscallFrame) {
    if let Some(frame) = unsafe { frame.as_mut() } {
        upcall::prepare_syscall_return(frame);
    }
}

const _: () = {
    assert!(core::mem::size_of::<SavedSyscallFrame>() == 16 * 8);
    assert!(core::mem::offset_of!(SavedSyscallFrame, user_rsp) == 0);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r15) == 8);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r14) == 16);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r13) == 24);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r12) == 32);
    assert!(core::mem::offset_of!(SavedSyscallFrame, rbx) == 40);
    assert!(core::mem::offset_of!(SavedSyscallFrame, rbp) == 48);
    assert!(core::mem::offset_of!(SavedSyscallFrame, user_rflags) == 56);
    assert!(core::mem::offset_of!(SavedSyscallFrame, user_rip) == 64);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg5) == 72);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg4) == 80);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg3) == 88);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg2) == 96);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg1) == 104);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg0) == 112);
    assert!(core::mem::offset_of!(SavedSyscallFrame, num) == 120);
};

/// fork/clone 用に、現在スレッドへユーザー復帰コンテキストを保存する
#[no_mangle]
pub extern "sysv64" fn save_user_context_for_fork(frame: *const SavedSyscallFrame) {
    if frame.is_null() {
        return;
    }
    let frame = unsafe { &*frame };
    if let Some(tid) = crate::task::current_thread_id() {
        let _ = crate::task::with_thread_mut(tid, |thread| {
            thread.set_syscall_user_context(crate::task::thread::SyscallUserContext {
                rip: frame.user_rip,
                rsp: frame.user_rsp,
                rflags: frame.user_rflags,
                rdi: frame.arg0,
                rsi: frame.arg1,
                rdx: frame.arg2,
                r8: frame.arg4,
                r9: frame.arg5,
                r10: frame.arg3,
                rbp: frame.rbp,
                rbx: frame.rbx,
                r12: frame.r12,
                r13: frame.r13,
                r14: frame.r14,
                r15: frame.r15,
            });
        });
    }
}

/// システムコール割り込みハンドラ (int 0x80) - アセンブリラッパー
///
/// # Safety
/// CPU が int 0x80 入口規約どおりのスタック/レジスタ状態でこの関数へ入ることを前提とする。
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_interrupt_handler() {
    core::arch::naked_asm!(
        // すべてのレジスタを保存（システムコール引数を含む）
        "push rax",      // syscall number
        "push rcx",
        "push rdx",      // arg2
        "push rbx",
        "push rbp",
        "push rsi",      // arg1
        "push rdi",      // arg0
        "push r8",       // arg4
        "push r9",
        "push r10",      // arg3
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // カーネルデータセグメントをロード
        // （ds/esはスタックに保存しない。復元時にユーザーセグメントを再設定）
        "mov ax, 0x10",    // カーネルデータセグメント (index=2)
        "mov ds, ax",
        "mov es, ax",

        // int 0x80 経路は、kernel CR3 に切り替えたまま dispatch と signal return を完結させる。
        // KPTI で user CR3 から kernel heap を完全に外しているため、signal 配送や
        // プロセス/スレッド metadata 参照を user CR3 上で行うと kernel-mode page fault になる。
        "mov rdi, rsp",               // arg0 = kstack（saved registers 先頭）
        "call {int80_handler}",       // 最終的な戻り値を rax で返す

        // 戻り値 (rax) をスタック上の保存された rax の位置に書き込む
        "mov [rsp + 112], rax",

        // ユーザーデータセグメントを設定
        "mov ax, 0x1b",    // ユーザーデータセグメント (index=3, RPL=3)
        "mov ds, ax",
        "mov es, ax",

        // すべてのレジスタを復元
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",

        // 割り込みから戻る
        "iretq",

        int80_handler = sym syscall_interrupt_handler_rust,
    );
}

/// int 0x80 経路専用の Rust wrapper。
///
/// KPTIでuser CR3から外したkernel heap/task metadataを参照するため、
/// dispatchをkernel CR3上で完結させる。
extern "sysv64" fn syscall_interrupt_handler_rust(kstack: *mut u64) -> u64 {
    crate::percpu::install_current_cpu_gs_base();

    let prev_cr3 = syscall_entry::switch_to_kernel_page_table();
    crate::cpu::reassert_runtime_hardening();

    let syscall_num = unsafe { kstack.add(14).read() };

    let current_tid = crate::task::current_thread_id();
    let current_slot = crate::task::current_thread_slot();
    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(true));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(true));
    }

    let ret = dispatch(
        syscall_num,
        unsafe { kstack.add(8).read() },  // saved rdi = arg0
        unsafe { kstack.add(9).read() },  // saved rsi = arg1
        unsafe { kstack.add(12).read() }, // saved rdx = arg2
        unsafe { kstack.add(5).read() },  // saved r10 = arg3
        unsafe { kstack.add(7).read() },  // saved r8  = arg4
        unsafe { kstack.add(6).read() },  // saved r9  = arg5
    );

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(false));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(false));
    }

    // int 0x80 復帰フレームの CS/SS を GDT 実値で正規化する。
    // 一部環境で固定値と実際の GDT 割当がずれると iretq で #GP(index=3/4) を起こすため、
    // 毎回ここで明示的に揃える。
    let user_cs = (crate::mem::gdt::user_code_selector() as u64) | 0x3;
    let user_ss = (crate::mem::gdt::user_data_selector() as u64) | 0x3;
    unsafe {
        kstack.add(16).write(user_cs);
        kstack.add(19).write(user_ss);
    }
    syscall_entry::restore_page_table(prev_cr3);
    ret
}

/// システムコールハンドラの Rust 実装
extern "C" fn syscall_handler_rust(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    crate::percpu::install_current_cpu_gs_base();

    let current_tid = crate::task::current_thread_id();
    let current_slot = crate::task::current_thread_slot();

    let _prev_cr3 = syscall_entry::switch_to_kernel_page_table();
    crate::cpu::reassert_runtime_hardening();

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(true));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(true));
    }

    let ret = dispatch(num, arg0, arg1, arg2, arg3, arg4, arg5);

    if let Some(slot) = current_slot {
        crate::task::with_thread_at_slot_mut(slot, |t| t.set_in_syscall(false));
    } else if let Some(tid) = current_tid {
        crate::task::with_thread_mut(tid, |t| t.set_in_syscall(false));
    }

    ret
}

#[no_mangle]
pub extern "sysv64" fn syscall_user_cr3_for_sysret() -> u64 {
    syscall_entry::current_thread_user_page_table().unwrap_or(0)
}

/// SYSCALL 命令エントリから呼ばれる system V ABI ディスパッチ関数
///
/// syscall_entry.rs の naked asm から `call {dispatch}` で呼ばれる。
/// system V ABI: 引数は rdi, rsi, rdx, rcx, r8, r9 の順。
#[no_mangle]
pub extern "sysv64" fn syscall_dispatch_sysv(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    syscall_handler_rust(num, arg0, arg1, arg2, arg3, arg4, arg5)
}
