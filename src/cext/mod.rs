//! cext 境界の共通定義
//!
//! Block-device implementations are isolated behind their CExt ABI adapter.
//! Filesystem services and POSIX metadata do not execute through this boundary.
//! このモジュールは、cext の登録・停止・endpoint・resource limit を束ねる
//! 最小の信頼基盤を表す。

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::task::ResourceLimits;

pub mod disk;
mod provider;
pub use provider::CextKind;
use provider::provider_kind;

const MCX_CEXT_ABI: u16 = 4;
const MCX_LOG_ERROR: u32 = 0;
const MCX_LOG_WARN: u32 = 1;
const MCX_LOG_INFO: u32 = 2;
const MCX_LOG_DEBUG: u32 = 3;
const MCX_LOG_BOOT: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct McxDmaRegion {
    pub virt: *mut u8,
    pub phys: u64,
    pub len: usize,
}

#[repr(C)]
pub struct McxKernelApi {
    pub abi: u16,
    pub struct_size: u16,
    pub alloc_dma: extern "C" fn(size: usize, align: usize, out_region: *mut McxDmaRegion) -> i32,
    pub log: extern "C" fn(level: u32, ptr: *const u8, len: usize),
    pub register_irq: extern "C" fn(irq: u8, handler: extern "C" fn(u8)) -> i32,
    pub now_seconds: extern "C" fn() -> u32,
    pub boot_system_slot: extern "C" fn() -> u32,
}

/// cext インスタンス
#[derive(Clone, Debug)]
pub struct CextInstance {
    pub id: u64,
    pub name: String,
    pub kind: CextKind,
    pub process_id: Option<u64>,
    pub endpoint: Option<crate::syscall::ipc::IpcEndpoint>,
    pub limits: ResourceLimits,
    pub loaded: bool,
}

static NEXT_CEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_MODULE_LOAD_BASE: AtomicU64 = AtomicU64::new(0);
static CEXT_REGISTRY: Mutex<Option<BTreeMap<u64, CextInstance>>> = Mutex::new(None);

fn with_registry_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, CextInstance>) -> R) -> R {
    let mut guard = CEXT_REGISTRY.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

pub fn load_cext(name: &str, kind: CextKind, process_id: Option<u64>) -> u64 {
    let id = NEXT_CEXT_ID.fetch_add(1, Ordering::Relaxed);
    let instance = CextInstance {
        id,
        name: name.to_string(),
        kind,
        process_id,
        endpoint: None,
        limits: ResourceLimits::default(),
        loaded: true,
    };
    with_registry_mut(|registry| {
        registry.insert(id, instance);
    });
    id
}

pub fn register_endpoint(id: u64, endpoint: crate::syscall::ipc::IpcEndpoint) -> bool {
    with_registry_mut(|registry| {
        let Some(instance) = registry.get_mut(&id) else {
            return false;
        };
        instance.endpoint = Some(endpoint);
        true
    })
}

pub fn endpoint_for(id: u64) -> Option<crate::syscall::ipc::IpcEndpoint> {
    with_registry_mut(|registry| registry.get(&id).and_then(|instance| instance.endpoint))
}

pub fn revoke(id: u64) -> bool {
    with_registry_mut(|registry| {
        if let Some(instance) = registry.get_mut(&id) {
            instance.loaded = false;
            instance.endpoint = None;
            true
        } else {
            false
        }
    })
}

pub fn unregister(id: u64) -> bool {
    with_registry_mut(|registry| registry.remove(&id).is_some())
}

type DiskInitFn = unsafe extern "C" fn(api: *const McxKernelApi) -> *const disk::McxDiskOps;

extern "C" fn kernel_log(level: u32, ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let Ok(msg) = core::str::from_utf8(unsafe { core::slice::from_raw_parts(ptr, len) }) else {
        return;
    };
    match level {
        MCX_LOG_ERROR => crate::error!("cext: {}", msg),
        MCX_LOG_WARN => crate::warn!("cext: {}", msg),
        MCX_LOG_INFO => crate::info!("cext: {}", msg),
        MCX_LOG_DEBUG => crate::debug!("cext: {}", msg),
        MCX_LOG_BOOT => {
            crate::info!("cext: {}", msg);
            crate::util::log::release_boot_marker(format_args!("cext: {}", msg));
        }
        _ => crate::info!("cext: {}", msg),
    }
}

extern "C" fn kernel_alloc_dma(size: usize, align: usize, out_region: *mut McxDmaRegion) -> i32 {
    if out_region.is_null() || size == 0 || align == 0 || !align.is_power_of_two() {
        return -22;
    }
    if size > 256 * 1024 || align > 4096 {
        return -38;
    }
    let pages = size.div_ceil(4096);
    let phys_off = match crate::mem::paging::physical_memory_offset() {
        Some(v) => v,
        None => return -5,
    };
    let Ok(first_frame) = crate::mem::frame::allocate_contiguous_frames(pages) else {
        return -12;
    };
    let phys = first_frame.start_address().as_u64();

    let release = || {
        for page in 0..pages {
            let frame = x86_64::structures::paging::PhysFrame::containing_address(
                x86_64::PhysAddr::new(phys + (page as u64) * 4096),
            );
            let _ = crate::mem::frame::deallocate_frame(frame);
        }
    };
    for page in 0..pages {
        let frame = x86_64::structures::paging::PhysFrame::containing_address(
            x86_64::PhysAddr::new(phys + (page as u64) * 4096),
        );
        if crate::mem::frame::zero_frame(frame).is_err() {
            release();
            return -5;
        }
    }
    let Some(virt) = phys.checked_add(phys_off) else {
        release();
        return -5;
    };
    unsafe {
        *out_region = McxDmaRegion {
            virt: virt as *mut u8,
            phys,
            len: pages * 4096,
        };
    }
    0
}

extern "C" fn kernel_register_irq(irq: u8, handler: extern "C" fn(u8)) -> i32 {
    crate::interrupt::dispatch::register_handler(irq, handler)
}

extern "C" fn kernel_now_seconds() -> u32 {
    let ticks_per_second = crate::interrupt::timer::ticks_per_second();
    if ticks_per_second == 0 {
        return 0;
    }
    let seconds = crate::interrupt::timer::get_ticks() / ticks_per_second;
    core::cmp::min(seconds, u32::MAX as u64) as u32
}

extern "C" fn kernel_boot_system_slot() -> u32 {
    let Some(info) = crate::smp::boot_info() else {
        return 0;
    };
    if (info.feature_flags & crate::BOOT_FEATURE_SYSTEM_SLOT) == 0 {
        return 0;
    }
    info.system_slot as u32
}

static KERNEL_API: McxKernelApi = McxKernelApi {
    abi: MCX_CEXT_ABI,
    struct_size: core::mem::size_of::<McxKernelApi>() as u16,
    alloc_dma: kernel_alloc_dma,
    log: kernel_log,
    register_irq: kernel_register_irq,
    now_seconds: kernel_now_seconds,
    boot_system_slot: kernel_boot_system_slot,
};

fn register_disk_provider(init_addr: u64, module_version: u16) -> bool {
    let init: DiskInitFn = unsafe { core::mem::transmute(init_addr) };
    let ops = unsafe { init(&KERNEL_API) };
    !ops.is_null() && disk::activate_bundle(module_version, ops)
}

struct CextHeader {
    module_version: u16,
    name_len: usize,
    dep_count: usize,
    header_size: usize,
    elf_size: usize,
}

struct CextMeta {
    name: String,
    _deps: Vec<String>,
    module_version: u16,
    elf: Vec<u8>,
}

fn register_provider(kind: CextKind, init_addr: u64, version: u16) -> bool {
    match kind {
        CextKind::BlockDevice => register_disk_provider(init_addr, version),
        CextKind::DeviceService | CextKind::Other => false,
    }
}

fn load_boot_modules() -> bool {
    let Ok(module) = mnu_abi::boot_module::decode(crate::init::fs::boot_module_bytes()) else {
        crate::util::log::release_boot_marker(format_args!("cext: invalid boot module"));
        return false;
    };
    let Ok(entries) = mnu_abi::boot_extensions::decode(module.native_modules) else {
        crate::util::log::release_boot_marker(format_args!("cext: invalid native module index"));
        return false;
    };
    let mut loaded = false;
    for index in 0..entries.len() {
        let entry = entries.get(index).unwrap();
        let Some(kind) = provider_kind(entry.adapter) else {
            return false;
        };
        let Some(meta) = parse_cext(entry.bytes) else {
            crate::warn!("cext: invalid selected module {}", index);
            if entry.required {
                return false;
            }
            continue;
        };
        let Some(mut module) = load_elf_symbol(&meta.elf, "mnu_module_init") else {
            crate::warn!("cext: init symbol not found in selected module {}", index);
            crate::util::log::release_boot_marker(format_args!(
                "cext: init symbol missing {}",
                index
            ));
            if entry.required {
                return false;
            }
            continue;
        };
        if register_provider(kind, module.address, meta.module_version) {
            loaded = true;
            module.keep_mapped();
            load_cext(&meta.name, kind, None);
            crate::info!("cext: loaded module {} v{}", meta.name, meta.module_version);
            crate::util::log::release_boot_marker(format_args!(
                "cext: loaded bundle {}",
                meta.name
            ));
        } else {
            crate::warn!("cext: module init failed for {}", meta.name);
            crate::util::log::release_boot_marker(format_args!(
                "cext: module init failed {}",
                meta.name
            ));
            if entry.required {
                return false;
            }
        }
    }
    loaded
}

fn parse_cext(bytes: &[u8]) -> Option<CextMeta> {
    let header = parse_header(bytes)?;
    if header.header_size > bytes.len() {
        return None;
    }

    let mut cursor = 0usize;
    cursor += 32;
    let name_end = cursor.checked_add(header.name_len)?;
    let name = core::str::from_utf8(bytes.get(cursor..name_end)?).ok()?;
    cursor = name_end;

    let mut deps = Vec::with_capacity(header.dep_count);
    for _ in 0..header.dep_count {
        let dep_len = read_u16(bytes, cursor)? as usize;
        cursor = cursor.checked_add(2)?;
        let dep_end = cursor.checked_add(dep_len)?;
        let dep = core::str::from_utf8(bytes.get(cursor..dep_end)?).ok()?;
        deps.push(dep.to_string());
        cursor = dep_end;
    }
    if cursor != header.header_size {
        return None;
    }
    let elf_start = header.header_size;
    let elf_end = elf_start.checked_add(header.elf_size)?;
    if elf_end > bytes.len() {
        return None;
    }

    Some(CextMeta {
        name: name.to_string(),
        _deps: deps,
        module_version: header.module_version,
        elf: bytes[elf_start..elf_end].to_vec(),
    })
}

fn parse_header(bytes: &[u8]) -> Option<CextHeader> {
    if bytes.len() < 32 {
        return None;
    }
    if bytes.get(0..4)? != b"MCEX" {
        return None;
    }
    let abi = read_u16(bytes, 4)?;
    if abi != MCX_CEXT_ABI {
        return None;
    }
    let module_version = read_u16(bytes, 6)?;
    let name_len = read_u16(bytes, 8)? as usize;
    let dep_count = read_u16(bytes, 10)? as usize;
    let header_size = read_u32(bytes, 12)? as usize;
    let elf_size = read_u64(bytes, 16)? as usize;
    if header_size < 32 {
        return None;
    }

    Some(CextHeader {
        module_version,
        name_len,
        dep_count,
        header_size,
        elf_size,
    })
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

struct LoadedElf {
    base: u64,
    min_vaddr: u64,
    max_vaddr: u64,
    segments: Vec<LoadedSegment>,
    release_on_drop: bool,
}

struct LoadedSymbol {
    address: u64,
    image: LoadedElf,
}

impl LoadedSymbol {
    fn keep_mapped(&mut self) {
        self.image.keep_mapped();
    }
}

impl LoadedElf {
    fn keep_mapped(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for LoadedElf {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        for segment in &self.segments {
            let _ = crate::mem::paging::release_kernel_range(segment.vaddr, segment.memsz);
        }
    }
}

#[derive(Clone, Copy)]
struct LoadedSegment {
    vaddr: u64,
    memsz: u64,
    writable: bool,
    executable: bool,
}

#[inline]
fn align_up_4k(v: u64) -> Option<u64> {
    v.checked_add(0xfff).map(|x| x & !0xfff)
}

fn alloc_module_base(span: u64) -> Option<u64> {
    let module_cfg = crate::config::kernel().cext;
    let size = align_up_4k(span)?;
    let step = size.checked_add(module_cfg.module_load_guard)?;
    if NEXT_MODULE_LOAD_BASE.load(Ordering::Acquire) == 0 {
        NEXT_MODULE_LOAD_BASE.store(module_cfg.module_load_base_start, Ordering::Release);
    }
    let mut cur = NEXT_MODULE_LOAD_BASE.load(Ordering::Relaxed);
    loop {
        let next = cur.checked_add(step)?;
        match NEXT_MODULE_LOAD_BASE.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => return Some(cur),
            Err(actual) => cur = actual,
        }
    }
}

fn load_elf_symbol(elf: &[u8], symbol_name: &str) -> Option<LoadedSymbol> {
    let eh = crate::elf::parse_elf_header(elf)?;
    let loaded = load_elf_image(elf, &eh)?;
    let reloc_ok = apply_relocations(elf, &eh, loaded.base, loaded.min_vaddr, loaded.max_vaddr);
    let restore_ok = finalize_loaded_elf(&loaded);
    reloc_ok?;
    restore_ok?;
    let address = find_symbol_runtime_addr(elf, &eh, symbol_name, loaded.base, loaded.min_vaddr)?;
    Some(LoadedSymbol {
        address,
        image: loaded,
    })
}

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const SHF_ALLOC: u64 = 0x2;
const SHT_RELA: u32 = 4;
const R_X86_64_RELATIVE: u32 = 8;
const ET_DYN: u16 = 3;
const CEXT_LOAD_VADDR_MIN: u64 = 0x0000_6000_0000_0000;
const CEXT_LOAD_VADDR_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

fn load_elf_image(elf: &[u8], eh: &crate::elf::Elf64Ehdr) -> Option<LoadedElf> {
    let phoff = eh.e_phoff as usize;
    let phentsize = eh.e_phentsize as usize;
    let phnum = eh.e_phnum as usize;
    if phoff == 0 || phentsize == 0 || phnum == 0 {
        return None;
    }

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;

    for i in 0..phnum {
        let off = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let ph = crate::elf::parse_phdr(elf, off)?;
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(ph.p_vaddr);
        max_vaddr = max_vaddr.max(ph.p_vaddr.checked_add(ph.p_memsz)?);
    }
    if min_vaddr == u64::MAX || max_vaddr <= min_vaddr {
        return None;
    }
    let is_dyn = eh.e_type == ET_DYN;
    let base = if is_dyn {
        alloc_module_base(max_vaddr.checked_sub(min_vaddr)?)?
    } else {
        0
    };
    let vaddr_bias = if is_dyn {
        base.checked_sub(min_vaddr)?
    } else {
        0
    };
    let mut loaded = LoadedElf {
        base,
        min_vaddr,
        max_vaddr,
        segments: Vec::new(),
        release_on_drop: true,
    };
    loaded.segments.try_reserve_exact(phnum).ok()?;

    for i in 0..phnum {
        let off = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let ph = crate::elf::parse_phdr(elf, off)?;
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let writable = (ph.p_flags & 0x2) != 0;
        let executable = (ph.p_flags & 0x1) != 0;
        let filesz = usize::try_from(ph.p_filesz).ok()?;
        let memsz = usize::try_from(ph.p_memsz).ok()?;
        if filesz > memsz {
            return None;
        }
        let seg_vaddr = ph.p_vaddr.checked_add(vaddr_bias)?;
        let seg_end = seg_vaddr.checked_add(ph.p_memsz.checked_sub(1)?)?;
        if seg_vaddr < CEXT_LOAD_VADDR_MIN || seg_end > CEXT_LOAD_VADDR_MAX {
            crate::warn!(
                "cext: rejecting PT_LOAD outside cext range [{:#x}, {:#x}] at {:#x}-{:#x}",
                CEXT_LOAD_VADDR_MIN,
                CEXT_LOAD_VADDR_MAX,
                seg_vaddr,
                seg_end
            );
            return None;
        }
        let src_off = usize::try_from(ph.p_offset).ok()?;
        let src_end = src_off.checked_add(filesz)?;
        if src_end > elf.len() {
            return None;
        }
        let src = &elf[src_off..src_end];
        crate::mem::paging::map_and_copy_segment(
            seg_vaddr,
            ph.p_filesz,
            ph.p_memsz,
            src,
            true,
            false,
        )
        .ok()?;
        loaded.segments.push(LoadedSegment {
            vaddr: seg_vaddr,
            memsz: ph.p_memsz,
            writable,
            executable,
        });
    }

    Some(loaded)
}

fn finalize_loaded_elf(loaded: &LoadedElf) -> Option<()> {
    for segment in &loaded.segments {
        crate::mem::paging::protect_current_range(
            segment.vaddr,
            segment.memsz,
            true,
            segment.writable,
            segment.executable,
        )
        .ok()?;
    }
    Some(())
}

fn apply_relocations(
    elf: &[u8],
    eh: &crate::elf::Elf64Ehdr,
    base: u64,
    min_vaddr: u64,
    max_vaddr: u64,
) -> Option<()> {
    let shoff = eh.e_shoff as usize;
    let shentsz = eh.e_shentsize as usize;
    let shnum = eh.e_shnum as usize;
    if shoff == 0 || shentsz == 0 || shnum == 0 {
        return Some(());
    }
    if shoff.checked_add(shentsz.checked_mul(shnum)?)? > elf.len() {
        return None;
    }

    for i in 0..shnum {
        let sh_off = shoff + i * shentsz;
        let sh_type = read_u32(elf, sh_off + 4)?;
        let sh_flags = read_u64(elf, sh_off + 8)?;
        if sh_type != SHT_RELA || (sh_flags & SHF_ALLOC) == 0 {
            continue;
        }
        let rela_off = usize::try_from(read_u64(elf, sh_off + 24)?).ok()?;
        let rela_size = usize::try_from(read_u64(elf, sh_off + 32)?).ok()?;
        let rela_entsize = usize::try_from(read_u64(elf, sh_off + 56)?).ok()?;
        if rela_entsize == 0 || rela_entsize < 24 || rela_size % rela_entsize != 0 {
            return None;
        }
        let rela_end = rela_off.checked_add(rela_size)?;
        if rela_end > elf.len() {
            return None;
        }
        let count = rela_size / rela_entsize;
        for r in 0..count {
            let ent = rela_off + r * rela_entsize;
            let r_offset = read_u64(elf, ent)?;
            let r_info = read_u64(elf, ent + 8)?;
            let r_addend = i64::from_le_bytes(elf.get(ent + 16..ent + 24)?.try_into().ok()?);
            let r_type = (r_info & 0xffff_ffff) as u32;
            if r_type != R_X86_64_RELATIVE {
                continue;
            }
            let reloc_vaddr = r_offset;
            let reloc_end = reloc_vaddr.checked_add(8)?;
            if reloc_vaddr < min_vaddr || reloc_end > max_vaddr {
                return None;
            }
            let dst = base.checked_add(reloc_vaddr.checked_sub(min_vaddr)?)? as *mut u64;
            let value_i128 = base as i128 + r_addend as i128 - min_vaddr as i128;
            if value_i128 < 0 || value_i128 > u64::MAX as i128 {
                return None;
            }
            let value = value_i128 as u64;
            unsafe {
                core::ptr::write_unaligned(dst, value);
            }
        }
    }

    Some(())
}

fn find_symbol_runtime_addr(
    elf: &[u8],
    eh: &crate::elf::Elf64Ehdr,
    symbol_name: &str,
    base: u64,
    min_vaddr: u64,
) -> Option<u64> {
    let shoff = eh.e_shoff as usize;
    let shentsz = eh.e_shentsize as usize;
    let shnum = eh.e_shnum as usize;
    if shoff == 0 || shentsz == 0 || shnum == 0 {
        return None;
    }

    for si in 0..shnum {
        let sh_off = shoff + si * shentsz;
        let sh_type = read_u32(elf, sh_off + 4)?;
        if sh_type != SHT_SYMTAB && sh_type != SHT_DYNSYM {
            continue;
        }
        let symtab_offset = usize::try_from(read_u64(elf, sh_off + 24)?).ok()?;
        let symtab_size = usize::try_from(read_u64(elf, sh_off + 32)?).ok()?;
        let sh_link = read_u32(elf, sh_off + 40)? as usize;
        let symtab_entsize = usize::try_from(read_u64(elf, sh_off + 56)?).ok()?;
        if symtab_entsize < 24 || symtab_size == 0 {
            continue;
        }
        if sh_link >= shnum {
            continue;
        }
        let link_sh_off = shoff + sh_link * shentsz;
        let strtab_offset = usize::try_from(read_u64(elf, link_sh_off + 24)?).ok()?;
        let strtab_size = usize::try_from(read_u64(elf, link_sh_off + 32)?).ok()?;
        let nsyms = symtab_size / symtab_entsize;
        for i_sym in 0..nsyms {
            let sym_off = symtab_offset + i_sym * symtab_entsize;
            let st_name = read_u32(elf, sym_off)? as usize;
            let st_value = read_u64(elf, sym_off + 8)?;
            if st_name >= strtab_size {
                continue;
            }
            let name_off = strtab_offset + st_name;
            if name_off >= elf.len() {
                continue;
            }
            let mut end = name_off;
            while end < elf.len() && elf[end] != 0 {
                end += 1;
            }
            let Ok(name_str) = core::str::from_utf8(&elf[name_off..end]) else {
                continue;
            };
            if name_str == symbol_name {
                if base == 0 {
                    return Some(st_value);
                }
                return base.checked_add(st_value.checked_sub(min_vaddr)?);
            }
        }
    }
    None
}

#[inline]
pub fn init_runtime_config() {
    let _ = crate::config::kernel().cext;
}

#[inline]
pub fn load_modules() {
    if !load_boot_modules() {
        crate::warn!("cext: no boot bundles found");
    }
}
