#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::fmt::Write;
use core::mem::size_of;
use core::ptr::{copy_nonoverlapping, write_bytes};
use core::sync::atomic::{AtomicU64, AtomicUsize};
use spin::Mutex;
use uefi::prelude::*;
use uefi::fs::Error as FsError;
use uefi::table::boot::{AllocateType, MemoryMap, MemoryType};
use uefi::{CString16, Status};
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame};
use x86_64::PhysAddr;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const EM_X86_64: u16 = 0x3e;
const R_X86_64_RELATIVE: u32 = 8;
const PAGE: u64 = 4096;
const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const SERIAL_BASE: u16 = 0x3f8;
const MAX_MEMORY_REGIONS: usize = 1024;
const MAX_CPU_IDS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryRegionKind {
    Usable = 0,
    Reserved = 1,
    AcpiReclaimable = 2,
    AcpiNvs = 3,
    BadMemory = 4,
    BootloaderReclaimable = 5,
    KernelStack = 6,
    PageTable = 7,
    Framebuffer = 8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct MemoryRegion {
    start: u64,
    len: u64,
    region_type: MemoryRegionKind,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct BootInfo {
    physical_memory_offset: u64,
    framebuffer_addr: u64,
    framebuffer_size: usize,
    screen_width: usize,
    screen_height: usize,
    stride: usize,
    memory_map_addr: u64,
    memory_map_len: usize,
    memory_map_entry_size: usize,
    kernel_heap_addr: u64,
    initfs_addr: u64,
    initfs_size: usize,
    rootfs_addr: u64,
    rootfs_size: usize,
    cpu_total: usize,
    cpu_enabled: usize,
    bsp_apic_id: u32,
    cpu_apic_ids: [u32; MAX_CPU_IDS],
    cpu_apic_id_count: usize,
    smp_handoff_addr: u64,
    smp_handoff_size: usize,
    smp_trampoline_addr: u64,
    smp_trampoline_size: usize,
}

#[repr(C)]
#[derive(Debug)]
struct SmpHandoff {
    ready: AtomicU64,
    kernel_secondary_entry: AtomicU64,
    boot_info_ptr: AtomicU64,
    kernel_cr3: AtomicU64,
    ap_count: AtomicUsize,
}

impl SmpHandoff {
    const fn new() -> Self {
        Self {
            ready: AtomicU64::new(0),
            kernel_secondary_entry: AtomicU64::new(0),
            boot_info_ptr: AtomicU64::new(0),
            kernel_cr3: AtomicU64::new(0),
            ap_count: AtomicUsize::new(0),
        }
    }
}

const EMPTY_BOOT_INFO: BootInfo = BootInfo {
    physical_memory_offset: 0,
    framebuffer_addr: 0,
    framebuffer_size: 0,
    screen_width: 0,
    screen_height: 0,
    stride: 0,
    memory_map_addr: 0,
    memory_map_len: 0,
    memory_map_entry_size: size_of::<MemoryRegion>(),
    kernel_heap_addr: 0,
    initfs_addr: 0,
    initfs_size: 0,
    rootfs_addr: 0,
    rootfs_size: 0,
    cpu_total: 1,
    cpu_enabled: 1,
    bsp_apic_id: 0,
    cpu_apic_ids: [0; MAX_CPU_IDS],
    cpu_apic_id_count: 1,
    smp_handoff_addr: 0,
    smp_handoff_size: 0,
    smp_trampoline_addr: 0,
    smp_trampoline_size: 0,
};

#[repr(C, align(4096))]
struct AlignedPageTable(PageTable);

static SERIAL: Mutex<SerialPort> = Mutex::new(SerialPort::new(SERIAL_BASE));
static mut MEMORY_REGIONS: [MemoryRegion; MAX_MEMORY_REGIONS] = [MemoryRegion {
    start: 0,
    len: 0,
    region_type: MemoryRegionKind::Reserved,
}; MAX_MEMORY_REGIONS];
static mut BOOT_INFO: BootInfo = EMPTY_BOOT_INFO;
static mut SMP_HANDOFF: SmpHandoff = SmpHandoff::new();
static mut PAGE_TABLES: [AlignedPageTable; 6] = [
    AlignedPageTable(PageTable::new()),
    AlignedPageTable(PageTable::new()),
    AlignedPageTable(PageTable::new()),
    AlignedPageTable(PageTable::new()),
    AlignedPageTable(PageTable::new()),
    AlignedPageTable(PageTable::new()),
];

struct SerialPort {
    data: x86_64::instructions::port::Port<u8>,
    int_en: x86_64::instructions::port::Port<u8>,
    fifo_ctrl: x86_64::instructions::port::Port<u8>,
    line_ctrl: x86_64::instructions::port::Port<u8>,
    modem_ctrl: x86_64::instructions::port::Port<u8>,
    line_status: x86_64::instructions::port::Port<u8>,
}

impl SerialPort {
    const fn new(base: u16) -> Self {
        Self {
            data: x86_64::instructions::port::Port::new(base),
            int_en: x86_64::instructions::port::Port::new(base + 1),
            fifo_ctrl: x86_64::instructions::port::Port::new(base + 2),
            line_ctrl: x86_64::instructions::port::Port::new(base + 3),
            modem_ctrl: x86_64::instructions::port::Port::new(base + 4),
            line_status: x86_64::instructions::port::Port::new(base + 5),
        }
    }

    fn init(&mut self) {
        unsafe {
            self.int_en.write(0x00);
            self.line_ctrl.write(0x80);
            self.data.write(0x03);
            self.int_en.write(0x00);
            self.line_ctrl.write(0x03);
            self.fifo_ctrl.write(0xC7);
            self.modem_ctrl.write(0x0B);
        }
    }

    fn write_byte(&mut self, byte: u8) {
        unsafe {
            while self.line_status.read() & 0x20 == 0 {}
            self.data.write(byte);
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

fn serial_init() {
    SERIAL.lock().init();
}

fn serial_print(args: core::fmt::Arguments) {
    let mut serial = SERIAL.lock();
    let _ = serial.write_fmt(args);
}

macro_rules! slog {
    ($($arg:tt)*) => {
        serial_print(format_args!($($arg)*))
    };
}

#[inline(always)]
fn align_down(addr: u64) -> u64 {
    addr & !(PAGE - 1)
}

#[inline(always)]
fn align_up(addr: u64) -> u64 {
    (addr + PAGE - 1) & !(PAGE - 1)
}

#[inline(always)]
fn uefi_to_kernel_memory_type(ty: MemoryType) -> MemoryRegionKind {
    match ty {
        x if x == MemoryType::CONVENTIONAL => MemoryRegionKind::Usable,
        x if x == MemoryType::LOADER_CODE
            || x == MemoryType::LOADER_DATA
            || x == MemoryType::BOOT_SERVICES_CODE
            || x == MemoryType::BOOT_SERVICES_DATA =>
        {
            MemoryRegionKind::BootloaderReclaimable
        }
        x if x == MemoryType::ACPI_RECLAIM => MemoryRegionKind::AcpiReclaimable,
        x if x == MemoryType::ACPI_NON_VOLATILE => MemoryRegionKind::AcpiNvs,
        x if x == MemoryType::UNUSABLE => MemoryRegionKind::BadMemory,
        _ => MemoryRegionKind::Reserved,
    }
}

fn open_filesystem(
    bs: &BootServices,
    image: Handle,
) -> Result<uefi::fs::FileSystem<'_>, Status> {
    let fs = bs
        .get_image_file_system(image)
        .map_err(|err| err.status())?;
    Ok(uefi::fs::FileSystem::new(fs))
}

fn load_file(fs: &mut uefi::fs::FileSystem<'_>, path: &str) -> Result<Vec<u8>, Status> {
    let path = CString16::try_from(path).map_err(|_| Status::INVALID_PARAMETER)?;
    fs.read(path.as_ref()).map_err(|err| match err {
        FsError::Io(io) => io.uefi_error.status(),
        FsError::Path(_) | FsError::Utf8Encoding(_) => Status::LOAD_ERROR,
    })
}

fn read_elf_header(bytes: &[u8]) -> Result<&Elf64Header, Status> {
    if bytes.len() < size_of::<Elf64Header>() {
        return Err(Status::LOAD_ERROR);
    }
    let hdr = unsafe { &*(bytes.as_ptr() as *const Elf64Header) };
    if hdr.e_ident[..4] != ELF_MAGIC {
        return Err(Status::LOAD_ERROR);
    }
    if hdr.e_machine != EM_X86_64 {
        return Err(Status::LOAD_ERROR);
    }
    Ok(hdr)
}

fn load_kernel(bs: &BootServices, bytes: &[u8]) -> Result<u64, Status> {
    let hdr = read_elf_header(bytes)?;
    let phoff = hdr.e_phoff as usize;
    let phentsize = hdr.e_phentsize as usize;
    let phnum = hdr.e_phnum as usize;
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;

    for idx in 0..phnum {
        let off = phoff
            .checked_add(idx.checked_mul(phentsize).ok_or(Status::LOAD_ERROR)?)
            .ok_or(Status::LOAD_ERROR)?;
        if off + size_of::<Elf64Phdr>() > bytes.len() {
            return Err(Status::LOAD_ERROR);
        }
        let ph = unsafe { &*(bytes[off..].as_ptr() as *const Elf64Phdr) };
        if ph.p_type != PT_LOAD {
            continue;
        }
        min_vaddr = min_vaddr.min(align_down(ph.p_vaddr));
        max_vaddr = max_vaddr.max(align_up(ph.p_vaddr + ph.p_memsz));
    }

    if min_vaddr == u64::MAX || max_vaddr <= min_vaddr {
        return Err(Status::LOAD_ERROR);
    }

    let image_size = max_vaddr - min_vaddr;
    let pages = ((image_size + PAGE - 1) / PAGE) as usize;
    let load_base = bs
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| err.status())?;
    unsafe {
        write_bytes(load_base as *mut u8, 0, (pages as u64 * PAGE) as usize);
    }

    let bias = load_base as i64 - min_vaddr as i64;
    let mut dynamic: Option<&Elf64Phdr> = None;

    for idx in 0..phnum {
        let off = phoff
            .checked_add(idx.checked_mul(phentsize).ok_or(Status::LOAD_ERROR)?)
            .ok_or(Status::LOAD_ERROR)?;
        if off + size_of::<Elf64Phdr>() > bytes.len() {
            return Err(Status::LOAD_ERROR);
        }
        let ph = unsafe { &*(bytes[off..].as_ptr() as *const Elf64Phdr) };
        match ph.p_type {
            PT_LOAD => {
                let dst = load_base + (ph.p_vaddr - min_vaddr);
                let src_start = ph.p_offset as usize;
                let src_end = src_start
                    .checked_add(ph.p_filesz as usize)
                    .ok_or(Status::LOAD_ERROR)?;
                if src_end > bytes.len() {
                    return Err(Status::LOAD_ERROR);
                }

                unsafe {
                    copy_nonoverlapping(
                        bytes[src_start..src_end].as_ptr(),
                        dst as *mut u8,
                        ph.p_filesz as usize,
                    );
                    if ph.p_memsz > ph.p_filesz {
                        write_bytes(
                            (dst + ph.p_filesz) as *mut u8,
                            0,
                            (ph.p_memsz - ph.p_filesz) as usize,
                        );
                    }
                }
            }
            PT_DYNAMIC => dynamic = Some(ph),
            _ => {}
        }
    }

    if let Some(dynamic) = dynamic {
        let dyn_start = dynamic.p_offset as usize;
        let dyn_end = dyn_start
            .checked_add(dynamic.p_filesz as usize)
            .ok_or(Status::LOAD_ERROR)?;
        if dyn_end > bytes.len() {
            return Err(Status::LOAD_ERROR);
        }

        let dyn_bytes = &bytes[dyn_start..dyn_end];
        let dyn_count = dyn_bytes.len() / size_of::<Elf64Dyn>();
        let mut rela_ptr = 0u64;
        let mut rela_size = 0u64;
        let mut rela_ent = size_of::<Elf64Rela>() as u64;

        for idx in 0..dyn_count {
            let d = unsafe {
                &*(dyn_bytes[idx * size_of::<Elf64Dyn>()..].as_ptr() as *const Elf64Dyn)
            };
            match d.d_tag {
                0 => break,
                7 => rela_ptr = d.d_val,
                8 => rela_size = d.d_val,
                9 => rela_ent = d.d_val,
                _ => {}
            }
        }

        if rela_ptr != 0 && rela_size != 0 {
            if rela_ent as usize != size_of::<Elf64Rela>() {
                return Err(Status::LOAD_ERROR);
            }

            let rela_off = (rela_ptr - min_vaddr) as usize;
            let rela_end = rela_off
                .checked_add(rela_size as usize)
                .ok_or(Status::LOAD_ERROR)?;
            if rela_end > image_size as usize {
                return Err(Status::LOAD_ERROR);
            }

            let rela_bytes = unsafe {
                core::slice::from_raw_parts(
                    (load_base + rela_off as u64) as *const u8,
                    rela_size as usize,
                )
            };
            let rela_count = rela_bytes.len() / size_of::<Elf64Rela>();

            for idx in 0..rela_count {
                let rela = unsafe {
                    &*(rela_bytes[idx * size_of::<Elf64Rela>()..].as_ptr() as *const Elf64Rela)
                };
                let r_type = (rela.r_info & 0xffff_ffff) as u32;
                if r_type != R_X86_64_RELATIVE {
                    return Err(Status::LOAD_ERROR);
                }

                let target = load_base + (rela.r_offset - min_vaddr);
                let value = (bias as i128 + rela.r_addend as i128) as u64;
                unsafe {
                    (target as *mut u64).write_unaligned(value);
                }
            }
        }
    }

    Ok((load_base as i64 + (hdr.e_entry as i64 - min_vaddr as i64)) as u64)
}

fn load_blob(bs: &BootServices, bytes: &[u8]) -> Result<(u64, usize), Status> {
    if bytes.is_empty() {
        return Ok((0, 0));
    }
    let pages = ((bytes.len() as u64 + PAGE - 1) / PAGE) as usize;
    let phys = bs
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| err.status())?;
    unsafe {
        copy_nonoverlapping(bytes.as_ptr(), phys as *mut u8, bytes.len());
    }
    Ok((phys, bytes.len()))
}

fn build_identity_map() {
    unsafe {
        let pml4 = &mut PAGE_TABLES[0].0;
        let pdpt = &mut PAGE_TABLES[1].0;
        let pd0 = &mut PAGE_TABLES[2].0;
        let pd1 = &mut PAGE_TABLES[3].0;
        let pd2 = &mut PAGE_TABLES[4].0;
        let pd3 = &mut PAGE_TABLES[5].0;

        pml4[0].set_addr(
            PhysAddr::new(core::ptr::addr_of!(PAGE_TABLES[1]) as u64),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        let pds = [pd0, pd1, pd2, pd3];
        for (idx, pd) in pds.into_iter().enumerate() {
            pdpt[idx].set_addr(
                PhysAddr::new(core::ptr::addr_of!(PAGE_TABLES[idx + 2]) as u64),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
            let base = (idx as u64) * GIB;
            for entry in 0..512u64 {
                pd[entry as usize].set_addr(
                    PhysAddr::new(base + entry * (2 * MIB)),
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::HUGE_PAGE,
                );
            }
        }

        let frame = PhysFrame::containing_address(PhysAddr::new(core::ptr::addr_of!(PAGE_TABLES[0]) as u64));
        Cr3::write(frame, Cr3Flags::empty());
    }
}

fn map_memory_regions(mmap: &MemoryMap) -> usize {
    let mut count = 0usize;
    unsafe {
        for desc in mmap.entries() {
            if count >= MAX_MEMORY_REGIONS {
                break;
            }
            MEMORY_REGIONS[count] = MemoryRegion {
                start: desc.phys_start,
                len: desc.page_count * PAGE,
                region_type: uefi_to_kernel_memory_type(desc.ty),
            };
            count += 1;
        }
    }
    count
}

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    serial_init();
    slog!("boot: entering UEFI loader\n");

    if uefi::helpers::init(&mut st).is_err() {
        slog!("boot: allocator init failed\n");
        return Status::ABORTED;
    }

    let (entry, initfs_addr, initfs_size, rootfs_addr, rootfs_size) = {
        let bs = st.boot_services();
        let mut fs = match open_filesystem(bs, image) {
            Ok(fs) => fs,
            Err(err) => {
                slog!("boot: failed to open image volume: {:?}\n", err);
                return err;
            }
        };

        let kernel = match load_file(&mut fs, "kernel") {
            Ok(bytes) => bytes,
            Err(err) => {
                slog!("boot: failed to read kernel: {:?}\n", err);
                return err;
            }
        };
        let initfs = match load_file(&mut fs, "initfs") {
            Ok(bytes) => bytes,
            Err(err) => {
                slog!("boot: failed to read initfs: {:?}\n", err);
                return err;
            }
        };
        let rootfs = match load_file(&mut fs, "rootfs") {
            Ok(bytes) => bytes,
            Err(err) => {
                slog!("boot: failed to read rootfs: {:?}\n", err);
                return err;
            }
        };

        let entry = match load_kernel(bs, &kernel) {
            Ok(entry) => entry,
            Err(err) => {
                slog!("boot: kernel load failed: {:?}\n", err);
                return err;
            }
        };

        let (initfs_addr, initfs_size) = match load_blob(bs, &initfs) {
            Ok(v) => v,
            Err(err) => {
                slog!("boot: initfs load failed: {:?}\n", err);
                return err;
            }
        };
        let (rootfs_addr, rootfs_size) = match load_blob(bs, &rootfs) {
            Ok(v) => v,
            Err(err) => {
                slog!("boot: rootfs load failed: {:?}\n", err);
                return err;
            }
        };

        (entry, initfs_addr, initfs_size, rootfs_addr, rootfs_size)
    };

    build_identity_map();
    slog!("boot: identity map ready\n");

    let (runtime_st, mmap) = unsafe { st.exit_boot_services(MemoryType::LOADER_DATA) };
    let _ = runtime_st;

    let region_count = map_memory_regions(&mmap);

    unsafe {
        BOOT_INFO = EMPTY_BOOT_INFO;
        BOOT_INFO.physical_memory_offset = 0;
        BOOT_INFO.framebuffer_addr = 0;
        BOOT_INFO.framebuffer_size = 0;
        BOOT_INFO.screen_width = 0;
        BOOT_INFO.screen_height = 0;
        BOOT_INFO.stride = 0;
        BOOT_INFO.memory_map_addr = core::ptr::addr_of!(MEMORY_REGIONS) as u64;
        BOOT_INFO.memory_map_len = region_count;
        BOOT_INFO.memory_map_entry_size = size_of::<MemoryRegion>();
        BOOT_INFO.kernel_heap_addr = 0;
        BOOT_INFO.initfs_addr = initfs_addr;
        BOOT_INFO.initfs_size = initfs_size;
        BOOT_INFO.rootfs_addr = rootfs_addr;
        BOOT_INFO.rootfs_size = rootfs_size;
        BOOT_INFO.cpu_total = 1;
        BOOT_INFO.cpu_enabled = 1;
        BOOT_INFO.bsp_apic_id = 0;
        BOOT_INFO.cpu_apic_ids = [0; MAX_CPU_IDS];
        BOOT_INFO.cpu_apic_id_count = 1;
        BOOT_INFO.smp_handoff_addr = core::ptr::addr_of!(SMP_HANDOFF) as u64;
        BOOT_INFO.smp_handoff_size = size_of::<SmpHandoff>();
        BOOT_INFO.smp_trampoline_addr = 0;
        BOOT_INFO.smp_trampoline_size = 0;
        SMP_HANDOFF = SmpHandoff {
            ready: AtomicU64::new(0),
            kernel_secondary_entry: AtomicU64::new(0),
            boot_info_ptr: AtomicU64::new(core::ptr::addr_of!(BOOT_INFO) as u64),
            kernel_cr3: AtomicU64::new(0),
            ap_count: AtomicUsize::new(0),
        };
    }

    slog!(
        "boot: kernel={:#x} initfs={} rootfs={} regions={}\n",
        entry,
        initfs_size,
        rootfs_size,
        region_count
    );

    let kernel_entry: unsafe extern "sysv64" fn(*mut BootInfo) -> ! =
        unsafe { core::mem::transmute(entry as usize) };
    unsafe { kernel_entry(core::ptr::addr_of_mut!(BOOT_INFO)) }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_init();
    slog!("boot panic: {}\n", info);
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
