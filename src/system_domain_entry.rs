#![no_std]
#![no_main]

use core::mem::size_of;
use mnu::mem::allocator::HardenedKernelHeap;
use mnu::{
    BootInfo, MemoryRegion, MemoryType, BOOT_FEATURE_HYPERVISOR_DOMAIN, BOOT_FEATURE_INITFS,
};
use mnu_abi::hypervisor::{DomainBootInfo, HypercallNumber, DOMAIN_ROLE_SYSTEM, HYPERCALL_SUCCESS};

unsafe extern "C" {
    static __kernel_end: u8;
}

#[global_allocator]
static KERNEL_ALLOCATOR: HardenedKernelHeap = HardenedKernelHeap::empty();

static mut MEMORY_MAP: [MemoryRegion; 2] = [
    MemoryRegion {
        start: 0,
        len: 0,
        region_type: MemoryType::Reserved,
    },
    MemoryRegion {
        start: 0,
        len: 0,
        region_type: MemoryType::Usable,
    },
];

static mut KERNEL_BOOT_INFO: BootInfo = BootInfo::empty();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(domain_info_ptr: *const DomainBootInfo) -> ! {
    let kernel_reserved_end = core::ptr::addr_of!(__kernel_end) as u64;
    let Some(domain_info) = (unsafe { domain_info_ptr.as_ref() }) else {
        halt()
    };
    if domain_info.validate().is_err()
        || domain_info.domain_role != DOMAIN_ROLE_SYSTEM
        || domain_info.boot_module_start < kernel_reserved_end
        || domain_info.boot_module_size == 0
        || !mnu::hypervisor_guest::configure(domain_info)
    {
        halt()
    }

    unsafe {
        MEMORY_MAP[0].len = kernel_reserved_end;
        MEMORY_MAP[1].start = kernel_reserved_end;
        MEMORY_MAP[1].len = domain_info.boot_module_start - kernel_reserved_end;
        KERNEL_BOOT_INFO.feature_flags = BOOT_FEATURE_INITFS | BOOT_FEATURE_HYPERVISOR_DOMAIN;
        KERNEL_BOOT_INFO.physical_memory_offset = 0;
        KERNEL_BOOT_INFO.memory_map_addr = core::ptr::addr_of!(MEMORY_MAP) as u64;
        KERNEL_BOOT_INFO.memory_map_len = 2;
        KERNEL_BOOT_INFO.memory_map_entry_size = size_of::<MemoryRegion>() as u32;
        KERNEL_BOOT_INFO.kernel_heap_addr = &KERNEL_ALLOCATOR as *const HardenedKernelHeap as u64;
        KERNEL_BOOT_INFO.initfs_addr = domain_info.boot_module_start;
        KERNEL_BOOT_INFO.initfs_size = domain_info.boot_module_size;
        KERNEL_BOOT_INFO.cpu_total = 1;
        KERNEL_BOOT_INFO.cpu_enabled = 1;
        KERNEL_BOOT_INFO.cpu_apic_ids[0] = 0;
        KERNEL_BOOT_INFO.cpu_apic_id_count = 1;
        KERNEL_BOOT_INFO.entropy_seed = domain_info.entropy_seed;
        KERNEL_BOOT_INFO.entropy_seed_valid = domain_info.entropy_seed_valid;
    }

    if mnu::hypervisor_guest::invoke(HypercallNumber::Ready, 0, 0, 0) != HYPERCALL_SUCCESS {
        halt()
    }
    let boot_info = unsafe { &*core::ptr::addr_of!(KERNEL_BOOT_INFO) };
    mnu::smp::set_boot_info_addr(boot_info as *const BootInfo as u64);
    mnu::kernel_entry(boot_info)
}

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
    }
}
