//! per-CPU 状態管理（SMP拡張の基盤）
//!
//! APIC ID をキーに CPU ローカルスロットを選択する。

use core::arch::asm;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

pub const MAX_CPUS: usize = 64;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const SYSCALL_SHARED_BASE: u64 = 0x0000_7fff_0000_0000;
pub const SYSCALL_SHARED_STACK_BASE: u64 = SYSCALL_SHARED_BASE + (MAX_CPUS as u64) * 4096;

#[repr(C)]
struct PerCpuState {
    kernel_cr3: AtomicU64,
    syscall_kernel_rsp: AtomicU64,
    current_thread_id: AtomicU64,
    current_thread_slot: AtomicU64,
    syscall_user_rsp_tmp: AtomicU64,
}

#[repr(C)]
struct SyscallPerCpuState {
    kernel_cr3: AtomicU64,
    syscall_kernel_rsp: AtomicU64,
    syscall_user_rsp_tmp: AtomicU64,
    syscall_trampoline_rsp: AtomicU64,
    syscall_user_r10_tmp: AtomicU64,
}

pub const GS_KERNEL_CR3_OFFSET: usize = offset_of!(SyscallPerCpuState, kernel_cr3);
pub const GS_SYSCALL_KERNEL_RSP_OFFSET: usize = offset_of!(SyscallPerCpuState, syscall_kernel_rsp);
pub const GS_SYSCALL_USER_RSP_TMP_OFFSET: usize =
    offset_of!(SyscallPerCpuState, syscall_user_rsp_tmp);
pub const GS_SYSCALL_TRAMPOLINE_RSP_OFFSET: usize =
    offset_of!(SyscallPerCpuState, syscall_trampoline_rsp);
pub const GS_SYSCALL_USER_R10_TMP_OFFSET: usize =
    offset_of!(SyscallPerCpuState, syscall_user_r10_tmp);

impl PerCpuState {
    const fn new() -> Self {
        Self {
            kernel_cr3: AtomicU64::new(0),
            syscall_kernel_rsp: AtomicU64::new(0),
            current_thread_id: AtomicU64::new(0),
            current_thread_slot: AtomicU64::new(u64::MAX),
            syscall_user_rsp_tmp: AtomicU64::new(0),
        }
    }
}

impl SyscallPerCpuState {
    fn at_vaddr(vaddr: u64) -> &'static Self {
        unsafe { &*(vaddr as *const Self) }
    }
}

static CPU_STATES: [PerCpuState; MAX_CPUS] = [const { PerCpuState::new() }; MAX_CPUS];
static SYSCALL_STATE_PHYS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static SYSCALL_STACK_PHYS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

#[inline]
fn state_for_current_cpu() -> &'static PerCpuState {
    &CPU_STATES[current_cpu_id()]
}

#[inline(never)]
fn halt_unsupported_cpu(_apic_id: u32) -> ! {
    x86_64::instructions::interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

#[inline]
unsafe fn write_kernel_gs_base(base: u64) {
    let lo = base as u32;
    let hi = (base >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") IA32_KERNEL_GS_BASE,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack)
    );
}

#[inline]
fn syscall_state_vaddr_for_cpu(cpu_id: usize) -> u64 {
    SYSCALL_SHARED_BASE + (cpu_id as u64) * 4096
}

#[inline]
fn syscall_stack_vaddr_for_cpu(cpu_id: usize) -> u64 {
    SYSCALL_SHARED_STACK_BASE + (cpu_id as u64) * 4096
}

pub fn is_syscall_shared_vaddr(vaddr: u64) -> bool {
    let page = vaddr & !0xfff;
    let state_start = SYSCALL_SHARED_BASE;
    let stack_start = SYSCALL_SHARED_STACK_BASE;
    let region_len = (MAX_CPUS as u64) * 4096;
    (page >= state_start && page < state_start + region_len)
        || (page >= stack_start && page < stack_start + region_len)
}

pub fn current_cpu_syscall_state_vaddr() -> u64 {
    syscall_state_vaddr_for_cpu(current_cpu_id())
}

fn map_syscall_page(cpu_id: usize, vaddr: u64, phys: u64) {
    if crate::mem::paging::translate_addr(VirtAddr::new(vaddr)).is_some() {
        return;
    }
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(vaddr));
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    if let Err(err) = crate::mem::paging::map_page(page, frame, flags) {
        panic!(
            "failed to map syscall shared page for cpu {} at {:#x}: {:?}",
            cpu_id, vaddr, err
        );
    }
}

fn ensure_syscall_shared_region_for_cpu(cpu_id: usize) {
    if SYSCALL_STATE_PHYS[cpu_id].load(Ordering::SeqCst) != 0
        && SYSCALL_STACK_PHYS[cpu_id].load(Ordering::SeqCst) != 0
    {
        return;
    }

    let state_frame = crate::mem::frame::allocate_zeroed_frame().unwrap_or_else(|_| {
        panic!(
            "failed to allocate syscall shared state page for cpu {}",
            cpu_id
        )
    });
    let stack_frame = match crate::mem::frame::allocate_zeroed_frame() {
        Ok(frame) => frame,
        Err(_) => {
            let _ = crate::mem::frame::deallocate_frame(state_frame);
            panic!(
                "failed to allocate syscall shared stack page for cpu {}",
                cpu_id
            );
        }
    };
    let state_phys = state_frame.start_address().as_u64();
    let stack_phys = stack_frame.start_address().as_u64();

    map_syscall_page(cpu_id, syscall_state_vaddr_for_cpu(cpu_id), state_phys);
    map_syscall_page(cpu_id, syscall_stack_vaddr_for_cpu(cpu_id), stack_phys);

    SYSCALL_STATE_PHYS[cpu_id].store(state_phys, Ordering::SeqCst);
    SYSCALL_STACK_PHYS[cpu_id].store(stack_phys, Ordering::SeqCst);

    let syscall_state = SyscallPerCpuState::at_vaddr(syscall_state_vaddr_for_cpu(cpu_id));
    syscall_state
        .syscall_trampoline_rsp
        .store(syscall_stack_vaddr_for_cpu(cpu_id) + 4096, Ordering::SeqCst);
}

pub fn map_syscall_shared_region_in_table(table_phys: u64) -> crate::result::Result<()> {
    for cpu_id in 0..MAX_CPUS {
        let state_phys = SYSCALL_STATE_PHYS[cpu_id].load(Ordering::SeqCst);
        let stack_phys = SYSCALL_STACK_PHYS[cpu_id].load(Ordering::SeqCst);
        if state_phys == 0 || stack_phys == 0 {
            continue;
        }
        crate::mem::paging::map_page_in_table(
            table_phys,
            syscall_state_vaddr_for_cpu(cpu_id),
            state_phys,
            true,
            false,
        )?;
        crate::mem::paging::map_page_in_table(
            table_phys,
            syscall_stack_vaddr_for_cpu(cpu_id),
            stack_phys,
            true,
            false,
        )?;
    }
    Ok(())
}

#[inline]
fn syscall_state_for_current_cpu() -> &'static SyscallPerCpuState {
    let cpu_id = current_cpu_id();
    ensure_syscall_shared_region_for_cpu(cpu_id);
    SyscallPerCpuState::at_vaddr(syscall_state_vaddr_for_cpu(cpu_id))
}

#[inline]
pub fn current_cpu_id() -> usize {
    let apic_id = local_apic_id() as usize;
    if apic_id < MAX_CPUS {
        apic_id
    } else {
        halt_unsupported_cpu(apic_id as u32)
    }
}

#[inline]
fn local_apic_id() -> u32 {
    // CPUID leaf 1: EBX[31:24] = Initial APIC ID
    let ebx: u64;
    unsafe {
        asm!(
            "xchg {tmp}, rbx",
            "cpuid",
            "xchg {tmp}, rbx",
            inout("eax") 1u32 => _,
            in("ecx") 0u32,
            tmp = inout(reg) 0u64 => ebx,
            out("edx") _,
            options(nomem, nostack)
        );
    }
    ((ebx as u32) >> 24) & 0xff
}

pub fn init_current_cpu(syscall_kernel_rsp: u64) {
    let apic_id = local_apic_id() as usize;
    let slot = if apic_id < MAX_CPUS {
        apic_id
    } else {
        crate::audit::log(
            crate::audit::AuditEventKind::Fault,
            "boot CPU APIC ID exceeded per-cpu table; falling back to CPU0 slot",
        );
        0
    };

    let (cr3, _) = Cr3::read();
    let state = &CPU_STATES[slot];
    state
        .kernel_cr3
        .store(cr3.start_address().as_u64(), Ordering::SeqCst);
    state
        .syscall_kernel_rsp
        .store(syscall_kernel_rsp, Ordering::SeqCst);
    state.current_thread_id.store(0, Ordering::SeqCst);
    state.current_thread_slot.store(u64::MAX, Ordering::SeqCst);
    state.syscall_user_rsp_tmp.store(0, Ordering::SeqCst);
    ensure_syscall_shared_region_for_cpu(slot);
    let syscall_state = SyscallPerCpuState::at_vaddr(syscall_state_vaddr_for_cpu(slot));
    syscall_state
        .kernel_cr3
        .store(cr3.start_address().as_u64(), Ordering::SeqCst);
    syscall_state
        .syscall_kernel_rsp
        .store(syscall_kernel_rsp, Ordering::SeqCst);
    syscall_state
        .syscall_user_rsp_tmp
        .store(0, Ordering::SeqCst);
    install_current_cpu_gs_base();
}

pub fn init_boot_cpu(syscall_kernel_rsp: u64) {
    init_current_cpu(syscall_kernel_rsp);
}

pub fn install_current_cpu_gs_base() {
    let cpu_id = current_cpu_id();
    ensure_syscall_shared_region_for_cpu(cpu_id);
    let state = syscall_state_vaddr_for_cpu(cpu_id);
    unsafe {
        write_kernel_gs_base(state);
    }
}

pub fn kernel_cr3() -> u64 {
    state_for_current_cpu().kernel_cr3.load(Ordering::SeqCst)
}

pub fn set_syscall_kernel_rsp(rsp: u64) {
    state_for_current_cpu()
        .syscall_kernel_rsp
        .store(rsp, Ordering::SeqCst);
    syscall_state_for_current_cpu()
        .syscall_kernel_rsp
        .store(rsp, Ordering::SeqCst);
}

pub fn syscall_kernel_rsp() -> u64 {
    state_for_current_cpu()
        .syscall_kernel_rsp
        .load(Ordering::SeqCst)
}

pub fn current_thread_raw_id() -> u64 {
    state_for_current_cpu()
        .current_thread_id
        .load(Ordering::SeqCst)
}

pub fn set_current_thread_raw_id(id: u64) {
    let current = current_thread_raw_id();
    if current == 2 || current == 3 || id == 2 || id == 3 {
        crate::debug!("[PERCPU] set_current_thread_raw_id {} -> {}", current, id);
    }
    state_for_current_cpu()
        .current_thread_id
        .store(id, Ordering::SeqCst);
}

pub fn current_thread_slot() -> Option<usize> {
    let raw = state_for_current_cpu()
        .current_thread_slot
        .load(Ordering::SeqCst);
    if raw == u64::MAX {
        None
    } else {
        Some(raw as usize)
    }
}

pub fn set_current_thread_slot(slot: Option<usize>) {
    let raw = slot.map(|value| value as u64).unwrap_or(u64::MAX);
    let current = state_for_current_cpu()
        .current_thread_slot
        .load(Ordering::SeqCst);
    if current == 2 || current == 3 || raw == 2 || raw == 3 || raw > 1024 {
        if current == u64::MAX {
            if raw == u64::MAX {
                crate::debug!("[PERCPU] set_current_thread_slot None -> None");
            } else {
                crate::debug!("[PERCPU] set_current_thread_slot None -> {}", raw);
            }
        } else if raw == u64::MAX {
            crate::debug!("[PERCPU] set_current_thread_slot {} -> None", current);
        } else {
            crate::debug!("[PERCPU] set_current_thread_slot {} -> {}", current, raw);
        }
    }
    state_for_current_cpu()
        .current_thread_slot
        .store(raw, Ordering::SeqCst);
}
