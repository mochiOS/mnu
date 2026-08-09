use crate::capability::path::{
    PATH_CREATE, PATH_LIST, PATH_READ, PATH_WRITE, PathRights, register_service_paths,
};
use crate::result::handle_kernel_error;
use crate::result::{Kernel, Process};
use crate::util::log::LogLevel;
use crate::{BootInfo, MemoryRegion, Result, init::kinit, task, util};
use crate::{debug, info};
use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicU64, AtomicUsize};

const KERNEL_THREAD_STACK_SIZE: usize = 4096 * 8;
static KERNEL_PROCESS_ID_RAW: AtomicU64 = AtomicU64::new(0);
static AP_IDLE_THREAD_SEQ: AtomicUsize = AtomicUsize::new(0);

#[repr(align(16))]
struct KernelStack([u8; KERNEL_THREAD_STACK_SIZE]);

static mut KERNEL_THREAD_STACK: KernelStack = KernelStack([0; KERNEL_THREAD_STACK_SIZE]);

fn kernel_process_id() -> Option<task::ProcessId> {
    let raw = KERNEL_PROCESS_ID_RAW.load(Ordering::Acquire);
    (raw != 0).then(|| task::ProcessId::from_u64(raw))
}

fn ap_idle_loop() -> ! {
    loop {
        task::schedule_and_switch();
        x86_64::instructions::hlt();
    }
}

fn spawn_ap_idle_thread() -> Result<(task::ThreadId, usize)> {
    let kernel_stack = task::allocate_kernel_stack(KERNEL_THREAD_STACK_SIZE)
        .ok_or(Kernel::Memory(crate::result::Memory::OutOfMemory))?;
    let seq = AP_IDLE_THREAD_SEQ.fetch_add(1, Ordering::AcqRel) + 1;
    let name = alloc::format!("ap-idle-{}", seq);
    let idle_process =
        task::Process::new(&name, task::PrivilegeLevel::Core, kernel_process_id(), 0);
    let idle_pid = idle_process.id();
    if task::add_process(idle_process).is_none() {
        task::free_kernel_stack(kernel_stack);
        return Err(Kernel::Process(Process::MaxProcessesReached));
    }
    let mut thread = task::Thread::new(
        idle_pid,
        &name,
        ap_idle_loop,
        kernel_stack,
        KERNEL_THREAD_STACK_SIZE,
    );
    thread.set_cpu_affinity(Some(crate::percpu::current_cpu_id()));
    let Some(thread_id) = task::add_thread(thread) else {
        task::free_kernel_stack(kernel_stack);
        return Err(Kernel::Process(Process::MaxProcessesReached));
    };
    let slot =
        task::thread_slot_index(thread_id).ok_or(Kernel::Process(Process::ProcessNotFound))?;
    Ok((thread_id, slot))
}

/// カーネルメイン関数
fn kernel_main() -> ! {
    util::log::set_level(LogLevel::Info);
    debug!("Kernel started");

    if let Some(handoff) = crate::smp::handoff() {
        let kernel_cr3 = crate::percpu::kernel_cr3();
        let secondary_entry = secondary_cpu_entry as *const () as usize as u64;
        let ap_count = handoff.ap_count.load(Ordering::Acquire);
        handoff.kernel_cr3.store(kernel_cr3, Ordering::Release);
        handoff
            .kernel_secondary_entry
            .store(secondary_entry, Ordering::Release);
        handoff.ready.store(1, Ordering::Release);
        info!(
            "SMP handoff released secondary CPUs: kernel_cr3={:#x} ap_count={}",
            kernel_cr3, ap_count
        );
    }

    crate::smp::start_secondary_cpus();

    let mut caps = crate::capability::CapabilitySet::empty();
    for cap in crate::capability::Capability::kernel_enforced_capabilities() {
        if matches!(
            cap,
            crate::capability::Capability::DmaAllocate
                | crate::capability::Capability::MemoryPhysMap
                | crate::capability::Capability::MemoryPhysTranslate
        ) {
            continue;
        }
        caps.insert(*cap);
    }
    caps.insert(crate::capability::Capability::UsbAccess);
    let mut kernel_authorities = crate::capability::KernelAuthoritySet::empty();
    kernel_authorities.insert(crate::capability::KernelAuthority::new(
        crate::capability::KernelCapability::PhysMap,
        crate::capability::KernelObjectRef::MmioRegion {
            base: 0,
            size: u64::MAX - 0xfff,
        },
    ));

    // 最小のサービス管理プロセスを起動する。
    info!("Starting service manager");
    let boot_launch = crate::policy::service_manager_launch();
    let manager_pid = crate::syscall::exec::exec_kernel_with_name_caps_and_authorities(
        boot_launch.exec_path,
        boot_launch.process_name,
        caps.clone(),
        kernel_authorities,
        crate::task::PrivilegeLevel::Service,
    );
    crate::info!("service manager pid = {:#x}", manager_pid);
    if manager_pid != 0
        && task::with_process(task::ProcessId::from_u64(manager_pid), |_| ()).is_some()
    {
        crate::policy::register_service_manager_pid(manager_pid);
        if let Some(pid) = task::with_process(task::ProcessId::from_u64(manager_pid), |proc| {
            let spawn = proc
                .capabilities()
                .contains(crate::capability::Capability::ProcessSpawn);
            let inspect = proc
                .capabilities()
                .contains(crate::capability::Capability::ProcessInspect);
            (spawn, inspect)
        }) {
            crate::info!(
                "service manager caps: process.spawn={} process.inspect={}",
                pid.0,
                pid.1
            );
        }
        let service_paths = [
            (
                "/tmp/core.service.fs-test",
                PathRights::new(PATH_READ | PATH_WRITE | PATH_CREATE),
            ),
            ("/tmp/testdata", PathRights::new(PATH_READ | PATH_LIST)),
        ];
        let _ = register_service_paths(manager_pid, &service_paths);
    } else {
        crate::warn!(
            "Failed to register service manager (ret={:#x})",
            manager_pid
        );
    }

    // カーネルはアイドル状態に入る
    info!("Kernel initialization complete. Entering idle loop...");
    loop {
        x86_64::instructions::hlt();
    }
}

/// カーネルエントリポイント（kernel binary から呼ばれる）
pub fn kernel_entry(boot_info: &'static BootInfo) -> ! {
    crate::smp::set_handoff_addr(boot_info.smp_handoff_addr);
    let memory_map = match kinit(boot_info) {
        Ok(map) => map,
        Err(e) => {
            handle_kernel_error(e);
            halt_forever();
        }
    };

    create_kernel_proc(boot_info, memory_map).unwrap_or_else(|e| {
        handle_kernel_error(e);
        halt_forever();
    });
    task::start_scheduling();
}

#[unsafe(no_mangle)]
pub extern "sysv64" fn secondary_cpu_entry(boot_info: *const BootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info.as_ref() }) else {
        halt_forever();
    };
    crate::smp::set_handoff_addr(boot_info.smp_handoff_addr);
    info!(
        "Secondary CPU entering kernel: boot_info={:#x} handoff={:#x}",
        boot_info as *const BootInfo as u64, boot_info.smp_handoff_addr
    );
    crate::mem::gdt::init();
    info!("Secondary CPU GDT/TSS initialized");
    crate::interrupt::init_idt();
    info!("Secondary CPU IDT initialized");
    crate::cpu::init();
    info!("Secondary CPU CPU features initialized");
    crate::syscall::syscall_entry::init_syscall_current_cpu();
    info!("Secondary CPU syscall state initialized");
    if crate::smp::enable_local_scheduler_timer() {
        info!("Secondary CPU scheduler timer initialized");
    } else {
        crate::warn!("Secondary CPU scheduler timer unavailable");
    }
    let (idle_thread_id, idle_thread_slot) = match spawn_ap_idle_thread() {
        Ok(v) => v,
        Err(err) => {
            crate::warn!("Failed to create AP idle thread: {:?}", err);
            halt_forever();
        }
    };
    if let Some(handoff) = crate::smp::handoff() {
        let before = handoff.ap_count.fetch_add(1, Ordering::SeqCst);
        info!(
            "Secondary CPU online: ap_count {} -> {}",
            before,
            before + 1
        );
    }
    info!(
        "Secondary CPU switching to idle thread {:?} (slot={})",
        idle_thread_id, idle_thread_slot
    );
    task::set_thread_state(idle_thread_id, task::ThreadState::Running);
    unsafe {
        x86_64::instructions::interrupts::enable();
    }
    unsafe {
        task::context::switch_to_thread_with_slots(None, None, idle_thread_id, idle_thread_slot);
    }
    crate::warn!("Secondary CPU idle thread switch returned unexpectedly");
    halt_forever();
}

#[used]
#[unsafe(no_mangle)]
pub static SECONDARY_CPU_ENTRY: unsafe extern "sysv64" fn(*const BootInfo) -> ! =
    secondary_cpu_entry;

/// カーネルメインプロセスの作成
fn create_kernel_proc(
    boot_info: &'static BootInfo,
    memory_map: &'static [MemoryRegion],
) -> Result<()> {
    let kernel_process = task::Process::new("kernel", task::PrivilegeLevel::Core, None, 0);
    let kernel_pid = kernel_process.id();
    KERNEL_PROCESS_ID_RAW.store(kernel_pid.as_u64(), Ordering::Release);

    if task::add_process(kernel_process).is_none() {
        return Err(Kernel::Process(Process::MaxProcessesReached));
    }

    let stack_addr = unsafe { (&raw const KERNEL_THREAD_STACK as *const u8) as u64 };
    let mut kernel_thread = task::Thread::new(
        kernel_pid,
        "core",
        kernel_main,
        stack_addr,
        KERNEL_THREAD_STACK_SIZE,
    );
    kernel_thread.set_cpu_affinity(Some(crate::percpu::current_cpu_id()));

    if task::add_thread(kernel_thread).is_none() {
        return Err(Kernel::Process(Process::MaxProcessesReached));
    }

    Ok(())
}

/// システムを無限ループで停止
fn halt_forever() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
