//! Native exception policy over the shared VM, scheduler and upcall machinery.
//! Interrupt-controller resources and their ownership are supplied separately.
use crate::arch::exception::{ExceptionFrame, ExceptionKind, ExceptionOrigin, UserAbort};
use crate::syscall::syscall_entry::{finish_user_trap, retain_user_trap};
use core::sync::atomic::{AtomicBool, Ordering};
use mnu_abi::arm64_interrupts::Resources;

// A virtual kernel arena, not a physical board/device address. It stays in
// TTBR1 independently of the active process's lower address space.
const CPU_INTERFACE_VA: u64 = 0xffff_c000_0000_0000;
struct Controller {
    resources: Resources,
    clock: crate::arch::timer::Clock,
    frequency: u64,
}
static CONTROLLER: spin::Once<Controller> = spin::Once::new();
static READY: [AtomicBool; crate::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::percpu::MAX_CPUS];

/// Map only the assigned CPU-interface bank. Never map the physical Distributor
/// or use map_page's replacement semantics for a pre-existing kernel mapping.
fn map_controller(resources: Resources) -> crate::Result<()> {
    use crate::arch::memory::paging::{
        mapper::MapToError, Mapper, Page, PageTableFlags as Flags, PhysFrame,
    };
    use crate::arch::memory::{PhysAddr, VirtAddr};
    use crate::result::{Kernel, Memory};
    let mut table_guard = crate::mem::paging::PAGE_TABLE.lock();
    let table = table_guard
        .as_mut()
        .ok_or(Kernel::Memory(Memory::NotMapped))?;
    let pages = [
        Page::containing_address(VirtAddr::new(CPU_INTERFACE_VA)),
        Page::containing_address(VirtAddr::new(CPU_INTERFACE_VA + 4096)),
    ];
    if pages.iter().any(|page| !table.page_is_vacant(*page)) {
        return Err(Kernel::Memory(Memory::AlreadyMapped));
    }
    let mut allocator_guard = crate::mem::frame::lock_allocator();
    let allocator = allocator_guard
        .as_mut()
        .ok_or(Kernel::Memory(Memory::OutOfMemory))?;
    let flags = Flags::PRESENT
        | Flags::WRITABLE
        | Flags::NO_EXECUTE
        | Flags::NO_CACHE
        | Flags::WRITE_THROUGH
        | Flags::BIT_52;
    for (index, &page) in pages.iter().enumerate() {
        let physical = resources.cpu_interface_base + index as u64 * 4096;
        let frame = PhysFrame::containing_address(PhysAddr::new(physical));
        // SAFETY: Validated boot resources reserve this bank for the Domain.
        // Both leaves are vacant under the same VM lock; MMIO is borrowed,
        // privileged RW/Device/XN and must never enter RAM frame accounting.
        match unsafe { table.map_to(page, frame, flags, allocator) } {
            Ok(flush) => flush.flush(),
            Err(error) => {
                for &previous in &pages[..index] {
                    // These leaves were just published by this transaction.
                    // Never free the returned MMIO frame as allocator RAM.
                    match table.unmap(previous) {
                        Ok((_, flush)) => flush.flush(),
                        Err(_) => crate::arch::halt(),
                    }
                }
                return Err(Kernel::Memory(match error {
                    MapToError::FrameAllocationFailed | MapToError::FrameReleaseFailed => {
                        Memory::OutOfMemory
                    }
                    MapToError::PageAlreadyMapped(_) | MapToError::ParentEntryHugePage => {
                        Memory::AlreadyMapped
                    }
                    MapToError::InvalidPermissions => Memory::PermissionDenied,
                    _ => Memory::InvalidAddress,
                }));
            }
        }
    }
    Ok(())
}

pub fn initialize_scheduler(info: &'static crate::BootInfo) -> crate::Result<()> {
    use crate::result::{Device, Kernel};
    if info.validate().is_err()
        || info.feature_flags & mnu_abi::boot::BOOT_FEATURE_ARM64_INTERRUPTS == 0
        || crate::arch::interrupts::are_enabled()
        || !crate::percpu::kernel_page_table_ready()
    {
        return Err(Kernel::InvalidParam);
    }
    let frequency = crate::arch::counter::frequency_hz();
    let controller = CONTROLLER.try_call_once(|| {
        let clock = crate::arch::timer::Clock::new(
            crate::arch::counter::timestamp(),
            frequency,
            crate::interrupt::timer::TICKS_PER_SECOND,
        )
        .map_err(|_| Kernel::InvalidParam)?;
        map_controller(info.arm64_interrupts)?;
        Ok(Controller {
            resources: info.arm64_interrupts,
            clock,
            frequency,
        })
    })?;
    if controller.resources != info.arm64_interrupts
        || controller.frequency != frequency
        || READY[crate::percpu::current_cpu_id()].load(Ordering::Acquire)
    {
        return Err(Kernel::InvalidParam);
    }
    if crate::hypervisor_guest::invoke(
        mnu_abi::hypervisor::HypercallNumber::EventIrqEnable,
        0,
        0,
        0,
    ) != mnu_abi::hypervisor::HYPERCALL_SUCCESS
    {
        return Err(Kernel::Device(Device::HardwareFailure));
    }
    // SAFETY: The immutable boot transaction retained this assigned bank.
    let mut interface = unsafe {
        crate::arch::gic::CpuInterface::new(
            CPU_INTERFACE_VA,
            controller.resources.cpu_interface_size,
        )
    }
    .map_err(|_| Kernel::Device(Device::HardwareFailure))?;
    interface
        .enable()
        .map_err(|_| Kernel::Device(Device::HardwareFailure))?;
    let mut timer = crate::arch::timer::LocalTimer::new(crate::interrupt::timer::TICKS_PER_SECOND)
        .map_err(|_| Kernel::InvalidParam)?;
    timer
        .start()
        .map_err(|_| Kernel::Device(Device::HardwareFailure))?;
    READY[crate::percpu::current_cpu_id()].store(true, Ordering::Release);
    Ok(())
}

fn handle_irq(frame: &mut ExceptionFrame) -> u64 {
    if !READY[crate::percpu::current_cpu_id()].load(Ordering::Acquire) {
        return 1;
    }
    crate::syscall::syscall_entry::verify_kernel_page_table_before_rust();
    let user = frame.origin() == Some(ExceptionOrigin::LowerAArch64);
    if !user && frame.origin() != Some(ExceptionOrigin::CurrentSpx) {
        return 1;
    }
    let thread = if user {
        let Some(id) = retain_user_trap(frame) else {
            return 1;
        };
        Some(id)
    } else {
        None
    };
    let Some(controller) = CONTROLLER.get() else {
        return 1;
    };
    let Ok(mut interface) = (unsafe {
        crate::arch::gic::CpuInterface::new(
            CPU_INTERFACE_VA,
            controller.resources.cpu_interface_size,
        )
    }) else {
        return 1;
    };
    let Ok(pending) = interface.acknowledge() else {
        return 1;
    };
    let mut schedule = false;
    if let Some(pending) = pending {
        let number = pending.interrupt();
        if number == controller.resources.timer_interrupt {
            let Ok(mut timer) =
                crate::arch::timer::LocalTimer::new(crate::interrupt::timer::TICKS_PER_SECOND)
            else {
                return 1;
            };
            let Ok(now) = timer.handle() else {
                return 1;
            };
            crate::interrupt::timer::advance_to(controller.clock.ticks(now));
            crate::performance::increment(crate::performance::CounterMetric::TimerInterrupts, 1);
            schedule = crate::task::scheduler_tick(user);
        } else if number == controller.resources.tlb_interrupt {
            crate::mem::tlb_shootdown::service_pending();
        } else if number != controller.resources.wake_interrupt
            && number != controller.resources.event_interrupt
            && number != controller.resources.management_interrupt
        {
            crate::error!("Unassigned native IRQ {}", number);
            return 1;
        }
        // Wake/event/management are level-independent notifications; payloads
        // remain in their owned EL2 queues for the existing transport to drain.
        if pending.complete().is_err() {
            return 1;
        }
    }
    // EOI must complete on the acknowledging CPU before stack/CPU scheduling.
    if schedule {
        crate::task::schedule_and_switch();
    }
    if let Some(id) = thread {
        crate::syscall::upcall::prepare_interrupt_return(frame);
        return u64::from(!finish_user_trap(frame, id));
    }
    0
}

pub fn init() {
    if crate::arch::interrupts::are_enabled() {
        crate::arch::halt();
    }
    // SAFETY: Boot/secondary initialization retains this CPU's EL1 stack,
    // enabled FP/SIMD and kernel vector mapping with IRQs still masked.
    unsafe { crate::arch::exception::install_vectors() };
}

fn resolve_user_abort(abort: UserAbort) -> Result<(), mnu_abi::MemoryFaultCause> {
    use mnu_abi::MemoryFaultCause;
    if abort.write && abort.protection {
        let root = crate::syscall::syscall_entry::current_thread_user_page_table()
            .ok_or(MemoryFaultCause::Unresolved)?;
        match crate::syscall::process::resolve_user_copy_on_write(root, abort.address) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(crate::Kernel::Memory(crate::result::Memory::Busy)) => {
                crate::task::yield_now();
                return Ok(());
            }
            Err(_) => return Err(MemoryFaultCause::Unresolved),
        }
    }
    let cause = match crate::syscall::process::handle_user_memory_fault(
        abort.address,
        abort.write,
        abort.execute,
    ) {
        Ok(()) => return Ok(()),
        Err(fault) if fault.is_retryable() => {
            // The VM resolver has dropped all guards. Retry the original
            // instruction only after giving the mutation owner CPU time.
            crate::task::yield_now();
            return Ok(());
        }
        Err(fault) => fault.cause(),
    };
    if !abort.protection && crate::interrupt::user_stack::try_grow_user_stack(abort.address) {
        return Ok(());
    }
    Err(cause)
}

fn terminate(frame: &ExceptionFrame, cause: mnu_abi::MemoryFaultCause) -> ! {
    let address =
        if matches!(frame.exception_class(), 0x20 | 0x24) && frame.syndrome() & (1 << 10) == 0 {
            frame.fault_address()
        } else {
            0
        };
    if let Some(id) = crate::task::current_thread_id() {
        crate::task::with_thread_mut(id, |thread| {
            thread.note_exception(crate::util::process_diagnostics::Exception {
                timestamp_ns: crate::syscall::time::monotonic_nanoseconds(),
                vector: u32::from(frame.exception_class()),
                cause: cause as u32,
                error_code: frame.syndrome(),
                instruction: frame.instruction_pointer(),
                stack_pointer: frame.user_stack_pointer(),
                address,
            });
        });
    }
    crate::task::scheduler::exit_current_process(u64::MAX)
}

/// The architecture vector entry is the sole caller, supplying its complete
/// kernel-owned frame. Returning nonzero keeps the vector from executing ERET.
#[unsafe(no_mangle)]
unsafe extern "C" fn mnu_aarch64_exception_dispatch(raw: *mut ExceptionFrame) -> u64 {
    let frame = unsafe { &mut *raw };
    if frame.origin() == Some(ExceptionOrigin::LowerAArch64) {
        crate::cpu::branch_predictor_barrier();
    }
    if frame.kind() == Some(ExceptionKind::Irq) {
        return handle_irq(frame);
    }
    if frame.kind() != Some(ExceptionKind::Synchronous)
        || frame.origin() != Some(ExceptionOrigin::LowerAArch64)
    {
        // FIQ/SError and kernel faults require their dedicated handler; never
        // them or resume an unknown privileged fault as a successful syscall.
        crate::error!(
            "Unhandled native exception: kind={:?} origin={:?} ESR={:#x} PC={:#x}",
            frame.kind(),
            frame.origin(),
            frame.syndrome(),
            frame.instruction_pointer()
        );
        return 1;
    }
    if crate::syscall::syscall_entry::handle_svc(frame) {
        return 0;
    }
    let Some(id) = retain_user_trap(frame) else {
        return 1;
    };
    if let Some(abort) = frame.user_abort() {
        let cause = match resolve_user_abort(abort) {
            Ok(()) => return u64::from(!finish_user_trap(frame, id)),
            Err(cause) => cause,
        };
        if crate::syscall::prepare_user_exception(frame, abort.address, cause) {
            return u64::from(!finish_user_trap(frame, id));
        }
        terminate(frame, cause);
    }
    terminate(frame, mnu_abi::MemoryFaultCause::Unresolved)
}
