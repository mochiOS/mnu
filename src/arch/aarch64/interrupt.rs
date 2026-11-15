//! Native exception policy over the shared VM, scheduler and upcall machinery.
//! Interrupt-controller resources and their ownership are supplied separately.
use crate::arch::exception::{ExceptionFrame, ExceptionKind, ExceptionOrigin, UserAbort};
use crate::syscall::syscall_entry::{finish_user_trap, retain_user_trap};

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
    if frame.kind() != Some(ExceptionKind::Synchronous)
        || frame.origin() != Some(ExceptionOrigin::LowerAArch64)
    {
        // No controller is enabled by this module. IRQ/FIQ/SError and kernel
        // faults require their dedicated handler; never acknowledge and lose
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
