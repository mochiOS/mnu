//! Task-owned address-space and exception-stack selection for native EL0 entry.
use crate::arch::exception::SyscallUserContext;
use mnu_abi::status::Error;

fn current_user_root() -> Option<u64> {
    let id = crate::task::current_thread_id()?;
    let process = crate::task::with_thread(id, |thread| thread.process_id())?;
    // Never retain the thread-queue lock across the process lookup or entry.
    crate::task::with_process(process, |process| process.page_table())?
        .filter(|root| *root != 0 && root & 4095 == 0)
}

/// Enter a newly created thread with only x0 and TLS initialized.
///
/// # Safety
/// The current thread must retain this process and its kernel stack. `entry`
/// and `user_stack` must name executable/writable mappings in that process.
pub unsafe fn jump_to_usermode(entry: u64, user_stack: u64, argument: u64) -> ! {
    crate::arch::interrupts::disable();
    let Some(tls) = crate::task::current_thread_id()
        .and_then(|id| crate::task::with_thread(id, |thread| thread.fs_base()))
    else {
        crate::task::scheduler::exit_current_process(Error::NotReady.into_raw());
    };
    let mut context = SyscallUserContext::empty();
    context.instruction_pointer = entry;
    context.stack_pointer = user_stack;
    // SAFETY: The caller retains the selected process and both stack mappings.
    unsafe { resume_usermode(context, argument, tls) }
}

/// Resume the current thread's complete native register image.
///
/// # Safety
/// Retain the current process and its owned kernel stack, exclude scheduling
/// and hold no locks through the terminal transition. The selected PC/SP must
/// have already passed the VM layer's executable/writable mapping checks.
pub unsafe fn resume_usermode(context: SyscallUserContext, result: u64, tls: u64) -> ! {
    crate::arch::interrupts::disable();
    let Some(root) = current_user_root() else {
        crate::task::scheduler::exit_current_process(Error::NotReady.into_raw());
    };
    let kernel_stack = crate::percpu::syscall_kernel_rsp();
    if !context.valid()
        || tls > 0x0000_7fff_ffff_ffff
        || kernel_stack == 0
        || kernel_stack & 15 != 0
    {
        crate::task::scheduler::exit_current_process(Error::InvalidArgument.into_raw());
    }
    // SAFETY: The current process owns this TTBR0 root. TTBR1 keeps the kernel
    // code, retained register image, exception vectors and trusted stack mapped.
    unsafe {
        crate::mem::paging::switch_page_table(root);
        match crate::arch::usermode::resume_user(&context, result, tls, kernel_stack) {
            Ok(never) => match never {},
            Err(_) => {
                crate::task::scheduler::exit_current_process(Error::InvalidArgument.into_raw())
            }
        }
    }
}
