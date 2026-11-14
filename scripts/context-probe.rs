//! Real stack handoffs with distinct register sentinels on each continuation.
//! Only this fixture owns these statics; the VM has one CPU and IRQ handlers
//! never touch them. No scheduler, userspace or Domain isolation is simulated.
use crate::arch::context::{switch_context, Context};
use crate::{arch, check};
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(16))]
struct Stack([u8; 16384]);

static mut STACK: Stack = Stack([0; 16384]);
static mut ROOT: Context = Context::new();
static mut WORKER: Context = Context::new();
static MARKER: AtomicU64 = AtomicU64::new(0);
static STEPS: AtomicU64 = AtomicU64::new(0);

pub fn run() {
    let enabled = arch::interrupts::are_enabled();
    arch::interrupts::disable();
    let bottom = core::ptr::addr_of!(STACK) as u64;
    let top = bottom + core::mem::size_of::<Stack>() as u64;
    unsafe {
        let context = Context::for_kernel_entry(
            worker as *const () as u64,
            top,
            unexpected_return as *const () as u64,
            true,
        );
        check(
            context.stack_pointer() >= bottom && context.stack_pointer() < top,
            "initial stack range",
        );
        check(
            context.instruction_pointer() == worker as *const () as u64,
            "initial entry",
        );
        WORKER = context;
        for round in 1..=16 {
            MARKER.store(0x1234, Ordering::Release);
            let status = sentinel_switch(
                core::ptr::addr_of_mut!(ROOT),
                core::ptr::addr_of!(WORKER),
                MARKER.as_ptr(),
                1,
            );
            check(status == 0, "root register/FP restoration");
            check(
                MARKER.load(Ordering::Acquire) == 0,
                "root handoff incomplete",
            );
            check(
                STEPS.load(Ordering::Acquire) == round,
                "lost worker continuation",
            );
            check(!arch::interrupts::are_enabled(), "root IRQ state");
        }
    }
    if enabled {
        arch::interrupts::enable();
    }
    crate::emit("Kernel context round trips PASS\n");
}

#[cfg(target_arch = "x86_64")]
extern "sysv64" fn worker() -> ! {
    worker_body()
}

#[cfg(target_arch = "aarch64")]
extern "C" fn worker() -> ! {
    worker_body()
}

fn worker_body() -> ! {
    let bottom = core::ptr::addr_of!(STACK) as u64;
    let top = bottom + core::mem::size_of::<Stack>() as u64;
    let sp = arch::stack_pointer();
    check(sp >= bottom && sp < top, "worker did not switch stack");
    check(arch::interrupts::are_enabled(), "initial worker IRQ state");
    loop {
        arch::interrupts::disable();
        check(
            MARKER.load(Ordering::Acquire) == 0,
            "worker handoff incomplete",
        );
        STEPS.fetch_add(1, Ordering::Release);
        MARKER.store(0x5678, Ordering::Release);
        #[cfg(target_arch = "aarch64")]
        arch::interrupts::enable();
        let status = unsafe {
            sentinel_switch(
                core::ptr::addr_of_mut!(WORKER),
                core::ptr::addr_of!(ROOT),
                MARKER.as_ptr(),
                2,
            )
        };
        check(status == 0, "worker register/FP restoration");
        #[cfg(target_arch = "aarch64")]
        check(arch::interrupts::are_enabled(), "worker IRQ restoration");
    }
}

extern "C" fn unexpected_return() -> ! {
    crate::fail("worker returned");
}

// Naked wrappers check registers before Rust can reuse them. Each saves its
// caller's ABI state and FP control before installing distinct thread values.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn sentinel_switch(
    _old: *mut Context,
    _new: *const Context,
    _marker: *mut u64,
    _seed: u64,
) -> u64 {
    core::arch::naked_asm!(
        "sub sp, sp, #256",
        "stp x19, x20, [sp, #0]",
        "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]",
        "stp x25, x26, [sp, #48]",
        "stp x27, x28, [sp, #64]",
        "stp x29, x30, [sp, #80]",
        "stp q8, q9, [sp, #96]",
        "stp q10, q11, [sp, #128]",
        "stp q12, q13, [sp, #160]",
        "stp q14, q15, [sp, #192]",
        "str x3, [sp, #224]",
        "mrs x9, fpcr",
        "str x9, [sp, #232]",
        "mrs x9, fpsr",
        "str x9, [sp, #240]",
        "mov x19, x3",
        "add x20, x3, #1",
        "add x29, x3, #2",
        "dup v0.2d, x3",
        "dup v8.2d, x3",
        "dup v15.2d, x3",
        "dup v31.2d, x3",
        "lsl x9, x3, #22",
        "msr fpcr, x9",
        "msr fpsr, x3",
        "lsl x9, x3, #28",
        "msr nzcv, x9",
        "bl {switch}",
        "mrs x11, nzcv",
        "ldr x10, [sp, #224]",
        "lsl x9, x10, #28",
        "cmp x11, x9",
        "b.ne 2f",
        "cmp x19, x10",
        "b.ne 2f",
        "add x9, x10, #1",
        "cmp x20, x9",
        "b.ne 2f",
        "add x9, x10, #2",
        "cmp x29, x9",
        "b.ne 2f",
        "umov x9, v0.d[0]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v0.d[1]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v8.d[0]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v8.d[1]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v15.d[0]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v15.d[1]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v31.d[0]",
        "cmp x9, x10",
        "b.ne 2f",
        "umov x9, v31.d[1]",
        "cmp x9, x10",
        "b.ne 2f",
        "mrs x9, fpsr",
        "cmp x9, x10",
        "b.ne 2f",
        "lsl x10, x10, #22",
        "mrs x9, fpcr",
        "cmp x9, x10",
        "b.ne 2f",
        "mov x0, #0",
        "b 3f",
        "2: mov x0, #1",
        "3:",
        "ldr x9, [sp, #232]",
        "msr fpcr, x9",
        "ldr x9, [sp, #240]",
        "msr fpsr, x9",
        "ldp x19, x20, [sp, #0]",
        "ldp x21, x22, [sp, #16]",
        "ldp x23, x24, [sp, #32]",
        "ldp x25, x26, [sp, #48]",
        "ldp x27, x28, [sp, #64]",
        "ldp x29, x30, [sp, #80]",
        "ldp q8, q9, [sp, #96]",
        "ldp q10, q11, [sp, #128]",
        "ldp q12, q13, [sp, #160]",
        "ldp q14, q15, [sp, #192]",
        "add sp, sp, #256",
        "ret",
        switch = sym switch_context,
    );
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "sysv64" fn sentinel_switch(
    _old: *mut Context,
    _new: *const Context,
    _marker: *mut u64,
    _seed: u64,
) -> u64 {
    core::arch::naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 24",
        "stmxcsr [rsp]",
        "mov [rsp + 8], rcx",
        "mov rbx, rcx",
        "lea r12, [rcx + 1]",
        "lea rbp, [rcx + 2]",
        "movq xmm0, rcx",
        "punpcklqdq xmm0, xmm0",
        "movdqa xmm7, xmm0",
        "movdqa xmm15, xmm0",
        "mov eax, ecx",
        "shl eax, 13",
        "or eax, 0x1f80",
        "mov [rsp + 16], eax",
        "ldmxcsr [rsp + 16]",
        "call {switch}",
        "mov rcx, [rsp + 8]",
        "cmp rbx, rcx",
        "jne 2f",
        "lea rax, [rcx + 1]",
        "cmp r12, rax",
        "jne 2f",
        "lea rax, [rcx + 2]",
        "cmp rbp, rax",
        "jne 2f",
        "movq rax, xmm0",
        "cmp rax, rcx",
        "jne 2f",
        "movhlps xmm1, xmm0",
        "movq rax, xmm1",
        "cmp rax, rcx",
        "jne 2f",
        "movq rax, xmm7",
        "cmp rax, rcx",
        "jne 2f",
        "movhlps xmm1, xmm7",
        "movq rax, xmm1",
        "cmp rax, rcx",
        "jne 2f",
        "movq rax, xmm15",
        "cmp rax, rcx",
        "jne 2f",
        "movhlps xmm1, xmm15",
        "movq rax, xmm1",
        "cmp rax, rcx",
        "jne 2f",
        "stmxcsr [rsp + 20]",
        "mov eax, [rsp + 16]",
        "cmp eax, [rsp + 20]",
        "jne 2f",
        "xor eax, eax",
        "jmp 3f",
        "2: mov eax, 1",
        "3:",
        "ldmxcsr [rsp]",
        "add rsp, 24",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
        switch = sym switch_context,
    );
}
