//! EL0 transition and memory protection using the production MMU and vectors.
//! A one-CPU diagnostic, not a replacement kernel or a Domain isolation test.
use crate::arch::exception::ExceptionFrame;
use crate::{arch, check, emit, exit, fail};
use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C, align(16))]
struct Stack([u8; 16384]);
#[unsafe(link_section = ".user.stack")]
static mut USER_STACK: Stack = Stack([0; 16384]);
static PHASE: AtomicU32 = AtomicU32::new(0);
static PRIVILEGED_TRAPS: AtomicU32 = AtomicU32::new(0);
static MEMORY_TRAPS: AtomicU32 = AtomicU32::new(0);
static CALLBACKS: AtomicU32 = AtomicU32::new(0);
static mut CALLBACK_RETURN: arch::exception::UserContext = arch::exception::UserContext::empty();
#[cfg(native_syscall_probe)]
static NATIVE_CALLS: AtomicU32 = AtomicU32::new(0);
static KERNEL_PRIVATE: u64 = 0xa5a5_1234_5678_ffff;

extern "C" {
    static probe_user_privileged: u8;
    static probe_user_forbidden_read: u8;
    static probe_user_forbidden_write: u8;
    static probe_user_begin: u8;
    static __stack_top: u8;
}

pub fn run() -> ! {
    emit("Entering EL0 CPU diagnostic\n");
    arch::interrupts::disable();
    let top = core::ptr::addr_of!(USER_STACK) as u64 + core::mem::size_of::<Stack>() as u64;
    // SAFETY: This fixture owns both stacks and maps only its dedicated user
    // code/stack as EL0-accessible. Domain separation is a separate mBoot test.
    unsafe { poison_and_enter(user_entry as *const () as u64, top, 0x99, 0x1234_5000) }
}

pub fn handle(frame: &mut ExceptionFrame) {
    check(
        frame.saved_state() & 0x1f == 0,
        "exception did not originate at EL0t",
    );
    let bottom = core::ptr::addr_of!(USER_STACK) as u64;
    let top = bottom + core::mem::size_of::<Stack>() as u64;
    check(
        frame.user_stack_pointer() >= bottom
            && frame.user_stack_pointer() <= top
            && frame.user_stack_pointer() & 15 == 0,
        "EL0 stack not retained",
    );
    let kernel_sp = arch::stack_pointer();
    check(
        kernel_sp < bottom || kernel_sp >= top,
        "trap used user stack",
    );

    let class = frame.syndrome() >> 26;
    if class == 0x24 {
        check(PHASE.load(Ordering::Acquire) == 1, "memory trap phase");
        check(
            frame.syndrome() & 0x3f == 0xf,
            "expected level-3 permission fault",
        );
        let pc = frame.instruction_pointer();
        if pc == core::ptr::addr_of!(probe_user_forbidden_read) as u64 {
            check(
                frame.fault_address() == core::ptr::addr_of!(KERNEL_PRIVATE) as u64,
                "kernel read FAR",
            );
            check(frame.syndrome() & (1 << 6) == 0, "expected read fault");
            check(
                MEMORY_TRAPS.fetch_add(1, Ordering::AcqRel) == 0,
                "kernel read fault order",
            );
        } else {
            check(
                pc == core::ptr::addr_of!(probe_user_forbidden_write) as u64,
                "unexpected data abort PC",
            );
            check(
                frame.fault_address() == core::ptr::addr_of!(probe_user_begin) as u64,
                "code write FAR",
            );
            check(frame.syndrome() & (1 << 6) != 0, "expected write fault");
            check(
                MEMORY_TRAPS.fetch_add(1, Ordering::AcqRel) == 1,
                "code write fault order",
            );
        }
        check(frame.advance_instruction(), "data abort return PC");
        return;
    }
    if class == 0x20 {
        check(PHASE.load(Ordering::Acquire) == 2, "execute fault phase");
        check(
            PRIVILEGED_TRAPS.load(Ordering::Acquire) == 1
                && MEMORY_TRAPS.load(Ordering::Acquire) == 2,
            "missing protection fault",
        );
        check(
            frame.syndrome() & 0x3f == 0xf,
            "expected level-3 execute permission fault",
        );
        check(
            frame.fault_address() == top - 16 && frame.instruction_pointer() == top - 16,
            "execute fault address",
        );
        check(frame.registers()[0] == 0, "EL0 register test failed");
        check(CALLBACKS.load(Ordering::Acquire) == 1, "EL0 callback not executed");
        emit("EL0 kernel isolation, read-only code and NX stack PASS\n");
        emit("Native EL0 continuation resume PASS\n");
        emit("EL0 SVC, privileged trap and register restoration PASS\n");
        emit("ARCH PRIMITIVES PASS aarch64\n");
        exit(0)
    }

    let privileged_pc = core::ptr::addr_of!(probe_user_privileged) as u64;
    if frame.instruction_pointer() == privileged_pc {
        check(PHASE.load(Ordering::Acquire) == 1, "privileged trap phase");
        check(
            matches!(frame.syndrome() >> 26, 0 | 0x18),
            "privileged instruction syndrome",
        );
        check(
            PRIVILEGED_TRAPS.fetch_add(1, Ordering::AcqRel) == 0,
            "repeated privileged trap",
        );
        check(
            frame.registers()[5] == 0x7654,
            "trapped instruction modified register",
        );
        check(frame.advance_instruction(), "privileged trap return PC");
        return;
    }

    check(frame.syndrome() >> 26 == 0x15, "expected AArch64 SVC");
    #[cfg(native_syscall_probe)]
    if frame.syndrome() & 0xffff == 0 {
        let number = frame.registers()[8];
        check(
            (0x7000..=0x7006).contains(&number),
            "native probe syscall number",
        );
        check(PHASE.load(Ordering::Acquire) == 1, "native syscall phase");
        let count = (number - 0x7000) as usize;
        check(
            NATIVE_CALLS.fetch_add(1, Ordering::AcqRel) as usize == count,
            "native syscall order",
        );
        let mut result = number;
        for index in 0..count {
            let argument = 0x11 * (index as u64 + 1);
            check(
                frame.registers()[index] == argument,
                "native syscall argument register",
            );
            result += argument;
        }
        frame.registers_mut()[0] = result;
        return;
    }
    match frame.syndrome() & 0xffff {
        0x51 => {
            check(frame.user_stack_pointer() == top, "initial EL0 stack");
            check(PHASE.swap(1, Ordering::AcqRel) == 0, "initial SVC phase");
            check(frame.registers()[0] == 0x99, "EL0 initial argument");
            check(
                frame.registers()[1..].iter().all(|value| *value == 0),
                "kernel GPR leaked into EL0",
            );
            check(
                frame.fp_registers().iter().all(|value| *value == 0),
                "kernel SIMD leaked into EL0",
            );
            check(
                frame.fp_control() == 0 && frame.fp_status() == 0,
                "kernel FP control leaked into EL0",
            );
            check(frame.saved_state() == 0, "kernel flags leaked into EL0");
            frame.registers_mut()[0] = 66;
            frame.registers_mut()[1] = core::ptr::addr_of!(KERNEL_PRIVATE) as u64;
        }
        0x52 => {
            #[cfg(native_syscall_probe)]
            {
                check(
                    NATIVE_CALLS.load(Ordering::Acquire) == 7,
                    "missing native syscall probe",
                );
                emit("Native syscall wrappers 0..6 PASS\n");
            }
            check(PHASE.swap(2, Ordering::AcqRel) == 1, "second SVC phase");
            check(
                PRIVILEGED_TRAPS.load(Ordering::Acquire) == 1,
                "EL0 privilege was not enforced",
            );
            check(
                MEMORY_TRAPS.load(Ordering::Acquire) == 2,
                "EL0 memory protection not enforced",
            );
            check(
                frame.registers()[0] == 0x42 && frame.registers()[8] == 55,
                "SVC argument registers",
            );
            check(frame.registers()[19] == 0x1234, "EL0 callee-saved register");
            let pattern = 0x42u128 | (0x42u128 << 64);
            check(
                frame.fp_registers()[0] == pattern && frame.fp_registers()[31] == pattern,
                "SVC SIMD capture",
            );
            check(
                frame.fp_control() == 1 << 22 && frame.fp_status() == 2,
                "SVC FP control capture",
            );
            let original = frame
                .user_context()
                .unwrap_or_else(|| fail("EL0 context absent"));
            check(original.valid(), "valid user context rejected");
            // Every privileged/reserved PSTATE bit is rejected atomically.
            for bit in (0..28).chain(32..64) {
                let mut invalid = original;
                invalid.pstate |= 1u64 << bit;
                invalid.registers[0] = 0xbad;
                check(
                    !frame.restore_user_context(&invalid),
                    "unsafe PSTATE accepted",
                );
                check(
                    frame.user_context() == Some(original),
                    "partial restore on rejection",
                );
            }
            for pc in [0, original.instruction_pointer | 1, 0xffff_8000_0000_0000] {
                let mut invalid = original;
                invalid.instruction_pointer = pc;
                check(
                    !frame.restore_user_context(&invalid),
                    "unsafe return PC accepted",
                );
            }
            for sp in [0, original.stack_pointer | 8, 0xffff_8000_0000_0000] {
                let mut invalid = original;
                invalid.stack_pointer = sp;
                check(
                    !frame.restore_user_context(&invalid),
                    "unsafe user SP accepted",
                );
            }
            let mut invalid = original;
            invalid.fpcr |= 1 << 63;
            check(
                !frame.restore_user_context(&invalid),
                "reserved FPCR accepted",
            );
            invalid = original;
            invalid.fpsr |= 1 << 63;
            check(
                !frame.restore_user_context(&invalid),
                "reserved FPSR accepted",
            );
            let mut selected = original;
            selected.registers[0] = 77;
            let mut fp = arch::fp::State::initial();
            // Clobber the live FP register before retaining the interrupted
            // user image. ARM must capture the exception frame, not Rust's FP.
            unsafe { asm!("movi v0.16b, #0xa5", out("v0") _, options(nostack)); }
            fp.capture(&original);
            let mut bytes = fp.snapshot_bytes();
            let mut bad = selected;
            bad.fpcr |= 1 << 63;
            check(fp.with_user_context(&bad, bytes).is_none(), "FP snapshot accepted reserved control");
            bytes[7 * 16..8 * 16].copy_from_slice(&0x4567u128.to_le_bytes());
            let fp = fp.with_user_context(&selected, bytes)
                .unwrap_or_else(|| fail("native FP snapshot rejected"));
            selected = fp.restore_context(selected);
            let image = arch::upcall::snapshot(selected, fp.snapshot_bytes());
            check(arch::upcall::decode(&image) == Some(selected), "native upcall snapshot round trip");
            let mut invalid = image;
            invalid.pstate |= 1 << 7;
            check(arch::upcall::decode(&invalid).is_none(), "snapshot accepted privileged PSTATE");
            invalid = image;
            invalid.fpcr |= 1 << 63;
            check(arch::upcall::decode(&invalid).is_none(), "snapshot accepted reserved FPCR");
            check(
                frame.restore_user_context(&selected),
                "EL0 context restore failed",
            );
            emit("Validated EL0 continuation PASS\n");
            let kernel_top = core::ptr::addr_of!(__stack_top) as u64;
            // SAFETY: The fixture owns the process mappings and retained
            // kernel stack. All failed calls must return before touching CPU
            // state; the final call abandons this handler and resumes EL0.
            unsafe {
                use arch::usermode::{resume_user, ResumeError};
                let mut invalid = selected;
                invalid.pstate |= 1 << 7;
                check(resume_user(&invalid, 77, 0x1234_5000, kernel_top)
                    == Err(ResumeError::InvalidContext), "resume accepted privileged state");
                check(resume_user(&selected, 77, u64::MAX, kernel_top)
                    == Err(ResumeError::InvalidTls), "resume accepted kernel TLS");
                check(resume_user(&selected, 77, 0x1234_5000, kernel_top - 8)
                    == Err(ResumeError::InvalidKernelStack), "resume accepted unaligned EL1 stack");
                asm!("movi v0.16b, #0xa5", "movi v31.16b, #0x5a",
                    out("v0") _, out("v31") _, options(nostack));
                core::ptr::addr_of_mut!(CALLBACK_RETURN).write(selected);
                let mut callback = selected;
                let stack = arch::upcall::callback_stack(top, true);
                let entry = callback_entry as *const () as u64;
                check(arch::upcall::valid_callback(entry, stack), "callback entry/stack rejected");
                check(arch::upcall::return_slot(stack).is_none()
                    && arch::upcall::exception_argument_slot(stack).is_none(), "ARM callback used stack arguments");
                arch::upcall::callback(&mut callback, entry, stack, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
                match resume_user(&callback, arch::upcall::result(&callback), 0x1234_5000, kernel_top) {
                    Ok(never) => match never {},
                    Err(_) => fail("validated native resume rejected"),
                }
            }
        }
        0x54 => {
            check(PHASE.load(Ordering::Acquire) == 2, "callback phase");
            check(frame.registers()[0] == 0, "native callback arguments/stack/LR");
            check(CALLBACKS.fetch_add(1, Ordering::AcqRel) == 0, "duplicate callback");
            emit("Native snapshot and EL0 callback C ABI PASS\n");
            // SAFETY: The fixture retained this complete kernel-owned image
            // before entering the callback; neither stack nor mappings changed.
            unsafe {
                let context = core::ptr::addr_of!(CALLBACK_RETURN).read();
                match arch::usermode::resume_user(&context, 77, 0x1234_5000, core::ptr::addr_of!(__stack_top) as u64) {
                    Ok(never) => match never {},
                    Err(_) => fail("callback continuation rejected"),
                }
            }
        }
        0x53 => fail("EL0 return register/TLS/FP mismatch"),
        _ => fail("unexpected SVC immediate"),
    }
    // The real vector must restore the saved user SIMD/control after kernel
    // code clobbers the live hardware registers, before it executes ERET.
    unsafe {
        asm!(
            "movi v0.16b, #0xa5", "movi v31.16b, #0x5a",
            "msr fpcr, {control}", "msr fpsr, {status}",
            control = in(reg) 3u64 << 22, status = in(reg) 1u64,
            out("v0") _, out("v31") _, options(nostack),
        );
    }
}

#[unsafe(naked)]
#[unsafe(link_section = ".user.text")]
unsafe extern "C" fn callback_entry(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> ! {
    naked_asm!(
        "cmp x0, #0x11", "b.ne 2f",
        "cmp x1, #0x22", "b.ne 2f",
        "cmp x2, #0x33", "b.ne 2f",
        "cmp x3, #0x44", "b.ne 2f",
        "cmp x4, #0x55", "b.ne 2f",
        "cmp x5, #0x66", "b.ne 2f",
        "cmp x6, #0x77", "b.ne 2f",
        "mov x7, sp", "and x7, x7, #15", "cbnz x7, 2f",
        "cbnz x30, 2f",
        "mov x0, #0", "svc #0x54", "b .",
        "2: mov x0, #1", "svc #0x54", "b .",
    );
}

// Seed every non-argument register before invoking the production EL0 entry.
#[unsafe(naked)]
unsafe extern "C" fn poison_and_enter(_entry: u64, _stack: u64, _arg: u64, _tls: u64) -> ! {
    naked_asm!(
        r#"
        .irp reg, 4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
        mov x\reg, #0xfeed
        .endr
        msr tpidrro_el0, x4
        .irp reg, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        movi v\reg\().16b, #0xa5
        .endr
        mov x4, #(3 << 22)
        msr fpcr, x4
        mov x4, #1
        msr fpsr, x4
        mov x4, #(15 << 28)
        msr nzcv, x4
        b {enter}
        "#,
        enter = sym arch::usermode::enter_user,
    );
}

#[unsafe(naked)]
#[unsafe(link_section = ".user.text")]
unsafe extern "C" fn user_entry() -> ! {
    naked_asm!(
        ".global probe_user_begin",
        "probe_user_begin:",
        "svc #0x51",
        "cmp x0, #66",
        "b.ne 2f",
        "mov x20, x1",
        ".if {native}",
        "bl probe_native_calls",
        "cbnz x0, 2f",
        ".endif",
        "mrs x7, tpidr_el0",
        "movz x9, #0x1234, lsl #16",
        "movk x9, #0x5000",
        "cmp x7, x9",
        "b.ne 2f",
        "mrs x7, tpidrro_el0",
        "cbnz x7, 2f",
        "mov x5, #0x7654",
        ".global probe_user_privileged",
        "probe_user_privileged:",
        "mrs x5, CurrentEL", // Must trap at EL0 without changing x5.
        "mov x6, #0x7654",
        "cmp x5, x6",
        "b.ne 2f",
        ".global probe_user_forbidden_read",
        "mov x1, x20",
        "probe_user_forbidden_read:",
        "ldr x6, [x1]", // Must fault: mapped kernel page has no EL0 permission.
        "adr x1, probe_user_begin",
        ".global probe_user_forbidden_write",
        "probe_user_forbidden_write:",
        "str wzr, [x1]", // Must fault: executable user code is read-only.
        "mov x19, #0x1234",
        "mov x0, #0x42",
        "dup v0.2d, x0",
        "dup v31.2d, x0",
        "mov x4, #(1 << 22)",
        "msr fpcr, x4",
        "mov x4, #2",
        "msr fpsr, x4",
        "mov x8, #55",
        "svc #0x52",
        "cmp x0, #77",
        "b.ne 2f",
        "mov x2, #0x1234",
        "cmp x19, x2",
        "b.ne 2f",
        "umov x1, v0.d[0]",
        "cmp x1, #0x42",
        "b.ne 2f",
        "umov x1, v0.d[1]",
        "cmp x1, #0x42",
        "b.ne 2f",
        "umov x1, v31.d[0]",
        "cmp x1, #0x42",
        "b.ne 2f",
        "umov x1, v31.d[1]",
        "cmp x1, #0x42",
        "b.ne 2f",
        "umov x1, v7.d[0]",
        "mov x2, #0x4567",
        "cmp x1, x2",
        "b.ne 2f",
        "mrs x1, fpcr",
        "mov x2, #(1 << 22)",
        "cmp x1, x2",
        "b.ne 2f",
        "mrs x1, fpsr",
        "cmp x1, #2",
        "b.ne 2f",
        "mov x0, #0",
        "mov x1, sp",
        "sub x1, x1, #16",
        "movz w2, #0x03c0",
        "movk w2, #0xd65f, lsl #16", // RET, if NX were incorrectly omitted.
        "str w2, [x1]",
        "br x1", // Must fault before executing the stack contents.
        "2: mov x0, #1",
        "svc #0x53",
        "b .",
        native = const cfg!(native_syscall_probe) as usize,
    );
}

// This optional path calls the real user crate, linked through --extern. Keep
// its code on the EL0 executable page; it cannot call fixture/kernel helpers.
#[cfg(native_syscall_probe)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".user.text")]
extern "C" fn probe_native_calls() -> u64 {
    unsafe {
        if mochi_user_syscall::syscall0(0x7000) != 0x7000 {
            return 1;
        }
        if mochi_user_syscall::syscall1(0x7001, 0x11) != 0x7012 {
            return 1;
        }
        if mochi_user_syscall::syscall2(0x7002, 0x11, 0x22) != 0x7035 {
            return 1;
        }
        if mochi_user_syscall::syscall3(0x7003, 0x11, 0x22, 0x33) != 0x7069 {
            return 1;
        }
        if mochi_user_syscall::syscall4(0x7004, 0x11, 0x22, 0x33, 0x44) != 0x70ae {
            return 1;
        }
        if mochi_user_syscall::syscall5(0x7005, 0x11, 0x22, 0x33, 0x44, 0x55) != 0x7104 {
            return 1;
        }
        if mochi_user_syscall::syscall6(0x7006, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66) != 0x716b {
            return 1;
        }
    }
    0
}
