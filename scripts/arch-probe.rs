//! Privileged CPU diagnostic using the production arch module directly.
//! Its UART, GIC and boot setup belong only to this QEMU fixture, not mnu.
#![no_std]
#![no_main]

#[path = "../src/arch/mod.rs"]
mod arch;

#[path = "context-probe.rs"]
mod context_probe;

#[cfg(target_arch = "aarch64")]
#[path = "user-probe.rs"]
mod user_probe;

#[cfg(target_arch = "aarch64")]
#[path = "mmu-probe.rs"]
mod mmu_probe;

use core::arch::asm;

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    // Fixed virt-8.2 / GICv2 / one-CPU reference machine, not board discovery.
    const GICD: usize = 0x0800_0000;
    const GICC: usize = 0x0801_0000;
    const TIMER_IRQ: u32 = 27;
    static INTERRUPTS: AtomicU32 = AtomicU32::new(0);
    static UNEXPECTED: AtomicU32 = AtomicU32::new(0);
    static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

    core::arch::global_asm!(
        r#"
        .section .text.entry, "ax"
        .global _start
    _start:
        ldr x0, =__stack_top
        mov sp, x0
        ldr x1, =__bss_start
        ldr x2, =__bss_end
    1:
        cmp x1, x2
        b.hs 2f
        str xzr, [x1], #8
        b 1b
    2:
        mrs x1, CurrentEL
        cmp x1, #8
        b.ne 3f
        mov x1, #(1 << 31)
        msr hcr_el2, x1
        mov x1, #3
        msr cnthctl_el2, x1
        msr cntvoff_el2, xzr
        msr sp_el1, x0
        adr x1, 3f
        msr elr_el2, x1
        mov x1, #0x3c5
        msr spsr_el2, x1
        isb
        eret
    3:
        msr daifset, #15
        mov x0, #(3 << 20)
        msr cpacr_el1, x0
        isb
        bl probe_main
        b .
        "#
    );

    pub fn daif() -> u64 {
        let value;
        unsafe {
            asm!("mrs {}, daif", out(reg) value, options(nomem, nostack));
        }
        value
    }

    pub fn initialize() {
        let level: u64;
        unsafe {
            asm!("mrs {}, CurrentEL", out(reg) level, options(nomem, nostack));
            check(level == 4, "probe must run at EL1");
            arch::exception::install_vectors();
            crate::mmu_probe::initialize();
            core::ptr::write_volatile((GICD + 0x100) as *mut u32, 1 << TIMER_IRQ);
            core::ptr::write_volatile(GICD as *mut u32, 1);
            core::ptr::write_volatile((GICC + 4) as *mut u32, 0xff);
            core::ptr::write_volatile(GICC as *mut u32, 1);
            asm!("dsb sy", "isb", options(nostack));
        }
    }

    fn arm_timer() {
        let frequency: u64;
        let now: u64;
        unsafe {
            asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack));
            asm!("mrs {}, cntvct_el0", out(reg) now, options(nomem, nostack));
        }
        check(frequency >= 100, "timer frequency");
        unsafe {
            asm!("msr cntv_cval_el0, {}", in(reg) now + frequency / 100, options(nostack));
            asm!("msr cntv_ctl_el0, {}", "isb", in(reg) 1u64, options(nostack));
        }
    }

    pub fn check_wait() {
        emit("ARM masked timer wake\n");
        arch::interrupts::disable();
        arm_timer();
        arch::wait_for_interrupt();
        check(
            INTERRUPTS.load(Ordering::Acquire) == 0,
            "masked IRQ delivered",
        );
        check(!arch::interrupts::are_enabled(), "WFI changed IRQ mask");
        arch::interrupts::enable();
        while INTERRUPTS.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop();
        }
        emit("ARM unmasked timer wake\n");
        arm_timer();
        while INTERRUPTS.load(Ordering::Acquire) < 2 {
            arch::wait_for_interrupt();
        }
        check(UNEXPECTED.load(Ordering::Acquire) == 0, "unexpected IRQ");
        check(arch::interrupts::are_enabled(), "IRQ return changed mask");
    }

    fn probe_irq() {
        unsafe {
            let acknowledgement = core::ptr::read_volatile((GICC + 0x0c) as *const u32);
            let interrupt = acknowledgement & 0x3ff;
            asm!("msr cntv_ctl_el0, {}", "isb", in(reg) 0u64, options(nostack));
            if interrupt != TIMER_IRQ {
                UNEXPECTED.store(interrupt + 1, Ordering::Release);
            }
            if interrupt < 1020 {
                core::ptr::write_volatile((GICC + 0x10) as *mut u32, acknowledgement);
                asm!("dsb sy", options(nostack));
            }
            INTERRUPTS.fetch_add(1, Ordering::Release);
        }
    }

    pub fn check_exceptions() {
        unsafe {
            asm!("brk #0x112", options(nostack));
        }
        check(
            BREAKPOINTS.load(Ordering::Acquire) == 2,
            "nested BRK return",
        );
        emit("EL1 exception vectors PASS\n");
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn mnu_aarch64_exception_dispatch(
        raw: *mut arch::exception::ExceptionFrame,
    ) -> u64 {
        use arch::exception::{ExceptionKind, ExceptionOrigin};
        // SAFETY: Only the production vector entry calls this symbol, after
        // saving the complete frame on the current CPU's kernel stack.
        let frame = unsafe { &mut *raw };
        if frame.origin() == Some(ExceptionOrigin::LowerAArch64)
            && frame.kind() == Some(ExceptionKind::Synchronous)
        {
            crate::user_probe::handle(frame);
            return 0;
        }
        check(
            frame.origin() == Some(ExceptionOrigin::CurrentSpx),
            "unexpected exception origin",
        );
        match frame.kind() {
            Some(ExceptionKind::Irq) => probe_irq(),
            Some(ExceptionKind::Synchronous) if frame.syndrome() >> 26 == 0x3c => {
                let immediate = frame.syndrome() & 0xffff;
                check(immediate == 0x112 || immediate == 0x223, "unexpected BRK");
                BREAKPOINTS.fetch_add(1, Ordering::Release);
                if immediate == 0x112 {
                    unsafe {
                        asm!("brk #0x223", options(nostack));
                    }
                }
                check(frame.advance_instruction(), "invalid BRK return PC");
            }
            _ => fail("unexpected exception"),
        }
        0
    }
}

fn emit(message: &str) {
    for byte in message.bytes() {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            while core::ptr::read_volatile(0x0900_0018 as *const u32) & (1 << 5) != 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(0x0900_0000 as *mut u32, u32::from(byte));
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let mut status: u8;
            loop {
                asm!("in al, dx", in("dx") 0x3fdu16, out("al") status, options(nomem, nostack));
                if status & 0x20 != 0 {
                    break;
                }
            }
            asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte, options(nomem, nostack));
        }
    }
}

fn exit(code: u64) -> ! {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let arguments = [0x20026u64, code];
        asm!("hlt #0xf000", in("x0") 0x20u64, in("x1") arguments.as_ptr(), options(nostack));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("out dx, eax", in("dx") 0xf4u16, in("eax") if code == 0 {0x10u32} else {0x11u32}, options(nomem, nostack));
    }
    arch::halt()
}

fn fail(message: &str) -> ! {
    arch::interrupts::disable();
    emit("ARCH PRIMITIVES FAIL: ");
    emit(message);
    emit("\n");
    exit(1)
}

fn check(condition: bool, message: &str) {
    if !condition {
        fail(message);
    }
}

#[unsafe(no_mangle)]
extern "C" fn probe_main() -> ! {
    #[cfg(target_arch = "aarch64")]
    arm::initialize();
    emit("CPU primitives entered\n");
    check(arch::stack_pointer() & 15 == 0, "unaligned stack");
    arch::interrupts::disable();
    #[cfg(target_arch = "aarch64")]
    let unrelated_masks = arm::daif() & !128;
    check(!arch::interrupts::are_enabled(), "disable");
    arch::interrupts::without_interrupts(|| {
        check(!arch::interrupts::are_enabled(), "masked nesting");
    });
    check(
        !arch::interrupts::are_enabled(),
        "masked entry restored incorrectly",
    );
    arch::interrupts::enable();
    check(arch::interrupts::are_enabled(), "enable");
    let result = arch::interrupts::without_interrupts(|| {
        check(!arch::interrupts::are_enabled(), "outer critical section");
        let value = arch::interrupts::without_interrupts(|| {
            check(!arch::interrupts::are_enabled(), "inner critical section");
            42
        });
        check(
            !arch::interrupts::are_enabled(),
            "inner enabled outer section",
        );
        value
    });
    check(
        result == 42 && arch::interrupts::are_enabled(),
        "outer IRQ restoration",
    );
    #[cfg(target_arch = "aarch64")]
    {
        check(
            arm::daif() & !128 == unrelated_masks,
            "non-IRQ DAIF mask changed",
        );
        arm::check_wait();
        arm::check_exceptions();
    }
    context_probe::run();
    #[cfg(target_arch = "aarch64")]
    {
        user_probe::run()
    }
    #[cfg(target_arch = "x86_64")]
    {
        emit("ARCH PRIMITIVES PASS x86_64\n");
        exit(0)
    }
}

#[cfg(target_arch = "x86_64")]
#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(_: usize, _: usize) -> usize {
    probe_main()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail("Rust panic")
}
