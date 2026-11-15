//! Execute the actual userspace library's AAPCS64 assembly. These are CPU
//! continuation checks at EL1, not a claim that native fork/signal delivery runs.
use crate::{check, emit};
use core::{
    arch::{asm, naked_asm},
    ffi::c_void,
    ptr::addr_of_mut,
};
use mochios_posix_client::{signal_checkpoint, signal_context::*, signal_stack, snapshot};

#[repr(C, align(16))]
struct StackBytes([u8; 8192]);
static mut STACK: StackBytes = StackBytes([0; 8192]);
#[repr(C, align(4096))]
struct TlsBytes([u8; 8192]);
static mut TLS: TlsBytes = TlsBytes([0; 8192]);
static TLS_SOURCE: [u8; 3] = [0x21, 0x43, 0x65];

fn tls_variant_i() {
    use mochios_posix_client::static_tls::{dtv, modules::Plan, Template};
    let root = Template {
        source: TLS_SOURCE.as_ptr() as usize,
        file_size: 3,
        memory_size: 17,
        alignment: 32,
        residue: 3,
    };
    let templates = [
        Some(root),
        None,
        Some(Template {
            alignment: 128,
            residue: 7,
            ..root
        }),
    ];
    let plan = Plan::new(&templates, 4096).unwrap_or_else(|| crate::fail("TLS plan"));
    let base = addr_of_mut!(TLS) as usize;
    let size = plan.layout().mapping_size;
    check(size <= 8192, "TLS fixture bounds");
    let tp = plan
        .initialize_zeroed(
            base,
            size,
            |source, bytes| {
                // SAFETY: the templates refer to this immutable fixture array.
                bytes.copy_from_slice(unsafe {
                    core::slice::from_raw_parts(source as *const u8, bytes.len())
                });
                Ok::<(), ()>(())
            },
            |destination, bytes| {
                check(
                    destination >= base && destination + bytes.len() <= base + size,
                    "TLS write bounds",
                );
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        destination as *mut u8,
                        bytes.len(),
                    );
                }
                Ok::<(), ()>(())
            },
        )
        .unwrap_or_else(|_| crate::fail("TLS initialize"));
    check(tp & 127 == 0, "TLS maximum alignment");
    let mapping = unsafe { core::slice::from_raw_parts(base as *const u8, size) };
    let first =
        dtv::address(mapping, base, tp, 1, 0).unwrap_or_else(|| crate::fail("TLS root DTV"));
    let last =
        dtv::address(mapping, base, tp, 3, 0).unwrap_or_else(|| crate::fail("TLS dependency DTV"));
    // LLD 18 AArch64: TP + 16 + ((p_vaddr - 16) & (p_align - 1)).
    check(
        first == tp + 16 + ((3usize.wrapping_sub(16)) & 31),
        "TLS compiler TP offset",
    );
    check(
        last >= first + root.memory_size && last & 127 == 7,
        "TLS dependency placement",
    );
    check(
        dtv::address(mapping, base, tp, 2, 0).is_none(),
        "absent TLS module resolved",
    );
    check(
        dtv::address(mapping, base, tp, 1, 18).is_none(),
        "TLS module overflow",
    );
    check(
        &mapping[first - base..first - base + 3] == TLS_SOURCE.as_slice(),
        "TLS template data",
    );
    check(
        mapping[first - base + 3..first - base + 17]
            .iter()
            .all(|b| *b == 0),
        "TLS zero-fill",
    );
    emit("AArch64 Variant-I TLS layout PASS\n");
}

unsafe extern "C" fn checkpoint(machine: *mut MachineContext, argument: *mut c_void) {
    check(argument as usize == 0x123, "checkpoint argument");
    let machine = unsafe { &mut *machine };
    check(
        machine.gregs[19] == 0x1234,
        "checkpoint callee-saved capture",
    );
    check(machine.gregs[REG_SP] & 15 == 0, "checkpoint SP alignment");
    check(machine.gregs[REG_PC] != 0, "checkpoint return PC");
    let original = *machine;
    machine.gregs[REG_X0] = 0x55;
    machine.fpregs[..16].copy_from_slice(&0x42u128.to_le_bytes());
    machine.fpregs[496..].copy_from_slice(&0x43u128.to_le_bytes());
    machine.fpcr = 1 << 22;
    machine.fpsr = 2;
    check(
        machine.checked_return(&original).is_some(),
        "checkpoint validated state",
    );
    let mut invalid = *machine;
    invalid.gregs[REG_PSTATE] |= 1 << 7;
    check(
        invalid.checked_return(&original).is_none(),
        "checkpoint privileged flags",
    );
    // The checkpoint must restore its selected image after this real clobber.
    unsafe {
        asm!("movi v0.16b, #0xa5", "movi v31.16b, #0x5a", out("v0") _, out("v31") _, options(nostack));
    }
}

// Rust cannot observe deliberately selected caller-saved registers across a
// call. A naked AAPCS64 wrapper checks them before reentering a Rust frame.
#[unsafe(naked)]
unsafe extern "C" fn checkpoint_registers() -> u64 {
    naked_asm!(
        "stp x19, x30, [sp, #-32]!",
        "mrs x2, fpcr", "mrs x3, fpsr", "stp x2, x3, [sp, #16]",
        "mov x19, #0x1234", "adr x0, {callback}", "mov x1, #0x123",
        "bl {run}", "cmp x0, #0x55", "b.ne 2f",
        "mov x2, #0x1234", "cmp x19, x2", "b.ne 2f",
        "umov x2, v0.d[0]", "cmp x2, #0x42", "b.ne 2f",
        "umov x2, v31.d[0]", "cmp x2, #0x43", "b.ne 2f",
        "mrs x2, fpcr", "mov x3, #(1 << 22)", "cmp x2, x3", "b.ne 2f",
        "mrs x2, fpsr", "cmp x2, #2", "b.ne 2f",
        "mov x0, #0", "b 3f", "2: mov x0, #1",
        "3: ldp x2, x3, [sp, #16]", "msr fpcr, x2", "msr fpsr, x3",
        "ldp x19, x30, [sp], #32", "ret",
        callback = sym checkpoint,
        run = sym signal_checkpoint::run_with,
    );
}

unsafe extern "C" fn capture_backend() -> u64 {
    0x4321
}

// Exercise the recorded child trampoline while its caller frame is still
// live. This reuses the same address space; it does not simulate VM cloning.
#[unsafe(naked)]
unsafe extern "C" fn resume_recorded_continuation() -> u64 {
    naked_asm!(
        "ldr x16, [x0]",
        "ldr x17, [x0, #8]",
        "mov sp, x17",
        "br x16",
    );
}

unsafe extern "C" fn on_stack(argument: *mut c_void) {
    let bounds = unsafe { &mut *argument.cast::<[usize; 2]>() };
    let sp = signal_stack::current_pointer();
    check(
        sp >= bounds[0] && sp < bounds[1],
        "alternate stack not selected",
    );
    check(sp & 15 == 0, "alternate stack alignment");
    bounds[0] = 0;
}

pub fn run() {
    tls_variant_i();
    #[cfg(elf_relocation_probe)]
    elf::run();
    check(
        unsafe { checkpoint_registers() } == 0,
        "AAPCS64 checkpoint restore",
    );
    let mut context = Default::default();
    let result = unsafe { snapshot::capture_with(&mut context, 0xabc, capture_backend) };
    check(result == 0x4321, "snapshot backend result");
    check(context.thread_local_base == 0xabc, "snapshot opaque TLS");
    check(
        context.entry != 0 && context.stack_pointer & 15 == 0,
        "snapshot continuation",
    );
    check(
        context.flags == 0 && context.reserved == [0; 3],
        "snapshot reserved fields",
    );
    let previous = signal_stack::current_pointer();
    let result =
        unsafe { snapshot::capture_with(&mut context, 0xabc, resume_recorded_continuation) };
    check(result == 0, "recorded child continuation result");
    check(
        signal_stack::current_pointer() == previous,
        "recorded child stack restore",
    );
    let base = addr_of_mut!(STACK) as usize;
    let top = base + core::mem::size_of::<StackBytes>();
    let mut bounds = [base, top];
    let previous = signal_stack::current_pointer();
    unsafe {
        signal_stack::call_on(top, on_stack, (&mut bounds as *mut [usize; 2]).cast());
    }
    check(bounds[0] == 0, "alternate callback missing");
    check(
        signal_stack::current_pointer() == previous,
        "alternate stack not restored",
    );
    emit("AAPCS64 userspace continuations PASS\n");
}

#[cfg(elf_relocation_probe)]
#[path = "elf-context-probe.rs"]
mod elf;
