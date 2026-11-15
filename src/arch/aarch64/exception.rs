//! EL1 exception mechanics. The kernel supplies `mnu_aarch64_exception_dispatch`
//! to decide IRQ delivery, faults and syscalls; no device or service policy lives
//! here. FP/SIMD must be enabled and SVE/SME disabled before installing vectors.

use core::arch::{asm, global_asm};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionKind {
    Synchronous,
    Irq,
    Fiq,
    SError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionOrigin {
    CurrentSp0,
    CurrentSpx,
    LowerAArch64,
    LowerAArch32,
}

/// Base AArch64 EL0 state accepted for an explicit continuation restore.
/// TLS and execution authority are deliberately outside this register image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserContext {
    pub registers: [u64; 31],
    pub stack_pointer: u64,
    pub instruction_pointer: u64,
    pub pstate: u64,
    pub fpcr: u64,
    pub fpsr: u64,
    pub simd: [u128; 32],
}

impl UserContext {
    pub fn valid(&self) -> bool {
        const USER_END: u64 = 0x0000_7fff_ffff_ffff;
        const NZCV: u64 = 15 << 28;
        // Base Armv8 FP/SIMD. Newer optional FP control bits must not be
        // accepted before CPU feature negotiation and context support exist.
        const FPCR: u64 = (31 << 22) | (1 << 15) | (31 << 8);
        const FPSR: u64 = (1 << 27) | (1 << 7) | 31;
        self.instruction_pointer != 0
            && self.instruction_pointer <= USER_END
            && self.instruction_pointer & 3 == 0
            && self.stack_pointer >= 16
            && self.stack_pointer <= USER_END
            && self.stack_pointer & 15 == 0
            && self.pstate & !NZCV == 0
            && self.fpcr & !FPCR == 0
            && self.fpsr & !FPSR == 0
    }
}

/// Kernel-owned hardware frame. Return privilege and vector metadata are not
/// mutable through this interface. Register changes still require the kernel's
/// usual syscall/upcall validation before accepting any user-supplied state.
#[repr(C, align(16))]
pub struct ExceptionFrame {
    registers: [u64; 31],
    user_sp: u64,
    pc: u64,
    pstate: u64,
    esr: u64,
    far: u64,
    fpcr: u64,
    fpsr: u64,
    simd: [u128; 32],
    origin: u64,
    kind: u64,
}

impl ExceptionFrame {
    pub fn user_context(&self) -> Option<UserContext> {
        if self.origin() != Some(ExceptionOrigin::LowerAArch64) || !self.valid_return_mode() {
            return None;
        }
        Some(UserContext {
            registers: self.registers,
            stack_pointer: self.user_sp,
            instruction_pointer: self.pc,
            pstate: self.pstate,
            fpcr: self.fpcr,
            fpsr: self.fpsr,
            simd: self.simd,
        })
    }

    /// Validate the complete CPU image before changing any saved register.
    /// The VM layer separately retains the address space and validates its
    /// required code/stack mappings. A user image cannot replace an EL1 frame,
    /// select a privileged mode, mask interrupts, alter TLS or vector metadata.
    pub fn restore_user_context(&mut self, context: &UserContext) -> bool {
        if self.origin() != Some(ExceptionOrigin::LowerAArch64)
            || !self.valid_return_mode()
            || !context.valid()
        {
            return false;
        }
        self.registers = context.registers;
        self.user_sp = context.stack_pointer;
        self.pc = context.instruction_pointer;
        self.pstate = context.pstate;
        self.fpcr = context.fpcr;
        self.fpsr = context.fpsr;
        self.simd = context.simd;
        true
    }

    pub fn registers(&self) -> &[u64; 31] {
        &self.registers
    }

    pub fn registers_mut(&mut self) -> &mut [u64; 31] {
        &mut self.registers
    }

    pub fn user_stack_pointer(&self) -> u64 {
        self.user_sp
    }

    pub fn instruction_pointer(&self) -> u64 {
        self.pc
    }

    pub fn saved_state(&self) -> u64 {
        self.pstate
    }

    /// ESR is meaningful according to the exception kind, not for every IRQ.
    pub fn syndrome(&self) -> u64 {
        self.esr
    }

    /// FAR is meaningful only for exception classes that define it.
    pub fn fault_address(&self) -> u64 {
        self.far
    }

    pub fn fp_registers(&self) -> &[u128; 32] {
        &self.simd
    }

    pub fn fp_control(&self) -> u64 {
        self.fpcr
    }

    pub fn fp_status(&self) -> u64 {
        self.fpsr
    }

    pub fn kind(&self) -> Option<ExceptionKind> {
        match self.kind {
            0 => Some(ExceptionKind::Synchronous),
            1 => Some(ExceptionKind::Irq),
            2 => Some(ExceptionKind::Fiq),
            3 => Some(ExceptionKind::SError),
            _ => None,
        }
    }

    pub fn origin(&self) -> Option<ExceptionOrigin> {
        match self.origin {
            0 => Some(ExceptionOrigin::CurrentSp0),
            1 => Some(ExceptionOrigin::CurrentSpx),
            2 => Some(ExceptionOrigin::LowerAArch64),
            3 => Some(ExceptionOrigin::LowerAArch32),
            _ => None,
        }
    }

    /// Skip a handled A64 trapping instruction (for example BRK). SVC already
    /// records the following PC, so syscall handlers must not advance it again.
    pub fn advance_instruction(&mut self) -> bool {
        let Some(next) = self.pc.checked_add(4).filter(|pc| pc & 3 == 0) else {
            return false;
        };
        self.pc = next;
        true
    }

    fn valid_return_mode(&self) -> bool {
        // Include nRW (bit 4), rejecting AArch32 and unsupported stack modes.
        match self.origin() {
            Some(ExceptionOrigin::CurrentSpx) => self.pstate & 0x1f == 5,
            Some(ExceptionOrigin::LowerAArch64) => self.pstate & 0x1f == 0,
            _ => false,
        }
    }
}

extern "C" {
    static mnu_aarch64_vectors: [u8; 2048];

    /// Return zero to resume, any other value to halt this CPU. Implemented by
    /// the kernel's exception policy, not by the architecture mechanism.
    fn mnu_aarch64_exception_dispatch(frame: *mut ExceptionFrame) -> u64;
}

/// Install the shared read-only vector table on the current CPU.
///
/// # Safety
/// Must run at EL1h with exceptions masked, a valid aligned kernel stack and
/// FP/SIMD enabled. The dispatch symbol must be linked to a kernel handler.
/// CPU-local state and memory mappings must already support that handler.
pub unsafe fn install_vectors() {
    let address = core::ptr::addr_of!(mnu_aarch64_vectors) as u64;
    unsafe {
        asm!("msr vbar_el1, {}", "isb", in(reg) address, options(nostack));
    }
}

// The only caller is the vector entry with a complete, aligned kernel frame.
#[unsafe(no_mangle)]
unsafe extern "C" fn mnu_aarch64_exception_entry(frame: *mut ExceptionFrame) -> u64 {
    let action = unsafe { mnu_aarch64_exception_dispatch(frame) };
    if action == 0 && unsafe { &*frame }.valid_return_mode() {
        0
    } else {
        1
    }
}

global_asm!(
    include_str!("exception.S"),
    frame_size = const core::mem::size_of::<ExceptionFrame>(),
    user_sp = const core::mem::offset_of!(ExceptionFrame, user_sp),
    pc = const core::mem::offset_of!(ExceptionFrame, pc),
    esr = const core::mem::offset_of!(ExceptionFrame, esr),
    fpcr = const core::mem::offset_of!(ExceptionFrame, fpcr),
    simd = const core::mem::offset_of!(ExceptionFrame, simd),
    origin = const core::mem::offset_of!(ExceptionFrame, origin),
    kind = const core::mem::offset_of!(ExceptionFrame, kind),
);

const _: () = {
    assert!(core::mem::offset_of!(ExceptionFrame, registers) == 0);
    assert!(core::mem::offset_of!(ExceptionFrame, user_sp) == 248);
    assert!(core::mem::offset_of!(ExceptionFrame, pc) == 256);
    assert!(core::mem::offset_of!(ExceptionFrame, pstate) == 264);
    assert!(core::mem::offset_of!(ExceptionFrame, far) == 280);
    assert!(core::mem::offset_of!(ExceptionFrame, fpsr) == 296);
    assert!(core::mem::offset_of!(ExceptionFrame, simd) == 304);
    assert!(core::mem::size_of::<ExceptionFrame>() == 832);
    assert!(core::mem::align_of::<ExceptionFrame>() == 16);
};
