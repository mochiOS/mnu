//! x86_64 entry layouts and conversion to retained user register contexts.
//! SYSCALL clobbers RCX/R11; interrupt frames retain both original registers.
#[derive(Debug, Clone, Copy)]
pub struct SyscallUserContext {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rcx: u64,
    pub r11: u64,
}

impl SyscallUserContext {
    pub const fn empty() -> Self {
        Self {
            rip: 0,
            rsp: 0,
            rflags: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rcx: 0,
            r11: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserUpcallContext {
    pub user_rsp: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub user_rflags: u64,
    pub user_rip: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rax: u64,
    pub rcx: u64,
    pub r11: u64,
}

#[repr(C)]
pub struct SavedSyscallFrame {
    pub(crate) user_rsp: u64,
    pub(crate) r15: u64,
    pub(crate) r14: u64,
    pub(crate) r13: u64,
    pub(crate) r12: u64,
    pub(crate) rbx: u64,
    pub(crate) rbp: u64,
    pub(crate) user_rflags: u64,
    pub(crate) user_rip: u64,
    pub(crate) arg5: u64,
    pub(crate) arg4: u64,
    pub(crate) arg3: u64,
    pub(crate) arg2: u64,
    pub(crate) arg1: u64,
    pub(crate) arg0: u64,
    pub(crate) num: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneralRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IretFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C)]
pub struct InterruptFrame {
    pub gprs: GeneralRegisters,
    pub iret: IretFrame,
}
#[repr(C)]
pub struct PageFaultFrame {
    pub gprs: GeneralRegisters,
    pub error_code: u64,
    pub iret: IretFrame,
}
impl InterruptFrame {
    pub(crate) fn context(&self) -> UserUpcallContext {
        UserUpcallContext {
            user_rsp: self.iret.rsp,
            r15: self.gprs.r15,
            r14: self.gprs.r14,
            r13: self.gprs.r13,
            r12: self.gprs.r12,
            rbx: self.gprs.rbx,
            rbp: self.gprs.rbp,
            user_rflags: self.iret.rflags,
            user_rip: self.iret.rip,
            r9: self.gprs.r9,
            r8: self.gprs.r8,
            r10: self.gprs.r10,
            rdx: self.gprs.rdx,
            rsi: self.gprs.rsi,
            rdi: self.gprs.rdi,
            rax: self.gprs.rax,
            rcx: self.gprs.rcx,
            r11: self.gprs.r11,
        }
    }

    pub(crate) fn set_context(&mut self, context: UserUpcallContext) {
        self.iret.rsp = context.user_rsp;
        self.gprs.r15 = context.r15;
        self.gprs.r14 = context.r14;
        self.gprs.r13 = context.r13;
        self.gprs.r12 = context.r12;
        self.gprs.rbx = context.rbx;
        self.gprs.rbp = context.rbp;
        self.iret.rflags = context.user_rflags;
        self.iret.rip = context.user_rip;
        self.gprs.r9 = context.r9;
        self.gprs.r8 = context.r8;
        self.gprs.r10 = context.r10;
        self.gprs.rdx = context.rdx;
        self.gprs.rsi = context.rsi;
        self.gprs.rdi = context.rdi;
        self.gprs.rax = context.rax;
        self.gprs.rcx = context.rcx;
        self.gprs.r11 = context.r11;
    }
}
impl SavedSyscallFrame {
    pub(crate) fn context(&self) -> UserUpcallContext {
        UserUpcallContext {
            user_rsp: self.user_rsp,
            r15: self.r15,
            r14: self.r14,
            r13: self.r13,
            r12: self.r12,
            rbx: self.rbx,
            rbp: self.rbp,
            user_rflags: self.user_rflags,
            user_rip: self.user_rip,
            r9: self.arg5,
            r8: self.arg4,
            r10: self.arg3,
            rdx: self.arg2,
            rsi: self.arg1,
            rdi: self.arg0,
            rax: self.num,
            rcx: self.user_rip,
            r11: self.user_rflags,
        }
    }

    pub(crate) fn set_context(&mut self, context: UserUpcallContext) {
        self.user_rsp = context.user_rsp;
        self.r15 = context.r15;
        self.r14 = context.r14;
        self.r13 = context.r13;
        self.r12 = context.r12;
        self.rbx = context.rbx;
        self.rbp = context.rbp;
        self.user_rflags = context.user_rflags;
        self.user_rip = context.user_rip;
        self.arg5 = context.r9;
        self.arg4 = context.r8;
        self.arg3 = context.r10;
        self.arg2 = context.rdx;
        self.arg1 = context.rsi;
        self.arg0 = context.rdi;
        self.num = context.rax;
    }
}
impl UserUpcallContext {
    pub(crate) fn syscall_registers(&self) -> SyscallUserContext {
        SyscallUserContext {
            rip: self.user_rip,
            rsp: self.user_rsp,
            rflags: self.user_rflags,
            rdi: self.rdi,
            rsi: self.rsi,
            rdx: self.rdx,
            r8: self.r8,
            r9: self.r9,
            r10: self.r10,
            rbp: self.rbp,
            rbx: self.rbx,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            rcx: self.rcx,
            r11: self.r11,
        }
    }
}
const _: () = {
    assert!(core::mem::size_of::<SavedSyscallFrame>() == 16 * 8);
    assert!(core::mem::offset_of!(SavedSyscallFrame, user_rsp) == 0);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r15) == 8);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r14) == 16);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r13) == 24);
    assert!(core::mem::offset_of!(SavedSyscallFrame, r12) == 32);
    assert!(core::mem::offset_of!(SavedSyscallFrame, rbx) == 40);
    assert!(core::mem::offset_of!(SavedSyscallFrame, rbp) == 48);
    assert!(core::mem::offset_of!(SavedSyscallFrame, user_rflags) == 56);
    assert!(core::mem::offset_of!(SavedSyscallFrame, user_rip) == 64);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg5) == 72);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg4) == 80);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg3) == 88);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg2) == 96);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg1) == 104);
    assert!(core::mem::offset_of!(SavedSyscallFrame, arg0) == 112);
    assert!(core::mem::offset_of!(SavedSyscallFrame, num) == 120);
};

const _: () = {
    assert!(core::mem::offset_of!(GeneralRegisters, r15) == 0 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r14) == 1 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r13) == 2 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r12) == 3 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r11) == 4 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r10) == 5 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r9) == 6 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, r8) == 7 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rdi) == 8 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rsi) == 9 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rbp) == 10 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rbx) == 11 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rdx) == 12 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rcx) == 13 * 8);
    assert!(core::mem::offset_of!(GeneralRegisters, rax) == 14 * 8);
    assert!(core::mem::offset_of!(IretFrame, rip) == 0 * 8);
    assert!(core::mem::offset_of!(IretFrame, cs) == 1 * 8);
    assert!(core::mem::offset_of!(IretFrame, rflags) == 2 * 8);
    assert!(core::mem::offset_of!(IretFrame, rsp) == 3 * 8);
    assert!(core::mem::offset_of!(IretFrame, ss) == 4 * 8);
    assert!(core::mem::size_of::<InterruptFrame>() == 20 * 8);
    assert!(core::mem::offset_of!(InterruptFrame, iret) == 15 * 8);
    assert!(core::mem::size_of::<PageFaultFrame>() == 21 * 8);
    assert!(core::mem::offset_of!(PageFaultFrame, error_code) == 15 * 8);
    assert!(core::mem::offset_of!(PageFaultFrame, iret) == 16 * 8);
};
