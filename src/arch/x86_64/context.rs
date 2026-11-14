//! Kernel switch frame and x87/SSE state for the System V AMD64 ABI.
//! Scheduling, address-space selection and CPU ownership stay in task/.

const FXSAVE_AREA_SIZE: usize = 512;

#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub(crate) struct FxSaveArea {
    bytes: [u8; FXSAVE_AREA_SIZE],
}

impl FxSaveArea {
    pub(crate) const fn initial() -> Self {
        let mut bytes = [0u8; FXSAVE_AREA_SIZE];
        // Intel-defined reset state used by FNINIT and LDMXCSR.
        bytes[0] = 0x7f;
        bytes[1] = 0x03;
        bytes[24] = 0x80;
        bytes[25] = 0x1f;
        Self { bytes }
    }

    /// Capture the current thread's x87/SSE state before entering user code.
    pub(crate) fn save_current(&mut self) {
        unsafe {
            core::arch::asm!(
                "fxsave64 [{}]",
                in(reg) self as *mut Self,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Restore a kernel-owned snapshot. This state is never supplied by a
    /// user pointer, so invalid MXCSR bits cannot reach FXRSTOR through IPC.
    pub(crate) fn restore_current(&self) {
        unsafe {
            core::arch::asm!(
                "fxrstor64 [{}]",
                in(reg) self as *const Self,
                clobber_abi("C"),
                options(nostack, preserves_flags, readonly),
            );
        }
    }

    pub(crate) fn with_user_bytes(&self, bytes: [u8; FXSAVE_AREA_SIZE]) -> Option<Self> {
        // Use the CPU's captured mask, never a mask supplied by user space.
        let mask = u32::from_le_bytes(self.bytes[28..32].try_into().ok()?);
        let mask = if mask == 0 { 0xffbf } else { mask };
        let mxcsr = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
        if mxcsr & !mask != 0 {
            return None;
        }
        let mut state = Self { bytes };
        state.bytes[28..32].copy_from_slice(&mask.to_le_bytes());
        state.bytes = state.snapshot_bytes();
        Some(state)
    }

    pub(crate) fn snapshot_bytes(&self) -> [u8; FXSAVE_AREA_SIZE] {
        let mut bytes = self.bytes;
        // FXSAVE leaves reserved bytes untouched. Do not expose them even if
        // a future save-area initializer stops zeroing the entire buffer.
        bytes[5] = 0;
        for slot in 0..8 {
            bytes[32 + slot * 16 + 10..32 + slot * 16 + 16].fill(0);
        }
        bytes[416..].fill(0);
        bytes
    }
}

impl core::fmt::Debug for FxSaveArea {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FxSaveArea(..)")
    }
}

/// CPU コンテキスト（callee-saved とFPU/SIMD状態を保存）
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct Context {
    pub rsp: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64, // Initial entry argument retained by the switch frame
    pub rsi: u64, // Initial entry argument retained by the switch frame
    /// 命令ポインタ（戻り先アドレス）
    pub rip: u64,
    pub rflags: u64,
    fx_state: FxSaveArea,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Prepare a kernel entry using this architecture's stack and return ABI.
    ///
    /// # Safety
    /// `stack_top` must be 16-byte aligned with a writable return slot below it.
    /// The caller owns that stack exclusively until switching to this context.
    /// `entry` and `return_address` must be valid kernel code addresses.
    pub unsafe fn for_kernel_entry(
        entry: u64,
        stack_top: u64,
        return_address: u64,
        interrupts_enabled: bool,
    ) -> Self {
        let mut context = Self::new();
        context.rsp = stack_top - 8;
        context.rbp = stack_top;
        context.rip = entry;
        context.rflags = 0x2 | if interrupts_enabled { 0x200 } else { 0 };
        unsafe { (context.rsp as *mut u64).write(return_address) };
        context
    }

    pub fn stack_pointer(&self) -> u64 {
        self.rsp
    }

    pub fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    pub const fn new() -> Self {
        Self {
            rsp: 0,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rip: 0,
            rflags: 0,
            fx_state: FxSaveArea::initial(),
        }
    }
}

const _: () = assert!(core::mem::offset_of!(Context, fx_state) == 0x60);
const _: () = assert!(core::mem::align_of::<Context>() == 16);
const _: () = assert!(core::mem::size_of::<Context>() == 0x260);

/// 現在のスレッドから次のスレッドへコンテキストを切り替える
///
/// Context構造体のレイアウト:
/// offset 0x00: rsp
/// offset 0x08: rbp
/// offset 0x10: rbx
/// offset 0x18: r12
/// offset 0x20: r13
/// offset 0x28: r14
/// offset 0x30: r15
/// offset 0x38: rdi
/// offset 0x40: rsi
/// offset 0x48: rip
/// offset 0x50: rflags
/// offset 0x60: 16-byte aligned FXSAVE area (512 bytes)
///
/// # Safety
/// `old_context`/`new_context` は有効な `Context` 領域を指し、呼び出し規約に従って
/// コンテキスト切替可能な状態である必要がある。
/// `outgoing_marker` must point to this CPU's live, aligned AtomicU64 handoff
/// marker, published while holding the thread queue before incoming publication.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "sysv64" fn switch_context(
    old_context: *mut Context,
    new_context: *const Context,
    outgoing_marker: *mut u64,
) {
    core::arch::naked_asm!(
        "cli",
        // save current (ret address is at [rsp])
        "lea rax, [rsp + 0x08]",
        // system V AMD64 ABI (used by x86_64-unknown-none):
        // 第1引数 (old_context) = rdi
        // 第2引数 (new_context) = rsi
        "mov [rdi + 0x00], rax", // rsp
        "mov [rdi + 0x08], rbp", // rbp
        "mov [rdi + 0x10], rbx", // rbx
        "mov [rdi + 0x18], r12", // r12
        "mov [rdi + 0x20], r13", // r13
        "mov [rdi + 0x28], r14", // r14
        "mov [rdi + 0x30], r15", // r15
        "mov [rdi + 0x38], rdi", // rdi
        "mov [rdi + 0x40], rsi", // rsi
        // 戻り先アドレス（call命令でスタックにpushされている）を保存
        "mov rax, [rsp]",
        "mov [rdi + 0x48], rax", // rip
        // RFLAGSを保存
        "pushfq",
        "pop rax",
        "mov [rdi + 0x50], rax", // rflags
        // FXSAVE/FXRSTOR are required because user rendering code keeps live
        // floating-point and SIMD values across preemptive context switches.
        "fxsave64 [rdi + 0x60]",
        // 新しいコンテキストを復元
        "fxrstor64 [rsi + 0x60]",
        "mov rax, [rsi + 0x48]", // 新しいrip
        "mov r11, [rsi + 0x50]", // 新しいrflags
        "mov rbx, [rsi + 0x10]", // rbx
        "mov r12, [rsi + 0x18]", // r12
        "mov r13, [rsi + 0x20]", // r13
        "mov r14, [rsi + 0x28]", // r14
        "mov r15, [rsi + 0x30]", // r15
        "mov rdi, [rsi + 0x38]", // rdi
        "mov rbp, [rsi + 0x08]", // rbp
        "mov rsp, [rsi + 0x00]", // rsp (rsiを最後に使う)
        // RDX is the third SysV argument. The old context has been saved and
        // its stack is no longer in use. Publish completion only at this point.
        "xor ecx, ecx",
        "xchg [rdx], rcx",
        "mov rsi, [rsi + 0x40]", // rsi (rspセット後、rsiを上書きしてOK)
        // RFLAGSを復元
        "push r11",
        "popfq",
        "jmp rax",
    );
}
