//! Full-register page-fault entry. The CPU error word is kept separate from
//! the 15 saved GPRs and five-word IRET frame; no user pointer is dereferenced.

#[unsafe(naked)]
pub(super) unsafe extern "C" fn entry() {
    core::arch::naked_asm!(
        "push rax", "push rcx", "push rdx", "push rbx", "push rbp",
        "push rsi", "push rdi", "push r8", "push r9", "push r10",
        "push r11", "push r12", "push r13", "push r14", "push r15",
        "mov rdi, rsp",
        "mov rbx, rsp",
        "and rsp, -16",
        "cld",
        "call {handle}",
        "mov rsp, rbx",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop r11",
        "pop r10", "pop r9", "pop r8", "pop rdi", "pop rsi",
        "pop rbp", "pop rbx", "pop rdx", "pop rcx", "pop rax",
        "add rsp, 8", // CPU error word, not part of IRET's frame.
        "iretq",
        handle = sym handle,
    );
}

extern "sysv64" fn handle(raw: *mut [u64; 21]) {
    // This pointer comes only from the assembly entry's current kernel stack.
    let raw = unsafe { &mut *raw };
    let entered = crate::syscall::syscall_entry::kpti_enter_for_trap(raw[17] & 3 == 3);
    let stack = x86_64::structures::idt::InterruptStackFrame::new(
        x86_64::VirtAddr::new_truncate(raw[16]),
        x86_64::structures::gdt::SegmentSelector(raw[17] as u16),
        x86_64::registers::rflags::RFlags::from_bits_truncate(raw[18]),
        x86_64::VirtAddr::new_truncate(raw[19]),
        x86_64::structures::gdt::SegmentSelector(raw[20] as u16),
    );
    let error = x86_64::structures::idt::PageFaultErrorCode::from_bits_truncate(raw[15]);
    super::idt::page_fault_handler(stack, error, raw, entered);
}
