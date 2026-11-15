//! x86 SYSCALL and int 0x80 adapters to the shared native dispatcher.
use crate::syscall::{syscall_entry, upcall};

pub use crate::cpu::context::SavedSyscallFrame;

#[no_mangle]
pub extern "sysv64" fn prepare_thread_upcall_for_sysret(frame: *mut SavedSyscallFrame) {
    if let Some(frame) = unsafe { frame.as_mut() } {
        upcall::prepare_syscall_return(frame);
    }
}

/// fork/clone 用に、現在スレッドへユーザー復帰コンテキストを保存する
#[no_mangle]
pub extern "sysv64" fn save_user_context_for_fork(frame: *const SavedSyscallFrame) {
    if frame.is_null() {
        return;
    }
    let frame = unsafe { &*frame };
    if let Some(tid) = crate::task::current_thread_id() {
        let _ = crate::task::with_thread_mut(tid, |thread| {
            thread.set_syscall_user_context(frame.context().syscall_registers());
        });
    }
}

/// システムコール割り込みハンドラ (int 0x80) - アセンブリラッパー
///
/// # Safety
/// CPU が int 0x80 入口規約どおりのスタック/レジスタ状態でこの関数へ入ることを前提とする。
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_interrupt_handler() {
    core::arch::naked_asm!(
        // すべてのレジスタを保存（システムコール引数を含む）
        "push rax",      // syscall number
        "push rcx",
        "push rdx",      // arg2
        "push rbx",
        "push rbp",
        "push rsi",      // arg1
        "push rdi",      // arg0
        "push r8",       // arg4
        "push r9",
        "push r10",      // arg3
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // カーネルデータセグメントをロード
        // （ds/esはスタックに保存しない。復元時にユーザーセグメントを再設定）
        "mov ax, 0x10",    // カーネルデータセグメント (index=2)
        "mov ds, ax",
        "mov es, ax",

        // int 0x80 経路は、kernel CR3 に切り替えたまま dispatch と signal return を完結させる。
        // KPTI で user CR3 から kernel heap を完全に外しているため、signal 配送や
        // プロセス/スレッド metadata 参照を user CR3 上で行うと kernel-mode page fault になる。
        "mov rdi, rsp",               // arg0 = kstack（saved registers 先頭）
        "cld",
        "call {int80_handler}",       // 最終的な戻り値を rax で返す

        // 戻り値 (rax) をスタック上の保存された rax の位置に書き込む
        "mov [rsp + 112], rax",

        // ユーザーデータセグメントを設定
        "mov ax, 0x1b",    // ユーザーデータセグメント (index=3, RPL=3)
        "mov ds, ax",
        "mov es, ax",

        // すべてのレジスタを復元
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",

        // 割り込みから戻る
        "iretq",

        int80_handler = sym syscall_interrupt_handler_rust,
    );
}

/// int 0x80 経路専用の Rust wrapper。
///
/// KPTIでuser CR3から外したkernel heap/task metadataを参照するため、
/// dispatchをkernel CR3上で完結させる。
extern "sysv64" fn syscall_interrupt_handler_rust(kstack: *mut u64) -> u64 {
    crate::percpu::install_current_cpu_state();

    let prev_cr3 = syscall_entry::switch_to_kernel_page_table();
    crate::cpu::reassert_runtime_hardening();

    let frame = unsafe { &mut *kstack.cast::<crate::cpu::context::InterruptFrame>() };
    let syscall_num = frame.gprs.rax;

    let ret = crate::syscall::entry_dispatch::dispatch_from_user(
        syscall_num,
        [
            frame.gprs.rdi,
            frame.gprs.rsi,
            frame.gprs.rdx,
            frame.gprs.r10,
            frame.gprs.r8,
            frame.gprs.r9,
        ],
    );

    // The assembly owns 15 saved GPRs followed by the five-word user IRET
    // frame. Publish dispatch's result before upcall delivery/restoration.
    frame.gprs.rax = ret;
    upcall::prepare_interrupt_return(frame);
    let ret = frame.gprs.rax;

    // int 0x80 復帰フレームの CS/SS を GDT 実値で正規化する。
    // 一部環境で固定値と実際の GDT 割当がずれると iretq で #GP(index=3/4) を起こすため、
    // 毎回ここで明示的に揃える。
    let user_cs = (crate::mem::gdt::user_code_selector() as u64) | 0x3;
    let user_ss = (crate::mem::gdt::user_data_selector() as u64) | 0x3;
    frame.iret.cs = user_cs;
    frame.iret.ss = user_ss;
    syscall_entry::restore_page_table(prev_cr3);
    ret
}

/// x86 entry has selected the privileged root before common dispatch.
extern "C" fn syscall_handler_rust(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    crate::percpu::install_current_cpu_state();
    let _previous = syscall_entry::switch_to_kernel_page_table();
    crate::cpu::reassert_runtime_hardening();
    crate::syscall::entry_dispatch::dispatch_from_user(num, [arg0, arg1, arg2, arg3, arg4, arg5])
}

#[no_mangle]
pub extern "sysv64" fn syscall_user_cr3_for_sysret() -> u64 {
    syscall_entry::current_thread_user_page_table().unwrap_or(0)
}

/// SYSCALL 命令エントリから呼ばれる system V ABI ディスパッチ関数
///
/// syscall_entry.rs の naked asm から `call {dispatch}` で呼ばれる。
/// system V ABI: 引数は rdi, rsi, rdx, rcx, r8, r9 の順。
#[no_mangle]
pub extern "sysv64" fn syscall_dispatch_sysv(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    syscall_handler_rust(num, arg0, arg1, arg2, arg3, arg4, arg5)
}
