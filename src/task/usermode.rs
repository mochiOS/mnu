//! ユーザーモード実行サポート

use crate::mem::gdt;
use core::arch::asm;

const IA32_FS_BASE: u32 = 0xC000_0100;

#[repr(C)]
struct ForkRegisters {
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
    r10: u64,
}

/// ユーザーモードでコードを実行する
///
/// # 引数
/// - `entry`: ユーザーモードで実行する関数のアドレス
/// - `user_stack`: ユーザースタックのトップアドレス
///
/// # 注意
/// この関数は戻らない
///
/// # Safety
/// `entry` と `user_stack` はユーザー空間の有効な実行/スタックアドレスである必要がある。
pub unsafe fn jump_to_usermode(entry: u64, user_stack: u64, user_arg0: u64) -> ! {
    let user_cs = gdt::user_code_selector() as u64 | 3; // RPL=3
    let user_ss = gdt::user_data_selector() as u64 | 3; // RPL=3
    let (fs_base, user_cr3) = crate::task::current_thread_id()
        .and_then(|tid| {
            crate::task::with_thread(tid, |thread| {
                let pid = thread.process_id();
                let fs = thread.fs_base();
                let cr3 = crate::task::with_process(pid, |proc| proc.page_table().unwrap_or(0))
                    .unwrap_or(0);
                (fs, cr3)
            })
        })
        .unwrap_or((0, 0));

    // GDTエントリの内容を読み取って確認
    let cs_selector = gdt::user_code_selector();
    let ss_selector = gdt::user_data_selector();

    let gdtr = read_gdtr();
    let gdt_base = gdtr.0;

    // CSのGDTエントリを読み取る
    let cs_index = (cs_selector >> 3) as usize;
    let cs_entry_ptr = (gdt_base + (cs_index * 8) as u64) as *const u64;
    let cs_entry = core::ptr::read_volatile(cs_entry_ptr);
    let cs_dpl = (cs_entry >> 45) & 0b11;

    // SSのGDTエントリを読み取る
    let ss_index = (ss_selector >> 3) as usize;
    let ss_entry_ptr = (gdt_base + (ss_index * 8) as u64) as *const u64;
    let ss_entry = core::ptr::read_volatile(ss_entry_ptr);
    let ss_dpl = (ss_entry >> 45) & 0b11;

    crate::debug!("GDT Check:");
    crate::debug!(
        "  CS selector={:#x}, index={}, entry={:#018x}, DPL={}",
        cs_selector,
        cs_index,
        cs_entry,
        cs_dpl
    );
    crate::debug!(
        "  SS selector={:#x}, index={}, entry={:#018x}, DPL={}",
        ss_selector,
        ss_index,
        ss_entry,
        ss_dpl
    );
    crate::debug!(
        "  Final CS={:#x} (with RPL=3), SS={:#x} (with RPL=3)",
        user_cs,
        user_ss
    );

    crate::debug!(
        "Jumping to usermode: entry={:#x}, stack={:#x}, fs_base={:#x}",
        entry,
        user_stack,
        fs_base
    );

    crate::cpu::write_fs_base(fs_base);
    if user_cr3 != 0 {
        crate::mem::paging::switch_page_table(user_cr3);
    }

    // iretqスタックフレームを構築:
    // SS, RSP, RFLAGS, CS, RIP
    asm!(
        "cli",

        // データセグメントをユーザーセグメントに設定（iretq前）
        "mov ax, r8w",
        "mov ds, ax",
        "mov es, ax",

        // iretq用のスタックフレームをプッシュ
        "push r8",         // SS (ユーザーデータセグメント)
        "push r9",         // RSP (ユーザースタック)
        "pushfq",          // 現在のRFLAGSを保存
        "pop r11",
        "or r11, 0x200",   // IF (Interrupt Flag) を設定
        "push r11",        // RFLAGS
        "push r10",        // CS (ユーザーコードセグメント)
        "push r12",        // RIP (エントリーポイント)
        "mov rdi, {arg0}", // 最初の引数を user rdi に載せる

        // iretqでユーザーモードへジャンプ
        "iretq",

        in("r8") user_ss,
        in("r9") user_stack,
        in("r10") user_cs,
        in("r12") entry,
        arg0 = in(reg) user_arg0,
        options(noreturn)
    )
}

/// GDTRを読み取る
fn read_gdtr() -> (u64, u16) {
    let mut gdtr: [u8; 10] = [0; 10];
    unsafe {
        asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
    }
    let limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);
    let base = u64::from_le_bytes([
        gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9],
    ]);
    (base, limit)
}

/// fork の子プロセスとしてユーザーモードへジャンプする
///
/// iretq フレームを構築し、RAX=0 (fork の子側戻り値) でユーザーに復帰する
///
/// # Safety
/// `context` と `fs_base` は子プロセスの有効な復帰コンテキストである必要がある。
pub unsafe fn jump_to_usermode_fork_child(
    context: crate::task::thread::SyscallUserContext,
    fs_base: u64,
) -> ! {
    let user_cs = gdt::user_code_selector() as u64 | 3;
    let user_ss = gdt::user_data_selector() as u64 | 3;
    let user_cr3 = crate::task::current_thread_id()
        .and_then(|tid| crate::task::with_thread(tid, |thread| thread.process_id()))
        .and_then(|pid| crate::task::with_process(pid, |proc| proc.page_table().unwrap_or(0)))
        .unwrap_or(0);
    let fs_lo = fs_base as u32;
    let fs_hi = (fs_base >> 32) as u32;
    let registers = ForkRegisters {
        rbx: context.rbx,
        rbp: context.rbp,
        r12: context.r12,
        r13: context.r13,
        r14: context.r14,
        r15: context.r15,
        rdi: context.rdi,
        rsi: context.rsi,
        rdx: context.rdx,
        r8: context.r8,
        r9: context.r9,
        r10: context.r10,
    };
    if user_cr3 != 0 {
        crate::mem::paging::switch_page_table(user_cr3);
    }
    asm!(
        "cli",
        // FS ベースを IA32_FS_BASE MSR 経由で設定。
        // ECX を明示入力にしないと、復帰先 RIP operand が RCX に割り当てられた場合に
        // 0xC0000100 へ iretq してしまう。
        "wrmsr",
        // データセグメントをユーザーセグメントに設定
        "mov ax, r8w",
        "mov ds, ax",
        "mov es, ax",
        // iretq フレームを構築: SS, RSP, RFLAGS, CS, RIP
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rdi",
        // syscallが保持するレジスタを親の入口時点へ戻す。RAXだけは子の戻り値0にする。
        "mov rax, rsi",
        "mov rbx, [rax + {rbx_offset}]",
        "mov rbp, [rax + {rbp_offset}]",
        "mov r12, [rax + {r12_offset}]",
        "mov r13, [rax + {r13_offset}]",
        "mov r14, [rax + {r14_offset}]",
        "mov r15, [rax + {r15_offset}]",
        "mov rdi, [rax + {rdi_offset}]",
        "mov rdx, [rax + {rdx_offset}]",
        "mov r8,  [rax + {r8_offset}]",
        "mov r9,  [rax + {r9_offset}]",
        "mov r10, [rax + {r10_offset}]",
        "mov rsi, [rax + {rsi_offset}]",
        // fork 子プロセスは rax=0 を返す
        "xor eax, eax",
        "iretq",
        in("r8") user_ss,
        in("r9") context.rsp,
        in("r10") (context.rflags | 0x200),
        in("r11") user_cs,
        in("rdi") context.rip,
        in("rsi") (&registers as *const ForkRegisters),
        in("ecx") IA32_FS_BASE,
        in("eax") fs_lo,
        in("edx") fs_hi,
        rbx_offset = const core::mem::offset_of!(ForkRegisters, rbx),
        rbp_offset = const core::mem::offset_of!(ForkRegisters, rbp),
        r12_offset = const core::mem::offset_of!(ForkRegisters, r12),
        r13_offset = const core::mem::offset_of!(ForkRegisters, r13),
        r14_offset = const core::mem::offset_of!(ForkRegisters, r14),
        r15_offset = const core::mem::offset_of!(ForkRegisters, r15),
        rdi_offset = const core::mem::offset_of!(ForkRegisters, rdi),
        rsi_offset = const core::mem::offset_of!(ForkRegisters, rsi),
        rdx_offset = const core::mem::offset_of!(ForkRegisters, rdx),
        r8_offset = const core::mem::offset_of!(ForkRegisters, r8),
        r9_offset = const core::mem::offset_of!(ForkRegisters, r9),
        r10_offset = const core::mem::offset_of!(ForkRegisters, r10),
        options(noreturn)
    )
}
