//! TSS管理モジュール
//!
//! TSSを管理

use crate::info;
use spin::Once;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// ダブルフォルト用ISTインデックス
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const IST_STACK_SIZE: usize = 4096 * 16;
const RING0_STACK_SIZE: usize = 4096 * 32;

#[repr(align(16))]
struct IstStack {
    _bytes: [u8; IST_STACK_SIZE],
}

#[repr(align(16))]
struct Ring0Stack {
    _bytes: [u8; RING0_STACK_SIZE],
}

static TSS: [Once<TaskStateSegment>; crate::percpu::MAX_CPUS] =
    [const { Once::new() }; crate::percpu::MAX_CPUS];
static mut IST_STACKS: [IstStack; crate::percpu::MAX_CPUS] =
    [const { IstStack { _bytes: [0; IST_STACK_SIZE] } }; crate::percpu::MAX_CPUS];
static mut RING0_STACKS: [Ring0Stack; crate::percpu::MAX_CPUS] =
    [const { Ring0Stack { _bytes: [0; RING0_STACK_SIZE] } }; crate::percpu::MAX_CPUS];

/// TSSを初期化して返す
///
/// ## Returns
/// - 初期化されたTSSへの参照
#[allow(unused_unsafe)]
pub fn init() -> &'static TaskStateSegment {
    info!("Initializing TSS...");

    let cpu = crate::percpu::current_cpu_id();
    TSS[cpu].call_once(|| {
        let mut tss = TaskStateSegment::new();

        // ダブルフォルト用の専用スタックを設定
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const IST_STACKS[cpu] });
            let stack_end = stack_start + IST_STACK_SIZE as u64;
            info!(
                "  IST[{}] stack: {:#x}",
                DOUBLE_FAULT_IST_INDEX,
                stack_end.as_u64()
            );
            stack_end
        };

        // ユーザーモードからカーネルモードへの遷移用のRing0スタックを設定
        tss.privilege_stack_table[0] = {
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const RING0_STACKS[cpu] });
            let stack_end = stack_start + RING0_STACK_SIZE as u64;
            info!("  Ring0 stack (RSP0): {:#x}", stack_end.as_u64());
            stack_end
        };

        info!("TSS configured:");
        info!(
            "  IST[0] stack: {:#x}",
            tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize].as_u64()
        );
        info!(
            "  Ring0 stack (RSP0): {:#x}",
            tss.privilege_stack_table[0].as_u64()
        );
        tss
    })
}

/// Ring 0スタック (RSP0) を更新
///
/// コンテキストスイッチ時に呼び出し、次のスレッドのカーネルスタックを設定する
///
/// ## Arguments
/// - `rsp`: 新しいRSP0の値 (次のスレッドのカーネルスタックのアドレス)
pub fn set_rsp0(rsp: u64) {
    if let Some(tss) = TSS[crate::percpu::current_cpu_id()].get() {
        let virt = tss as *const TaskStateSegment as u64;
        let ptr = crate::mem::paging::translate_addr(VirtAddr::new(virt))
            .and_then(|phys| {
                crate::mem::paging::physical_memory_offset()
                    .and_then(|off| phys.as_u64().checked_add(off))
            })
            .map(|alias| alias as *mut TaskStateSegment)
            .unwrap_or(virt as *mut TaskStateSegment);
        unsafe {
            // RSP0更新中の割り込み/コンテキストスイッチを防ぐため、
            // 割り込みを一時的に無効化してアトミックに更新
            x86_64::instructions::interrupts::without_interrupts(|| {
                (*ptr).privilege_stack_table[0] = VirtAddr::new(rsp);
            });
        }
    }
}
