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

#[derive(Clone, Copy)]
struct CpuStacks {
    ist_start: u64,
    ring0_start: u64,
}

static TSS: [Once<TaskStateSegment>; crate::percpu::MAX_CPUS] =
    [const { Once::new() }; crate::percpu::MAX_CPUS];
static CPU_STACKS: [Once<CpuStacks>; crate::percpu::MAX_CPUS] =
    [const { Once::new() }; crate::percpu::MAX_CPUS];
static mut BSP_IST_STACK: IstStack = IstStack {
    _bytes: [0; IST_STACK_SIZE],
};
static mut BSP_RING0_STACK: Ring0Stack = Ring0Stack {
    _bytes: [0; RING0_STACK_SIZE],
};

fn halt_on_stack_allocation_failure() -> ! {
    crate::audit::log(
        crate::audit::AuditEventKind::Fault,
        "TSS stack allocation failed",
    );
    crate::warn!("TSS stack allocation failed");
    x86_64::instructions::interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

fn allocate_stack(size: usize) -> Option<u64> {
    let page_count = size.checked_add(4095)? / 4096;
    let frame = crate::mem::frame::allocate_contiguous_frames(page_count).ok()?;
    let pointer = frame
        .start_address()
        .as_u64()
        .checked_add(crate::mem::paging::physical_memory_offset()?)? as *mut u8;
    // SAFETY: The contiguous frames are owned permanently by this CPU's TSS,
    // and the HHDM pointer spans at least `size` writable bytes.
    unsafe {
        pointer.write_bytes(0, size);
    }
    Some(pointer as u64)
}

fn cpu_stacks(cpu: usize) -> CpuStacks {
    if cpu == 0 {
        return CpuStacks {
            ist_start: core::ptr::addr_of_mut!(BSP_IST_STACK) as u64,
            ring0_start: core::ptr::addr_of_mut!(BSP_RING0_STACK) as u64,
        };
    }

    *CPU_STACKS[cpu].call_once(|| {
        let ist_start =
            allocate_stack(IST_STACK_SIZE).unwrap_or_else(|| halt_on_stack_allocation_failure());
        let ring0_start =
            allocate_stack(RING0_STACK_SIZE).unwrap_or_else(|| halt_on_stack_allocation_failure());
        CpuStacks {
            ist_start,
            ring0_start,
        }
    })
}

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
        let stacks = cpu_stacks(cpu);

        // ダブルフォルト用の専用スタックを設定
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::new(stacks.ist_start);
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
            let stack_start = VirtAddr::new(stacks.ring0_start);
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
