#![no_std]
#![no_main]

//! カーネルスタンドアローンバイナリのエントリポイント
//!
//! ブートローダーは sysv64 呼び出し規約で kernel_entry(boot_info_ptr) を呼ぶ。
//! ここで自前の LockedHeap アロケータを設定してから `mnu` のカーネル本体へ移譲する。

use mnu::mem::allocator::HardenedKernelHeap;

unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

/// カーネルのグローバルアロケータ
/// mem::init 内の init_heap がこの HardenedKernelHeap を初期化する
#[global_allocator]
static KERNEL_ALLOCATOR: HardenedKernelHeap = HardenedKernelHeap::empty();

/// ELF エントリポイント
///
/// ブートローダーが構築した BootInfo の kernel_heap_addr フィールドを
/// 自分の KERNEL_ALLOCATOR のアドレスで上書きしてから kernel_entry を呼ぶ。
/// これにより `mnu` 側の init_heap が正しいアロケータを初期化できる。
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn kernel_entry(boot_info_ptr: *mut mnu::BootInfo) -> ! {
    let stack_pointer: u64;
    core::arch::asm!(
        "mov {}, rsp",
        out(reg) stack_pointer,
        options(nomem, nostack, preserves_flags)
    );
    let kernel_heap_addr = &KERNEL_ALLOCATOR as *const HardenedKernelHeap as u64;
    let boot_info = match mnu::boot_memory::prepare_boot_info(
        boot_info_ptr,
        core::ptr::addr_of!(__kernel_start) as u64,
        core::ptr::addr_of!(__kernel_end) as u64,
        stack_pointer,
        kernel_heap_addr,
    ) {
        Ok(boot_info) => boot_info,
        Err(_) => {
            mnu::boot_memory::note_preparation_failure();
            (*boot_info_ptr).kernel_heap_addr = kernel_heap_addr;
            &*boot_info_ptr
        }
    };
    mnu::smp::set_boot_info_addr(boot_info as *const mnu::BootInfo as u64);

    mnu::kernel_entry(boot_info)
}
