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
	early_serial("entry: start\n");

	early_serial("entry: read stack pointer\n");
	let stack_pointer: u64;
	core::arch::asm!(
		"mov {}, rsp",
		out(reg) stack_pointer,
		options(nomem, nostack, preserves_flags)
	);

	early_serial("entry: get allocator address\n");
	let kernel_heap_addr = &KERNEL_ALLOCATOR as *const HardenedKernelHeap as u64;

	early_serial("entry: prepare boot info\n");
	let boot_info = match mnu::boot_memory::prepare_boot_info(
		boot_info_ptr,
		core::ptr::addr_of!(__kernel_start) as u64,
		core::ptr::addr_of!(__kernel_end) as u64,
		stack_pointer,
		kernel_heap_addr,
	) {
		Ok(boot_info) => {
			early_serial("entry: prepare boot info ok\n");
			boot_info
		}
		Err(_) => {
			early_serial("entry: prepare boot info failed\n");

			mnu::boot_memory::note_preparation_failure();

			early_serial("entry: set fallback heap address\n");
			(*boot_info_ptr).kernel_heap_addr = kernel_heap_addr;

			early_serial("entry: use original boot info\n");
			&*boot_info_ptr
		}
	};

	early_serial("entry: set SMP boot info address\n");
	mnu::smp::set_boot_info_addr(
		boot_info as *const mnu::BootInfo as u64,
	);

	early_serial("entry: enter mnu kernel\n");
	mnu::kernel_entry(boot_info)
}

fn early_serial(text: &str) {
	for byte in text.bytes() {
		unsafe {
			let mut status: u8;

			loop {
				core::arch::asm!(
					"in al, dx",
					in("dx") 0x3fdu16,
					out("al") status,
					options(nomem, nostack, preserves_flags),
				);

				if status & 0x20 != 0 {
					break;
				}
			}

			core::arch::asm!(
				"out dx, al",
				in("dx") 0x3f8u16,
				in("al") byte,
				options(nomem, nostack, preserves_flags),
			);
		}
	}
}
