#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

#[cfg(test)]
compile_error!("cargo test is disabled for this crate; use the QEMU/kernel self-test path instead");

#[cfg(feature = "kcfi")]
compile_error!(
    "feature `kcfi` is intentionally gated off: the current mochiOS build does not have a \
     verified Rust/LLVM KCFI pipeline for this freestanding x86_64 kernel. Leaving it \
     selectable without end-to-end verification would be unsound."
);

#[cfg(feature = "cet-ibt")]
compile_error!(
    "feature `cet-ibt` is intentionally gated off: hand-written syscall/interrupt/trampoline \
     assembly has not yet been fully annotated and inspected for ENDBR64 compliance."
);

#[cfg(feature = "cet-shadow-stack")]
compile_error!(
    "feature `cet-shadow-stack` is intentionally gated off: kernel shadow-stack allocation, \
     context-switch save/restore, and signal integration are not yet complete."
);

extern crate alloc;

/// エラー型定義
pub mod result;

/// 監査ログ
pub mod audit;

#[cfg(not(test))]
/// 割込み管理
pub mod interrupt;

#[cfg(not(test))]
pub mod config;
/// カーネル本体
#[cfg(not(test))]
pub mod kernel;

#[cfg(not(test))]
/// メモリ管理、GDT、TSSを含む
pub mod mem;

#[cfg(not(test))]
/// ELF周り
pub mod elf;

#[cfg(not(test))]
/// 起動ポリシー、manifest、署名検証の境界
pub mod policy;

/// パニックハンドラ
pub mod panic;

#[cfg(not(test))]
/// タスク管理
pub mod task;

#[cfg(not(test))]
/// システムコール
pub mod syscall;

#[cfg(not(test))]
/// 起動時初期化
pub mod init;

#[cfg(not(test))]
/// ユーティリティモジュール
pub mod util;

#[cfg(not(test))]
/// capability（権限）管理
pub mod capability;

#[cfg(not(test))]
/// cext 境界
pub mod cext;

#[cfg(not(test))]
/// CPU機能の初期化
pub mod cpu;
#[cfg(not(test))]
pub mod hypervisor_guest;
#[cfg(not(test))]
/// per-CPU状態管理
pub mod percpu;
#[cfg(not(test))]
/// Kernel cryptographic random generator.
pub mod random;
#[cfg(not(test))]
/// SMP/マルチコアの共有ハンドオフ
pub mod smp;

pub use mnu_abi::boot::{
    BootInfo, BootInfoError, MemoryRegion, MemoryType, SmpHandoff, BOOT_ABI_MAGIC,
    BOOT_ABI_VERSION, BOOT_FEATURE_ENTROPY, BOOT_FEATURE_FRAMEBUFFER,
    BOOT_FEATURE_HYPERVISOR_DOMAIN, BOOT_FEATURE_INITFS, BOOT_FEATURE_ROOTFS_IMAGE,
    BOOT_FEATURE_SMP, MAX_CPU_IDS,
};

#[cfg(not(test))]
pub use kernel::kernel_entry;
pub use result::{Kernel, Result};
