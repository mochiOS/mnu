//! 割込み管理モジュール
//!
//! IDT、PIC、タイマーなどの割込み処理を管理

pub mod apic;
pub mod dispatch;
#[cfg(target_arch = "x86_64")]
pub mod idt;
mod page_fault;
pub mod pic;
pub mod spinlock;
pub mod timer;
mod user_stack;

#[cfg(target_arch = "aarch64")]
#[path = "../arch/aarch64/interrupt.rs"]
mod native;

#[cfg(target_arch = "x86_64")]
pub use idt::init as init_idt;
#[cfg(target_arch = "aarch64")]
pub use native::init as init_idt;
pub use pic::{init as init_pic, send_eoi};
pub use timer::{disable_pit, enable_timer_interrupt, init_pit};
