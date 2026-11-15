//! 割込み管理モジュール
//!
//! IDT、PIC、タイマーなどの割込み処理を管理

#[cfg(target_arch = "x86_64")]
pub mod apic;
pub mod dispatch;
#[cfg(target_arch = "x86_64")]
pub mod idt;
#[cfg(target_arch = "x86_64")]
mod page_fault;
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
pub use pic::{init as init_pic, send_eoi};
#[cfg(target_arch = "x86_64")]
pub use timer::{disable_pit, enable_timer_interrupt, init_pit};

/// Install the native scheduler interrupt source while IRQs remain masked.
pub fn init_scheduler_timer(info: &'static crate::BootInfo) -> crate::Result<()> {
    #[cfg(target_arch = "aarch64")]
    {
        native::initialize_scheduler(info)
    }
    #[cfg(target_arch = "x86_64")]
    {
        let _ = info;
        if crate::hypervisor_guest::is_active() {
            if !crate::smp::enable_hypervisor_scheduler_timer() {
                crate::warn!("Hypervisor virtual scheduler timer unavailable");
            }
        } else {
            init_pit();
            enable_timer_interrupt();
        }
        Ok(())
    }
}
