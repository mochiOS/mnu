//! Shared scheduling clock. Tick units are independent of the CPU timer.
use core::sync::atomic::{AtomicU64, Ordering};

pub const TICKS_PER_SECOND: u64 = 500;
#[cfg(target_arch = "x86_64")]
pub const PIT_HZ: u64 = TICKS_PER_SECOND;
pub const TICK_MS: u64 = 1000 / TICKS_PER_SECOND;
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
#[path = "../arch/x86_64/timer.rs"]
mod hardware;
#[cfg(target_arch = "x86_64")]
pub use hardware::*;

#[cfg(target_arch = "x86_64")]
fn advance_clock() {
    let ticks = TIMER_TICKS
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    crate::syscall::time::wake_due_sleepers(ticks);
}

/// Publish elapsed architected-counter time, not a per-CPU interrupt count.
/// Concurrent timer IRQs can only move the shared clock forward.
#[cfg(target_arch = "aarch64")]
pub(crate) fn advance_to(ticks: u64) {
    let previous = TIMER_TICKS.fetch_max(ticks, Ordering::AcqRel);
    if ticks > previous {
        crate::syscall::time::wake_due_sleepers(ticks);
    }
}

/// 現在のタイマーティック数を取得
///
/// ## Returns
/// - タイマーティック数
pub fn get_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

#[inline]
pub const fn tick_ms() -> u64 {
    TICK_MS
}

#[inline]
pub const fn ticks_per_second() -> u64 {
    TICKS_PER_SECOND
}

#[inline]
pub const fn ms_to_ticks_ceil(milliseconds: u64) -> u64 {
    milliseconds
        .saturating_add(TICK_MS.saturating_sub(1))
        .saturating_div(TICK_MS)
}

/// タイマーカウンタをリセット
pub fn reset_ticks() {
    TIMER_TICKS.store(0, Ordering::Relaxed);
}
