//! 時間関連システムコール

use super::types::{EACCES, EAGAIN, EFAULT, EINVAL, SUCCESS};
use crate::interrupt::spinlock::SpinLock;
use crate::task::ThreadId;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static REALTIME_VALID: AtomicBool = AtomicBool::new(false);
static REALTIME_BASE_SECONDS: AtomicU64 = AtomicU64::new(0);
static REALTIME_BASE_TICKS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeError {
    Unavailable,
    InvalidDate,
    InvalidYear,
}

pub fn initialize_realtime() -> Result<(), RealtimeError> {
    let date = crate::cpu::rtc_utc().ok_or(RealtimeError::Unavailable)?;
    let seconds = mochios_time_core::unix_seconds(date).map_err(|error| match error {
        mochios_time_core::Error::InvalidDate => RealtimeError::InvalidDate,
        mochios_time_core::Error::InvalidYear => RealtimeError::InvalidYear,
    })?;
    REALTIME_BASE_SECONDS.store(seconds, Ordering::Release);
    REALTIME_BASE_TICKS.store(get_ticks(), Ordering::Release);
    REALTIME_VALID.store(true, Ordering::Release);
    Ok(())
}

pub fn realtime() -> Result<(u64, u64), RealtimeError> {
    if !REALTIME_VALID.load(Ordering::Acquire) {
        return Err(RealtimeError::Unavailable);
    }
    let ticks_per_second = crate::interrupt::timer::ticks_per_second();
    if ticks_per_second == 0 {
        return Err(RealtimeError::Unavailable);
    }
    let elapsed = get_ticks().saturating_sub(REALTIME_BASE_TICKS.load(Ordering::Acquire));
    let seconds = REALTIME_BASE_SECONDS
        .load(Ordering::Acquire)
        .saturating_add(elapsed / ticks_per_second);
    let nanoseconds = (elapsed % ticks_per_second)
        .saturating_mul(crate::interrupt::timer::tick_ms())
        .saturating_mul(1_000_000);
    Ok((seconds, nanoseconds))
}

#[derive(Clone, Copy)]
struct SleepEntry {
    tid: ThreadId,
    wake_tick: u64,
}

const MAX_SLEEPERS: usize = crate::task::ThreadQueue::MAX_THREADS;
static SLEEP_QUEUE: SpinLock<[Option<SleepEntry>; MAX_SLEEPERS]> =
    SpinLock::new([None; MAX_SLEEPERS]);

fn register_sleep_entry(tid: ThreadId, wake_tick: u64) -> bool {
    let mut queue = SLEEP_QUEUE.lock();

    for slot in queue.iter_mut() {
        if slot.is_some_and(|entry| entry.tid == tid) {
            *slot = Some(SleepEntry { tid, wake_tick });
            return true;
        }
    }

    for slot in queue.iter_mut() {
        if slot.is_none() {
            *slot = Some(SleepEntry { tid, wake_tick });
            return true;
        }
    }

    false
}

pub fn wake_due_sleepers(now_tick: u64) {
    #[cfg(feature = "performance-instrumentation")]
    let started = crate::performance::timestamp();
    let mut wake_list = [None; MAX_SLEEPERS];
    let mut wake_count = 0usize;

    {
        let mut queue = SLEEP_QUEUE.lock();
        for slot in queue.iter_mut() {
            if let Some(entry) = *slot {
                if now_tick >= entry.wake_tick {
                    if wake_count < wake_list.len() {
                        wake_list[wake_count] = Some(entry.tid);
                        wake_count += 1;
                    }
                    *slot = None;
                }
            }
        }
    }

    for tid in wake_list.iter().take(wake_count).flatten() {
        crate::task::wake_thread(*tid);
    }
    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_timer_queue_check(
        crate::performance::TimerQueueKind::Sleep,
        started,
        true,
        wake_count,
    );
}

/// GetTicksシステムコール
///
/// カーネル起動からのティック数を取得
///
/// # 戻り値
/// ティック数
pub fn get_ticks() -> u64 {
    crate::interrupt::timer::get_ticks()
}

/// clock_gettimeシステムコール (Linux互換)
///
/// # 引数
/// - `clk_id`: クロックID (0=CLOCK_REALTIME, 1=CLOCK_MONOTONIC)
/// - `ts_ptr`: timespec構造体へのポインタ
///
/// # 戻り値
/// 成功時は0
pub fn clock_gettime(clk_id: u64, ts_ptr: u64) -> u64 {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
    const CLOCK_THREAD_CPUTIME_ID: u64 = 3;

    if ts_ptr == 0 {
        return EINVAL;
    }
    // ユーザー空間アドレスの有効性を検証する (timespec = 16バイト)
    if !crate::syscall::validate_user_ptr(ts_ptr, 16) {
        return EFAULT;
    }

    if clk_id == CLOCK_REALTIME
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::SystemTimeRead,
        ])
    {
        return EACCES;
    }

    let ticks = get_ticks();
    let ticks_per_second = crate::interrupt::timer::ticks_per_second();
    let tick_ns = crate::interrupt::timer::tick_ms() * 1_000_000;
    let (sec, nsec) = match clk_id {
        CLOCK_REALTIME => match realtime() {
            Ok(value) => value,
            Err(_) => return EAGAIN,
        },
        CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => (
            ticks / ticks_per_second,
            (ticks % ticks_per_second) * tick_ns,
        ),
        _ => return EINVAL,
    };
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&(sec as i64).to_ne_bytes());
    buf[8..16].copy_from_slice(&(nsec as i64).to_ne_bytes());
    match crate::syscall::copy_to_user(ts_ptr, &buf) {
        Ok(()) => SUCCESS,
        Err(e) => e,
    }
}

/// SleepUntilシステムコール
///
/// 指定されたティック数まで待機する
///
/// # 引数
/// - `ticks`: 待機する絶対ティック数
///
/// # 戻り値
/// 成功時は0
pub fn sleep_until(ticks: u64) -> u64 {
    if get_ticks() >= ticks {
        return SUCCESS;
    }

    let current_tid = match crate::task::current_thread_id() {
        Some(tid) => tid,
        None => return EINVAL,
    };

    let queued = x86_64::instructions::interrupts::without_interrupts(|| {
        if !register_sleep_entry(current_tid, ticks) {
            return false;
        }
        crate::task::sleep_thread(current_tid);
        true
    });
    if !queued {
        return EAGAIN;
    }

    while get_ticks() < ticks {
        crate::task::yield_now();
    }
    SUCCESS
}
