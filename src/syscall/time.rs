//! 時間関連システムコール

use super::types::{EACCES, EAGAIN, EFAULT, EINVAL, SUCCESS};
use crate::interrupt::spinlock::SpinLock;
use crate::task::ThreadId;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static REALTIME_VALID: AtomicBool = AtomicBool::new(false);
static REALTIME_BASE_SECONDS: AtomicU64 = AtomicU64::new(0);
static REALTIME_BASE_TICKS: AtomicU64 = AtomicU64::new(0);
const NO_DEADLINE: u64 = u64::MAX;

pub(super) struct DeadlineHint(AtomicU64);

impl DeadlineHint {
    pub const fn new() -> Self {
        Self(AtomicU64::new(NO_DEADLINE))
    }

    pub fn note(&self, deadline: u64) {
        self.0.fetch_min(deadline, Ordering::Release);
    }

    pub fn is_due(&self, now: u64) -> bool {
        now >= self.0.load(Ordering::Acquire)
    }

    /// Replaces the hint after scanning the queue while its lock is held.
    pub fn replace_after_scan(&self, deadline: u64) {
        self.0.store(deadline, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeError {
    Unavailable,
    InvalidDate,
    InvalidYear,
}

pub fn initialize_realtime() -> Result<(), RealtimeError> {
    let date = crate::cpu::rtc_utc().ok_or(RealtimeError::Unavailable)?;
    let seconds = mnu_time_core::unix_seconds(date).map_err(|error| match error {
        mnu_time_core::Error::InvalidDate => RealtimeError::InvalidDate,
        mnu_time_core::Error::InvalidYear => RealtimeError::InvalidYear,
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
static NEXT_SLEEP_DEADLINE: DeadlineHint = DeadlineHint::new();

fn store_sleep_entry(slot: &mut Option<SleepEntry>, entry: SleepEntry) {
    *slot = Some(entry);
    NEXT_SLEEP_DEADLINE.note(entry.wake_tick);
}

fn register_sleep_entry(tid: ThreadId, wake_tick: u64) -> bool {
    let mut queue = SLEEP_QUEUE.lock();

    for slot in queue.iter_mut() {
        if slot.is_some_and(|entry| entry.tid == tid) {
            store_sleep_entry(slot, SleepEntry { tid, wake_tick });
            return true;
        }
    }

    for slot in queue.iter_mut() {
        if slot.is_none() {
            store_sleep_entry(slot, SleepEntry { tid, wake_tick });
            return true;
        }
    }

    false
}

pub(crate) fn arm_thread_deadline(tid: ThreadId, wake_tick: u64) -> bool {
    register_sleep_entry(tid, wake_tick)
}

pub(crate) fn disarm_thread_deadline(tid: ThreadId) {
    let mut queue = SLEEP_QUEUE.lock();
    for slot in queue.iter_mut() {
        if slot.is_some_and(|entry| entry.tid == tid) {
            *slot = None;
        }
    }
}

pub fn wake_due_sleepers(now_tick: u64) {
    #[cfg(feature = "performance-instrumentation")]
    let started = crate::performance::timestamp();
    if !NEXT_SLEEP_DEADLINE.is_due(now_tick) {
        #[cfg(feature = "performance-instrumentation")]
        crate::performance::record_timer_queue_check(
            crate::performance::TimerQueueKind::Sleep,
            started,
            false,
            0,
        );
        return;
    }

    let wake_count = wake_due_sleepers_slow(now_tick);
    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = wake_count;
    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_timer_queue_check(
        crate::performance::TimerQueueKind::Sleep,
        started,
        true,
        wake_count,
    );
}

#[cold]
#[inline(never)]
fn wake_due_sleepers_slow(now_tick: u64) -> usize {
    let mut wake_list = [None; MAX_SLEEPERS];
    let mut wake_count = 0usize;

    {
        let mut queue = SLEEP_QUEUE.lock();
        let mut next_deadline = NO_DEADLINE;
        for slot in queue.iter_mut() {
            if let Some(entry) = *slot {
                if now_tick >= entry.wake_tick {
                    if wake_count < wake_list.len() {
                        wake_list[wake_count] = Some(entry.tid);
                        wake_count += 1;
                    }
                    *slot = None;
                } else {
                    next_deadline = next_deadline.min(entry.wake_tick);
                }
            }
        }
        NEXT_SLEEP_DEADLINE.replace_after_scan(next_deadline);
    }

    for tid in wake_list.iter().take(wake_count).flatten() {
        crate::task::wake_thread(*tid);
    }
    wake_count
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

/// Reads one native mnu clock into a fixed-layout `ClockInstant`.
///
/// POSIX clock identifiers and `timespec` layout are deliberately translated
/// in user space rather than exposed by this syscall.
pub fn clock_read(clock: u64, instant_ptr: u64) -> u64 {
    let Some(clock) = mnu_abi::ClockId::from_raw(clock) else {
        return EINVAL;
    };
    if instant_ptr == 0
        || !crate::syscall::validate_user_ptr(
            instant_ptr,
            core::mem::size_of::<mnu_abi::ClockInstant>() as u64,
        )
    {
        return EFAULT;
    }

    if clock == mnu_abi::ClockId::Realtime
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::SystemTimeRead,
        ])
    {
        return EACCES;
    }

    let ticks_per_second = crate::interrupt::timer::ticks_per_second();
    if ticks_per_second == 0 {
        return EAGAIN;
    }
    let ticks = match clock {
        mnu_abi::ClockId::Monotonic => get_ticks(),
        mnu_abi::ClockId::ThreadCpu => {
            let Some(thread_id) = crate::task::current_thread_id() else {
                return EAGAIN;
            };
            let Some(ticks) = crate::task::with_thread(thread_id, |thread| thread.cpu_ticks())
            else {
                return EAGAIN;
            };
            ticks
        }
        mnu_abi::ClockId::ProcessCpu => {
            let Some(thread_id) = crate::task::current_thread_id() else {
                return EAGAIN;
            };
            let Some(process_id) =
                crate::task::with_thread(thread_id, |thread| thread.process_id())
            else {
                return EAGAIN;
            };
            let mut ticks = 0u64;
            crate::task::for_each_thread(|thread| {
                if thread.process_id() == process_id {
                    ticks = ticks.saturating_add(thread.cpu_ticks());
                }
            });
            ticks
        }
        mnu_abi::ClockId::Realtime => 0,
    };
    let (seconds, nanoseconds) = match clock {
        mnu_abi::ClockId::Realtime => match realtime() {
            Ok(value) => value,
            Err(_) => return EAGAIN,
        },
        mnu_abi::ClockId::Monotonic
        | mnu_abi::ClockId::ProcessCpu
        | mnu_abi::ClockId::ThreadCpu => (
            ticks / ticks_per_second,
            (ticks % ticks_per_second)
                .saturating_mul(crate::interrupt::timer::tick_ms())
                .saturating_mul(1_000_000),
        ),
    };
    let instant = mnu_abi::ClockInstant {
        seconds,
        nanoseconds: nanoseconds as u32,
        reserved: 0,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&instant as *const mnu_abi::ClockInstant).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ClockInstant>(),
        )
    };
    match crate::syscall::copy_to_user(instant_ptr, bytes) {
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
