//! Generic wait/wake operations keyed by user memory identity.
//!
//! This module provides a native synchronization mechanism. It deliberately
//! does not interpret POSIX futex operations, flags, or timeout structures.

use super::types::{EAGAIN, EFAULT, EINVAL};
use crate::interrupt::spinlock::SpinLock;
use crate::task::ThreadId;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use x86_64::VirtAddr;

#[derive(Clone, Copy)]
struct AddressKey {
    page_table: u64,
    virtual_address: u64,
    physical_address: u64,
}

impl AddressKey {
    fn matches(self, other: Self) -> bool {
        (self.page_table == other.page_table && self.virtual_address == other.virtual_address)
            || self.physical_address == other.physical_address
    }
}

#[derive(Clone, Copy)]
struct AddressWaiter {
    thread: ThreadId,
    key: AddressKey,
}

const MAX_WAITERS: usize = crate::task::ThreadQueue::MAX_THREADS;
static WAITERS: SpinLock<[Option<AddressWaiter>; MAX_WAITERS]> = SpinLock::new([None; MAX_WAITERS]);

fn resolve_key(address: u64, value_size: u64) -> Result<AddressKey, u64> {
    if !matches!(value_size, 1 | 2 | 4 | 8) || address & (value_size - 1) != 0 {
        return Err(EINVAL);
    }
    if !super::validate_user_ptr(address, value_size) {
        return Err(EFAULT);
    }

    // Fault in a lazily backed anonymous/file page before resolving its
    // physical identity. The value is loaded again atomically while holding
    // the waiter lock.
    let mut resident = [0u8; 8];
    super::copy_from_user(address, &mut resident[..value_size as usize])?;

    let page_table = super::current_user_page_table().ok_or(EFAULT)?;
    let (physical, _) =
        crate::mem::paging::translate_addr_in_table(page_table, VirtAddr::new(address))
            .ok_or(EFAULT)?;
    Ok(AddressKey {
        page_table,
        virtual_address: address,
        physical_address: physical.as_u64(),
    })
}

pub(crate) fn read_guard_value(address: u64) -> Result<u64, u64> {
    let key = resolve_key(address, 8)?;
    load_value(key, 8)
}

fn load_value(key: AddressKey, value_size: u64) -> Result<u64, u64> {
    let physical_offset = crate::mem::paging::physical_memory_offset().ok_or(EFAULT)?;
    let address = key
        .physical_address
        .checked_add(physical_offset)
        .ok_or(EFAULT)? as usize;
    let _smap_guard = crate::cpu::SmapSmepGuard::new();
    let value = unsafe {
        match value_size {
            1 => (&*(address as *const AtomicU8)).load(Ordering::Relaxed) as u64,
            2 => (&*(address as *const AtomicU16)).load(Ordering::Relaxed) as u64,
            4 => (&*(address as *const AtomicU32)).load(Ordering::Relaxed) as u64,
            8 => (&*(address as *const AtomicU64)).load(Ordering::Relaxed),
            _ => return Err(EINVAL),
        }
    };
    Ok(value)
}

fn expected_for_size(expected: u64, value_size: u64) -> u64 {
    match value_size {
        1 => expected & u8::MAX as u64,
        2 => expected & u16::MAX as u64,
        4 => expected & u32::MAX as u64,
        8 => expected,
        _ => expected,
    }
}

fn remove_waiter_locked(
    waiters: &mut [Option<AddressWaiter>; MAX_WAITERS],
    thread: ThreadId,
) -> bool {
    for slot in waiters.iter_mut() {
        if slot.is_some_and(|waiter| waiter.thread == thread) {
            *slot = None;
            return true;
        }
    }
    false
}

pub(crate) fn remove_waiter(thread: ThreadId) {
    remove_waiter_locked(&mut WAITERS.lock(), thread);
}

/// Waits while a naturally aligned 1, 2, 4, or 8-byte value equals
/// `expected`. `deadline_nanoseconds` is an absolute native monotonic-clock
/// deadline, or `ADDRESS_WAIT_INFINITE`.
pub fn wait(address: u64, expected: u64, value_size: u64, deadline_nanoseconds: u64) -> u64 {
    let key = match resolve_key(address, value_size) {
        Ok(key) => key,
        Err(error) => return error,
    };
    let thread = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return EINVAL,
    };
    let expected = expected_for_size(expected, value_size);

    {
        let mut waiters = WAITERS.lock();
        if waiters
            .iter()
            .flatten()
            .any(|waiter| waiter.thread == thread)
        {
            return EAGAIN;
        }
        let current = match load_value(key, value_size) {
            Ok(value) => value,
            Err(error) => return error,
        };
        if current != expected {
            return mnu_abi::AddressWaitResult::ValueChanged as u64;
        }
        if deadline_nanoseconds != mnu_abi::ADDRESS_WAIT_INFINITE
            && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds
        {
            return mnu_abi::AddressWaitResult::DeadlineReached as u64;
        }
        let Some(slot) = waiters.iter_mut().find(|slot| slot.is_none()) else {
            return EAGAIN;
        };
        *slot = Some(AddressWaiter { thread, key });
    }

    if deadline_nanoseconds != mnu_abi::ADDRESS_WAIT_INFINITE {
        let deadline_tick = crate::syscall::time::monotonic_deadline_tick(deadline_nanoseconds);
        if !crate::syscall::time::arm_thread_deadline(thread, deadline_tick) {
            remove_waiter(thread);
            return EAGAIN;
        }
    }

    loop {
        // Interrupt delivery needs a return to user mode, not just a scheduler
        // wakeup. No payload or userspace signal policy is interpreted here.
        let interrupted =
            crate::task::with_thread(thread, |thread| thread.has_deliverable_upcall())
                .unwrap_or(false);
        let result = {
            let mut waiters = WAITERS.lock();
            if interrupted {
                remove_waiter_locked(&mut waiters, thread);
                Some(mnu_abi::AddressWaitResult::Awoken)
            } else if !waiters
                .iter()
                .flatten()
                .any(|waiter| waiter.thread == thread)
            {
                Some(mnu_abi::AddressWaitResult::Awoken)
            } else if deadline_nanoseconds != mnu_abi::ADDRESS_WAIT_INFINITE
                && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds
            {
                remove_waiter_locked(&mut waiters, thread);
                Some(mnu_abi::AddressWaitResult::DeadlineReached)
            } else {
                None
            }
        };
        if let Some(result) = result {
            crate::syscall::time::disarm_thread_deadline(thread);
            return result as u64;
        }
        let _ = crate::task::sleep_thread_unless_woken(thread);
        crate::task::yield_now();
    }
}

/// Wakes up to `maximum_count` waiters registered for the same memory
/// identity and returns the number removed from the wait queue.
pub fn wake(address: u64, maximum_count: u64) -> u64 {
    if maximum_count == 0 {
        return 0;
    }
    let key = match resolve_key(address, 1) {
        Ok(key) => key,
        Err(error) => return error,
    };
    let maximum_count = usize::try_from(maximum_count)
        .unwrap_or(usize::MAX)
        .min(MAX_WAITERS);
    let mut wake_list = [None; MAX_WAITERS];
    let mut wake_count = 0usize;
    {
        let mut waiters = WAITERS.lock();
        for slot in waiters.iter_mut() {
            if wake_count == maximum_count {
                break;
            }
            if slot.is_some_and(|waiter| waiter.key.matches(key)) {
                if let Some(waiter) = slot.take() {
                    wake_list[wake_count] = Some(waiter.thread);
                    wake_count += 1;
                }
            }
        }
    }
    for thread in wake_list.into_iter().take(wake_count).flatten() {
        crate::task::wake_registered_waiter(thread);
    }
    wake_count as u64
}
