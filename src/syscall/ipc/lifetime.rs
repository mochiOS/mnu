//! Endpoint-lifetime subscriptions, independent of message or provider policy.
//! One fixed row per native thread avoids allocation on synchronous IPC paths.
//! Retirement and subscription share the registry lock; thread-queue mutation
//! must be published before calling retire, with the queue lock released.

use super::IpcEndpoint;
use crate::interrupt::spinlock::SpinLock;
use crate::task::{ThreadId, ThreadQueue};

const LIMIT: usize = mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS;
const ESRCH: u64 = (-3i64) as u64;
const EAGAIN: u64 = (-11i64) as u64;

#[derive(Clone, Copy)]
struct Entry {
    endpoint: IpcEndpoint,
    references: u16,
}
struct Row {
    owner: Option<ThreadId>,
    entries: [Option<Entry>; LIMIT],
}
impl Row {
    const fn new() -> Self {
        Self {
            owner: None,
            entries: [None; LIMIT],
        }
    }
}
static WATCHERS: SpinLock<[Row; ThreadQueue::MAX_THREADS]> =
    SpinLock::new([const { Row::new() }; ThreadQueue::MAX_THREADS]);

#[must_use]
pub(crate) struct Observation {
    waiter: ThreadId,
    slot: usize,
    endpoint: IpcEndpoint,
}

impl Drop for Observation {
    fn drop(&mut self) {
        let mut watchers = WATCHERS.lock();
        let row = &mut watchers[self.slot];
        if row.owner != Some(self.waiter) {
            return;
        }
        if let Some(slot) = row
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|entry| entry.endpoint == self.endpoint))
        {
            let entry = slot.as_mut().unwrap();
            entry.references -= 1;
            if entry.references == 0 {
                *slot = None;
            }
        }
    }
}

pub(crate) fn observe(endpoint: IpcEndpoint, waiter: ThreadId) -> Result<Observation, u64> {
    let slot = crate::task::thread_slot_index_by_u64(waiter.as_u64()).ok_or(ESRCH)?;
    let mut watchers = WATCHERS.lock();
    // Validate under the subscription lock. A retirement published after this
    // check must see the new entry; an earlier retirement makes it fail here.
    if !super::endpoint_is_valid(endpoint) {
        return Err(ESRCH);
    }
    let row = watchers.get_mut(slot).ok_or(ESRCH)?;
    if row.owner != Some(waiter) {
        *row = Row::new();
        row.owner = Some(waiter);
    }
    if let Some(entry) = row
        .entries
        .iter_mut()
        .flatten()
        .find(|entry| entry.endpoint == endpoint)
    {
        entry.references = entry.references.checked_add(1).ok_or(EAGAIN)?;
    } else {
        let entry = row
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(EAGAIN)?;
        *entry = Some(Entry {
            endpoint,
            references: 1,
        });
    }
    Ok(Observation {
        waiter,
        slot,
        endpoint,
    })
}

pub(crate) fn retire(endpoint: IpcEndpoint) {
    let mut wake = [None; ThreadQueue::MAX_THREADS];
    {
        let mut watchers = WATCHERS.lock();
        for (index, row) in watchers.iter_mut().enumerate() {
            for entry in &mut row.entries {
                if entry.is_some_and(|entry| entry.endpoint == endpoint) {
                    *entry = None;
                    wake[index] = row.owner;
                }
            }
        }
    }
    // Never acquire the thread queue while holding the subscription registry.
    for waiter in wake.into_iter().flatten() {
        // The observer may still be Running immediately before parking.
        // Latch this notification so that transition cannot lose retirement.
        crate::task::wake_registered_waiter(waiter);
    }
}

/// A parked kernel stack can be discarded without running local destructors.
pub(crate) fn remove_waiter(waiter: ThreadId) {
    let mut watchers = WATCHERS.lock();
    for row in watchers.iter_mut() {
        if row.owner == Some(waiter) {
            *row = Row::new();
        }
    }
}
