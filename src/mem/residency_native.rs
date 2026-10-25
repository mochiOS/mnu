//! One counter per physical root generation. Counter retention owns no tables.
use super::residency::{Counter, Snapshot};
use crate::interrupt::spinlock::SpinLock;
use alloc::{sync::Arc, vec::Vec};

static ROOTS: SpinLock<Vec<(u64, Arc<Stats>)>> = SpinLock::new(Vec::new());
const MAX_ROOTS: usize = 65536;

pub(crate) struct Stats(SpinLock<Counter>);

impl Stats {
    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        self.0.lock().snapshot()
    }
}

/// Register before publishing a newly-created root. Allocation is fallible;
/// no leaf transition allocates or scans the address space afterwards.
pub(crate) fn register(root: u64) -> Result<(), ()> {
    if root == 0 || root & 4095 != 0 {
        return Err(());
    }
    let mut roots = ROOTS.lock();
    let index = roots
        .binary_search_by_key(&root, |(key, _)| *key)
        .err()
        .ok_or(())?;
    if roots.len() >= MAX_ROOTS {
        return Err(());
    }
    roots.try_reserve(1).map_err(|_| ())?;
    let stats = Arc::try_new(Stats(SpinLock::new(Counter::new()))).map_err(|_| ())?;
    roots.insert(index, (root, stats));
    Ok(())
}

pub(crate) fn get(root: u64) -> Option<Arc<Stats>> {
    let roots = ROOTS.lock();
    let index = roots.binary_search_by_key(&root, |(key, _)| *key).ok()?;
    Some(Arc::clone(&roots[index].1))
}

pub(crate) fn transition(root: u64, before: u64, after: u64) {
    if super::residency::is_resident(before) == super::residency::is_resident(after) {
        return;
    }
    if let Some(stats) = get(root) {
        stats.0.lock().transition(before, after);
    }
}

/// After destroying user leaves and before returning the root frame for reuse.
/// Also used by deferred root-pin cleanup.
/// Previously retained stats keep their peak and cannot alias a reused root.
pub(crate) fn retire(root: u64) {
    let stats = {
        let mut roots = ROOTS.lock();
        let Ok(index) = roots.binary_search_by_key(&root, |(key, _)| *key) else {
            return;
        };
        roots.remove(index).1
    };
    stats.0.lock().retire();
}
