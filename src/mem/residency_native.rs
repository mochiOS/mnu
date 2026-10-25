//! One counter per physical root generation. Counter retention owns no tables.
use super::residency::{Counter, Snapshot};
use crate::interrupt::spinlock::SpinLock;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

static ROOTS: SpinLock<Vec<(u64, Arc<Stats>)>> = SpinLock::new(Vec::new());
const MAX_ROOTS: usize = 65536;

struct Watch {
    root: u64,
    started: bool,
    value: Snapshot,
    valid: bool,
}

impl Watch {
    fn observe(&mut self, value: Option<Snapshot>) {
        match value {
            Some(value) => {
                self.value.current_bytes = value.current_bytes;
                self.value.peak_bytes = self.value.peak_bytes.max(value.current_bytes);
            }
            None => self.valid = false,
        }
    }
}

struct State {
    counter: Counter,
    observers: Vec<Weak<SpinLock<Watch>>>,
}

impl State {
    fn notify(&mut self, root: u64) {
        let value = self.counter.snapshot();
        self.observers.retain(|observer| {
            let Some(observer) = observer.upgrade() else {
                return false;
            };
            let mut observer = observer.lock();
            if observer.root != root {
                return false;
            }
            observer.observe(value);
            true
        });
    }
}

/// One observer follows its process across root replacement. Shared roots
/// have independent observers; a new observer never inherits older peaks.
pub(crate) struct ProcessStats(Option<Arc<SpinLock<Watch>>>);

impl core::fmt::Debug for ProcessStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcessStats").finish_non_exhaustive()
    }
}

impl ProcessStats {
    pub(crate) fn new() -> Self {
        Self(
            Arc::try_new(SpinLock::new(Watch {
                root: 0,
                started: false,
                value: Snapshot::default(),
                valid: true,
            }))
            .ok(),
        )
    }

    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        let observer = self.0.as_ref()?.lock();
        (observer.started && observer.valid).then_some(observer.value)
    }

    /// Execution ownership ended, even if independent VM pins retain tables.
    pub(crate) fn detach(&self) {
        if let Some(observer) = &self.0 {
            let mut observer = observer.lock();
            observer.root = 0;
            observer.value.current_bytes = 0;
        }
    }

    pub(crate) fn bind_root(&self, root: u64) {
        let Some(observer) = &self.0 else { return };
        let Some(stats) = get(root) else {
            let mut observer = observer.lock();
            observer.valid = false;
            observer.root = 0;
            return;
        };
        let mut state = stats.0.lock();
        let weak = Arc::downgrade(observer);
        state.observers.retain(|old| {
            old.upgrade()
                .is_some_and(|old| !Arc::ptr_eq(&old, observer) && old.lock().root == root)
        });
        if state.observers.len() >= MAX_ROOTS || state.observers.try_reserve(1).is_err() {
            observer.lock().valid = false;
            return;
        }
        let mut value = observer.lock();
        value.root = root;
        value.started = true;
        value.observe(state.counter.snapshot());
        state.observers.push(weak);
    }
}

pub(crate) struct Stats(SpinLock<State>);

impl Stats {
    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        self.0.lock().counter.snapshot()
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
    let stats = Arc::try_new(Stats(SpinLock::new(State {
        counter: Counter::new(),
        observers: Vec::new(),
    })))
    .map_err(|_| ())?;
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
        let mut state = stats.0.lock();
        state.counter.transition(before, after);
        state.notify(root);
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
    let mut state = stats.0.lock();
    state.counter.retire();
    state.notify(root);
    state.observers.clear();
}
