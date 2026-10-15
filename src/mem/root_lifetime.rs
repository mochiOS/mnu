//! Physical root lifetime only, not permission to access or edit page tables.
//! Acquiring pins requires the caller's mapping/ownership lock. A pin does not
//! replace mapping exclusion and must never justify retaining raw PTE pointers
//! across concurrent unmap, protection changes or address-space publication.
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::interrupt::spinlock::SpinLock;

static ROOTS: SpinLock<Vec<(u64, Weak<State>)>> = SpinLock::new(Vec::new());

pub(crate) struct State {
    table: u64,
    retired: AtomicBool,
}

impl Drop for State {
    fn drop(&mut self) {
        if self.retired.load(Ordering::Acquire) {
            if let Err(error) = super::paging::destroy_user_page_table_unpinned(self.table) {
                crate::warn!("Failed to release retired VM root: {:?}", error);
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct Pin {
    _state: Arc<State>,
}

/// The caller proves that the table is still owned and cannot be retired
/// during acquisition. Failed allocation never assumes physical ownership.
pub(crate) fn pin_with(
    table: u64,
    allocate: impl FnOnce(State) -> Result<Arc<State>, ()>,
) -> Result<Pin, ()> {
    if table == 0 || table & 4095 != 0 {
        return Err(());
    }
    let mut roots = ROOTS.lock();
    roots.retain(|(_, root)| root.strong_count() != 0);
    if let Some(state) = roots
        .iter()
        .find(|(key, _)| *key == table)
        .and_then(|(_, root)| root.upgrade())
    {
        // A rejected acquisition may hold the final retired reference too.
        // Its physical cleanup must not run under the registry lock.
        drop(roots);
        return if state.retired.load(Ordering::Acquire) {
            Err(())
        } else {
            Ok(Pin { _state: state })
        };
    }
    roots.try_reserve(1).map_err(|_| ())?;
    let state = allocate(State {
        table,
        retired: AtomicBool::new(false),
    })?;
    roots.push((table, Arc::downgrade(&state)));
    Ok(Pin { _state: state })
}

/// Transfer the owner's destruction obligation to the final pin, if any.
/// An absent registration leaves destruction with the original caller. Drop
/// the upgraded reference outside ROOTS: final release can run native cleanup.
pub(crate) fn retire(table: u64) -> bool {
    let state = {
        let roots = ROOTS.lock();
        let Some(state) = roots
            .iter()
            .find(|(key, _)| *key == table)
            .and_then(|(_, root)| root.upgrade())
        else {
            return false;
        };
        state.retired.store(true, Ordering::Release);
        state
    };
    drop(state);
    true
}
