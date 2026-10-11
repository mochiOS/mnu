//! Serialize native image replacement with thread construction. This gate
//! contains no userspace policy, names, paths or POSIX state.
use super::ProcessId;
use crate::interrupt::spinlock::SpinLock;
use alloc::collections::BTreeMap;

#[derive(Default)]
struct Activity {
    creators: usize,
    replacing: bool,
}

static ACTIVITY: SpinLock<BTreeMap<ProcessId, Activity>> = SpinLock::new(BTreeMap::new());

pub(crate) struct ThreadCreation(ProcessId);
pub(crate) struct ImageReplacement(ProcessId);

pub(crate) fn begin_thread_creation(process: ProcessId) -> Option<ThreadCreation> {
    let mut activity = ACTIVITY.lock();
    let state = activity.entry(process).or_default();
    if state.replacing {
        return None;
    }
    state.creators += 1;
    Some(ThreadCreation(process))
}

pub(crate) fn begin_image_replace(process: ProcessId) -> Option<ImageReplacement> {
    let mut activity = ACTIVITY.lock();
    let state = activity.entry(process).or_default();
    if state.replacing || state.creators != 0 {
        return None;
    }
    state.replacing = true;
    Some(ImageReplacement(process))
}

impl Drop for ThreadCreation {
    fn drop(&mut self) {
        let mut activity = ACTIVITY.lock();
        if let Some(state) = activity.get_mut(&self.0) {
            state.creators -= 1;
            if state.creators == 0 && !state.replacing {
                activity.remove(&self.0);
            }
        }
    }
}

impl Drop for ImageReplacement {
    fn drop(&mut self) {
        ACTIVITY.lock().remove(&self.0);
    }
}
