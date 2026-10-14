//! Serialize native image capture/replacement with thread construction. This gate
//! contains no userspace policy, names, paths or POSIX state.
use super::ProcessId;
use crate::interrupt::spinlock::SpinLock;
use alloc::collections::BTreeMap;

#[derive(Default)]
struct Activity {
    creators: usize,
    exclusive: bool,
}

static ACTIVITY: SpinLock<BTreeMap<ProcessId, Activity>> = SpinLock::new(BTreeMap::new());

pub(crate) struct ThreadCreation(ProcessId);
pub(crate) struct ImageTransition(ProcessId);

pub(crate) fn begin_thread_creation(process: ProcessId) -> Option<ThreadCreation> {
    let mut activity = ACTIVITY.lock();
    let state = activity.entry(process).or_default();
    if state.exclusive {
        return None;
    }
    state.creators += 1;
    Some(ThreadCreation(process))
}

pub(crate) fn begin_image_transition(process: ProcessId) -> Option<ImageTransition> {
    let mut activity = ACTIVITY.lock();
    let state = activity.entry(process).or_default();
    if state.exclusive || state.creators != 0 {
        return None;
    }
    state.exclusive = true;
    Some(ImageTransition(process))
}

impl Drop for ThreadCreation {
    fn drop(&mut self) {
        let mut activity = ACTIVITY.lock();
        if let Some(state) = activity.get_mut(&self.0) {
            state.creators -= 1;
            if state.creators == 0 && !state.exclusive {
                activity.remove(&self.0);
            }
        }
    }
}

impl Drop for ImageTransition {
    fn drop(&mut self) {
        ACTIVITY.lock().remove(&self.0);
    }
}
