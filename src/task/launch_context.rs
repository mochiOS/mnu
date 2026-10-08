use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use super::handle_table::ObjectHandle;

pub const PROCESS_MAX_INHERITED_HANDLES: usize = 256;
pub const PROCESS_MAX_INHERITED_VALUES: usize = 256;

/// Opaque launch metadata mapping user-space-defined keys to process-local
/// kernel object handles. The kernel never assigns meaning to a key.
#[derive(Clone, Debug)]
pub struct LaunchContext {
    inherited_handles: BTreeMap<u64, ObjectHandle>,
    inherited_values: BTreeMap<u64, u64>,
}

impl LaunchContext {
    pub fn new_boxed() -> Box<Self> {
        Box::new(Self {
            inherited_handles: BTreeMap::new(),
            inherited_values: BTreeMap::new(),
        })
    }

    pub fn get(&self, key: u64) -> Option<ObjectHandle> {
        self.inherited_handles.get(&key).copied()
    }

    pub fn install(&mut self, key: u64, handle: ObjectHandle) -> bool {
        if self.inherited_handles.len() >= PROCESS_MAX_INHERITED_HANDLES
            || self.inherited_handles.contains_key(&key)
        {
            return false;
        }
        self.inherited_handles.insert(key, handle);
        true
    }

    pub fn set(&mut self, key: u64, handle: ObjectHandle) -> bool {
        if self.inherited_handles.len() >= PROCESS_MAX_INHERITED_HANDLES
            && !self.inherited_handles.contains_key(&key)
        {
            return false;
        }
        self.inherited_handles.insert(key, handle);
        true
    }

    pub fn take(&mut self, key: u64) -> Option<ObjectHandle> {
        self.inherited_handles.remove(&key)
    }

    pub fn remove_handle(&mut self, handle: ObjectHandle) {
        self.inherited_handles
            .retain(|_, inherited| *inherited != handle);
    }

    pub fn references_handle(&self, handle: ObjectHandle) -> bool {
        self.inherited_handles
            .values()
            .any(|inherited| *inherited == handle)
    }

    pub fn value(&self, key: u64) -> Option<u64> {
        self.inherited_values.get(&key).copied()
    }

    pub fn install_value(&mut self, key: u64, value: u64) -> bool {
        if self.inherited_values.len() >= PROCESS_MAX_INHERITED_VALUES
            || self.inherited_values.contains_key(&key)
        {
            return false;
        }
        self.inherited_values.insert(key, value);
        true
    }

    pub fn set_value(&mut self, key: u64, value: u64) -> bool {
        if self.inherited_values.len() >= PROCESS_MAX_INHERITED_VALUES
            && !self.inherited_values.contains_key(&key)
        {
            return false;
        }
        self.inherited_values.insert(key, value);
        true
    }

    pub fn remove_value(&mut self, key: u64) -> Option<u64> {
        self.inherited_values.remove(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_opaque_and_cannot_be_replaced() {
        let mut context = LaunchContext::new_boxed();
        let first = ObjectHandle::from_raw(1).unwrap();
        let second = ObjectHandle::from_raw(2).unwrap();
        assert!(context.install(0x706f_7369_782d_6970, first));
        assert!(!context.install(0x706f_7369_782d_6970, second));
        assert_eq!(context.get(0x706f_7369_782d_6970), Some(first));
    }

    #[test]
    fn taking_and_closing_handles_remove_launch_references() {
        let mut context = LaunchContext::new_boxed();
        let first = ObjectHandle::from_raw(1).unwrap();
        let second = ObjectHandle::from_raw(2).unwrap();
        assert!(context.install(1, first));
        assert!(context.install(2, second));
        assert_eq!(context.take(1), Some(first));
        assert_eq!(context.get(1), None);
        context.remove_handle(second);
        assert_eq!(context.get(2), None);
    }

    #[test]
    fn opaque_values_are_independent_from_handle_keys() {
        let mut context = LaunchContext::new_boxed();
        let handle = ObjectHandle::from_raw(1).unwrap();
        assert!(context.install(7, handle));
        assert!(context.install_value(7, u64::MAX));
        assert_eq!(context.value(7), Some(u64::MAX));
        assert!(!context.install_value(7, 1));
    }

    #[test]
    fn context_entries_can_be_replaced_and_removed_by_opaque_key() {
        let mut context = LaunchContext::new_boxed();
        let first = ObjectHandle::from_raw(1).unwrap();
        let second = ObjectHandle::from_raw(2).unwrap();
        assert!(context.set(11, first));
        assert!(context.set(11, second));
        assert_eq!(context.get(11), Some(second));
        assert_eq!(context.take(11), Some(second));
        assert_eq!(context.get(11), None);

        assert!(context.set_value(12, 40));
        assert!(context.set_value(12, 41));
        assert_eq!(context.value(12), Some(41));
        assert_eq!(context.remove_value(12), Some(41));
        assert_eq!(context.value(12), None);
    }
}
