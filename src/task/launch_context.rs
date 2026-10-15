use alloc::boxed::Box;
use alloc::vec::Vec;

use super::handle_table::ObjectHandle;

pub const PROCESS_MAX_INHERITED_HANDLES: usize = 256;
pub const PROCESS_MAX_INHERITED_VALUES: usize = 256;

/// Small sorted maps allow fallible reservation before an image transition.
/// No node allocation is hidden in the subsequent context commit.
#[derive(Clone, Debug)]
struct Entries<T>(Vec<(u64, T)>);

impl<T: Copy> Entries<T> {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn index(&self, key: &u64) -> Result<usize, usize> {
        self.0.binary_search_by_key(key, |entry| entry.0)
    }
    fn get(&self, key: &u64) -> Option<&T> {
        self.index(key).ok().map(|index| &self.0[index].1)
    }
    fn contains_key(&self, key: &u64) -> bool {
        self.index(key).is_ok()
    }
    fn insert(&mut self, key: u64, value: T) -> bool {
        match self.index(&key) {
            Ok(index) => self.0[index].1 = value,
            Err(index) => {
                if self.0.try_reserve(1).is_err() {
                    return false;
                }
                self.0.insert(index, (key, value));
            }
        }
        true
    }
    fn remove(&mut self, key: &u64) -> Option<T> {
        self.index(key).ok().map(|index| self.0.remove(index).1)
    }
    fn retain(&mut self, mut keep: impl FnMut(&u64, &T) -> bool) {
        self.0.retain(|(key, value)| keep(key, value));
    }
    fn values(&self) -> impl Iterator<Item = &T> {
        self.0.iter().map(|entry| &entry.1)
    }
    fn try_copy(&self, capacity: usize) -> Result<Self, u64> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(capacity.max(self.len()))
            .map_err(|_| mnu_abi::ENOMEM)?;
        copy.extend_from_slice(&self.0);
        Ok(Self(copy))
    }
}

/// Opaque launch metadata mapping user-space-defined keys to process-local
/// kernel object handles. The kernel never assigns meaning to a key.
#[derive(Clone, Debug)]
pub struct LaunchContext {
    inherited_handles: Entries<ObjectHandle>,
    inherited_values: Entries<u64>,
}

impl LaunchContext {
    pub fn new_boxed() -> Box<Self> {
        Box::new(Self {
            inherited_handles: Entries::new(),
            inherited_values: Entries::new(),
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
        self.inherited_handles.insert(key, handle)
    }

    pub fn set(&mut self, key: u64, handle: ObjectHandle) -> bool {
        if self.inherited_handles.len() >= PROCESS_MAX_INHERITED_HANDLES
            && !self.inherited_handles.contains_key(&key)
        {
            return false;
        }
        self.inherited_handles.insert(key, handle)
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
        self.inherited_values.insert(key, value)
    }

    pub fn set_value(&mut self, key: u64, value: u64) -> bool {
        if self.inherited_values.len() >= PROCESS_MAX_INHERITED_VALUES
            && !self.inherited_values.contains_key(&key)
        {
            return false;
        }
        self.inherited_values.insert(key, value)
    }

    pub fn remove_value(&mut self, key: u64) -> Option<u64> {
        self.inherited_values.remove(&key)
    }

    /// Prepare a replacement off to the side. Call with sibling execution
    /// quiesced and the process locked, so selected owned labels cannot change.
    /// Keys are opaque; Handle association never duplicates or elevates rights.
    pub(crate) fn patched<I>(
        &self,
        updates: I,
        mut valid_handle: impl FnMut(ObjectHandle) -> bool,
    ) -> Result<Self, u64>
    where
        I: Iterator<Item = mnu_abi::process_image::ContextUpdate> + Clone,
    {
        use mnu_abi::process_image::ContextUpdate as U;
        let mut handles = self.inherited_handles.len();
        let mut values = self.inherited_values.len();
        for update in updates.clone() {
            match update.kind {
                U::SET_HANDLE => {
                    let handle = u32::try_from(update.value)
                        .ok()
                        .and_then(ObjectHandle::from_raw)
                        .ok_or(mnu_abi::EBADF)?;
                    if !valid_handle(handle) {
                        return Err(mnu_abi::EBADF);
                    }
                    handles += usize::from(!self.inherited_handles.contains_key(&update.key));
                }
                U::REMOVE_HANDLE => {
                    handles = handles
                        .checked_sub(usize::from(
                            self.inherited_handles.contains_key(&update.key),
                        ))
                        .ok_or(mnu_abi::EINVAL)?
                }
                U::SET_VALUE => {
                    values += usize::from(!self.inherited_values.contains_key(&update.key))
                }
                U::REMOVE_VALUE => {
                    values = values
                        .checked_sub(usize::from(self.inherited_values.contains_key(&update.key)))
                        .ok_or(mnu_abi::EINVAL)?
                }
                _ => return Err(mnu_abi::EINVAL),
            }
        }
        if handles > PROCESS_MAX_INHERITED_HANDLES || values > PROCESS_MAX_INHERITED_VALUES {
            return Err(mnu_abi::ENOSPC);
        }
        let mut prepared = Self {
            inherited_handles: self.inherited_handles.try_copy(handles)?,
            inherited_values: self.inherited_values.try_copy(values)?,
        };
        // Remove first: replacing a full context with a different key set must
        // not fail merely because the serialized edits list additions first.
        for update in updates.clone() {
            match update.kind {
                U::REMOVE_HANDLE => {
                    prepared.take(update.key);
                }
                U::REMOVE_VALUE => {
                    prepared.remove_value(update.key);
                }
                _ => {}
            }
        }
        for update in updates {
            let installed = match update.kind {
                U::SET_HANDLE => prepared.set(
                    update.key,
                    ObjectHandle::from_raw(update.value as u32).ok_or(mnu_abi::EBADF)?,
                ),
                U::SET_VALUE => prepared.set_value(update.key, update.value),
                _ => true,
            };
            if !installed {
                return Err(mnu_abi::ENOMEM);
            }
        }
        Ok(prepared)
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
