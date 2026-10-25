//! RAM-backed user leaf references, independent of accessibility and VM policy.
//! An inaccessible or suspended leaf still owns its resident RAM frame.
pub(crate) const RAM_LEAF: u64 = 1 << 11;
const USER: u64 = 1 << 2;
const PAGE_BYTES: u64 = 4096;

pub(crate) fn is_resident(flags: u64) -> bool {
    flags & (RAM_LEAF | USER) == RAM_LEAF | USER
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub current_bytes: u64,
    pub peak_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct Counter(Option<Snapshot>);

impl Counter {
    pub(crate) const fn new() -> Self {
        Self(Some(Snapshot {
            current_bytes: 0,
            peak_bytes: 0,
        }))
    }

    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        self.0
    }

    /// Call exactly once after a committed leaf change under VM exclusion.
    /// A lost/duplicate decrement makes metrics unavailable, never plausible.
    pub(crate) fn transition(&mut self, before: u64, after: u64) {
        let Some(mut value) = self.0 else { return };
        let old = is_resident(before);
        let new = is_resident(after);
        let next = match (old, new) {
            (false, true) => value.current_bytes.checked_add(PAGE_BYTES),
            (true, false) => value.current_bytes.checked_sub(PAGE_BYTES),
            _ => Some(value.current_bytes),
        };
        self.0 = next.map(|bytes| {
            value.current_bytes = bytes;
            value.peak_bytes = value.peak_bytes.max(bytes);
            value
        });
    }

    pub(crate) fn retire(&mut self) {
        if let Some(value) = &mut self.0 {
            value.current_bytes = 0;
        }
    }
}
