//! Shared I/O objects referenced by native kernel Handles.

use alloc::sync::Arc;

use crate::interrupt::spinlock::SpinLock;

/// FileHandle に付与する権限
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHandleCap(u32);

impl FileHandleCap {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Shared native byte-stream endpoint state, independent of POSIX descriptors.
pub struct OpenFile {
    /// Native stream identity in the global stream table.
    pub pipe_id: Option<usize>,
    /// パイプの書き込み端の場合 true
    pub pipe_write: bool,
    /// Native object behavior flags. These are independent of any POSIX ABI.
    pub io_options: u64,
}

impl OpenFile {
    fn new_pipe(pipe_id: usize, pipe_write: bool) -> Self {
        Self {
            pipe_id: Some(pipe_id),
            pipe_write,
            io_options: 0,
        }
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if let Some(pipe_id) = self.pipe_id {
            crate::syscall::fs::close_pipe_endpoint_from_kernel(pipe_id, self.pipe_write);
        }
    }
}

/// Native Handle reference to a shared I/O object.
///
/// Per-reference rights are separate from the shared object state.
pub struct FileHandle {
    pub open: Arc<SpinLock<OpenFile>>,
    /// Operations permitted through this reference.
    pub cap: FileHandleCap,
}

impl FileHandle {
    pub fn new(open: OpenFile, cap: FileHandleCap) -> Self {
        Self {
            open: Arc::new(SpinLock::new(open)),
            cap,
        }
    }

    pub fn duplicate(&self) -> Self {
        Self {
            open: self.open.clone(),
            cap: self.cap,
        }
    }

    pub fn new_pipe_read(pipe_id: usize) -> Self {
        Self::new(
            OpenFile::new_pipe(pipe_id, false),
            FileHandleCap::READ,
        )
    }

    pub fn new_pipe_write(pipe_id: usize) -> Self {
        Self::new(
            OpenFile::new_pipe(pipe_id, true),
            FileHandleCap::WRITE,
        )
    }

    pub fn stream_endpoint(&self) -> Option<(usize, bool)> {
        let open = self.open.lock();
        open.pipe_id.map(|stream_id| (stream_id, open.pipe_write))
    }
}

#[cfg(test)]
mod tests {
    use super::{FileHandle, FileHandleCap};

    #[test]
    fn duplicated_stream_handles_share_native_options() {
        let source = FileHandle::new_pipe_read(usize::MAX);
        let duplicate = source.duplicate();
        source.open.lock().io_options = mnu_abi::HANDLE_OPTION_NONBLOCKING;
        assert_eq!(
            duplicate.open.lock().io_options,
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        );
    }
}
