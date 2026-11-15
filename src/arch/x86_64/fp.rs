//! Retained x87/SSE state for the existing x86 upcall return path.
use super::context::FxSaveArea;
use super::exception::UserUpcallContext;

#[derive(Clone, Copy)]
pub(crate) struct State {
    inner: FxSaveArea,
}

impl State {
    pub(crate) const fn initial() -> Self {
        Self {
            inner: FxSaveArea::initial(),
        }
    }

    pub(crate) fn capture(&mut self, _context: &UserUpcallContext) {
        // The area is initialized when the Thread is created, preserving the
        // existing capture timing rather than clearing live SSE registers here.
        self.inner.save_current();
    }

    pub(crate) fn snapshot_bytes(&self) -> [u8; 512] {
        self.inner.snapshot_bytes()
    }

    pub(crate) fn with_user_context(
        &self,
        _context: &UserUpcallContext,
        bytes: [u8; 512],
    ) -> Option<Self> {
        // Preserve the kernel-captured MXCSR mask and reserved-byte filtering.
        Some(Self {
            inner: self.inner.with_user_bytes(bytes)?,
        })
    }

    pub(crate) fn restore_context(&self, context: UserUpcallContext) -> UserUpcallContext {
        self.inner.restore_current();
        context
    }
}
