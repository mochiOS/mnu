//! Base FP/SIMD retained from the exception image, before Rust can clobber
//! caller-saved vector registers. FPCR/FPSR travel in the native user context;
//! the 512-byte extension payload contains the 32 little-endian Q registers.
use super::exception::UserUpcallContext;

#[derive(Clone, Copy)]
pub(crate) struct State {
    simd: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

impl State {
    pub(crate) const fn initial() -> Self {
        Self {
            simd: [0; 32],
            fpcr: 0,
            fpsr: 0,
        }
    }

    pub(crate) fn capture(&mut self, context: &UserUpcallContext) {
        self.simd = context.simd;
        self.fpcr = context.fpcr;
        self.fpsr = context.fpsr;
    }

    pub(crate) fn snapshot_bytes(&self) -> [u8; 512] {
        let mut bytes = [0; 512];
        for (slot, value) in bytes.chunks_exact_mut(16).zip(self.simd) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn with_user_context(
        &self,
        context: &UserUpcallContext,
        bytes: [u8; 512],
    ) -> Option<Self> {
        if !context.valid() {
            return None;
        }
        let mut state = Self::initial();
        state.fpcr = context.fpcr;
        state.fpsr = context.fpsr;
        for (register, bytes) in state.simd.iter_mut().zip(bytes.chunks_exact(16)) {
            *register = u128::from_le_bytes(bytes.try_into().ok()?);
        }
        Some(state)
    }

    /// Prepare the complete return image. The exception return or validated
    /// EL0 entry loads hardware only after the rest of the kernel work ends.
    pub(crate) fn restore_context(&self, mut context: UserUpcallContext) -> UserUpcallContext {
        context.simd = self.simd;
        context.fpcr = self.fpcr;
        context.fpsr = self.fpsr;
        context
    }
}
