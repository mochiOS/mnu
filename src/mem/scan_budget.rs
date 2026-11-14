//! Bound discovery work while a shared VM lock disables local interrupts.
//! Charge inspected entries/intervals, never the size of a virtual reservation.
pub(crate) struct Budget(usize);

impl Budget {
    pub(crate) const fn new() -> Self {
        Self(16_384)
    }

    pub(crate) fn take(&mut self, amount: usize) -> bool {
        match self.0.checked_sub(amount) {
            Some(remaining) => {
                self.0 = remaining;
                true
            }
            None => {
                self.0 = 0;
                false
            }
        }
    }
}
