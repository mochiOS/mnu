use alloc::sync::Arc;

pub(crate) fn pin(table: u64) -> Result<super::root_lifetime::Pin, ()> {
    super::root_lifetime::pin_with(table, |state| Arc::try_new(state).map_err(|_| ()))
}
