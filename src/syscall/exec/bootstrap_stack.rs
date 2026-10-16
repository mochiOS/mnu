//! Fresh native bootstrap memory. There are no vectors, text, auxiliary keys
//! or executable-name conventions in this entry state. A runtime may interpret
//! the empty writable entry page according to its own startup convention.
use super::InitialUserStack;
use mnu_abi::status::Error;

pub(super) fn empty(stack_end: u64, pages: usize) -> Result<InitialUserStack, Error> {
    let bytes = u64::try_from(pages)
        .ok()
        .and_then(|pages| pages.checked_mul(4096))
        .ok_or(Error::InvalidArgument)?;
    let base = stack_end
        .checked_sub(bytes)
        .filter(|&base| base != 0)
        .ok_or(Error::InvalidArgument)?;
    // Leave at least one page below the empty entry page for the runtime's
    // first native calls; reject malformed boot configuration, not underflow.
    if pages < 2 || stack_end & 4095 != 0 || stack_end > (1u64 << 47) {
        return Err(Error::InvalidArgument);
    }
    Ok(InitialUserStack {
        stack_base_vaddr: base,
        stack_end_vaddr: stack_end,
        initial_rsp: stack_end - 4096,
        page_data: crate::util::object_snapshot::zeroed_native(4096)?,
    })
}
