//! Self-only initial-stack observation; no process lookup or mapping grant.

pub(crate) fn read(output: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    if length != core::mem::size_of::<mnu_abi::ProcessInitialStackInfo>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let result = (|| {
        let caller = super::security::current_process_id().ok_or(Error::NotReady)?;
        let info = crate::task::with_process(caller, |process| {
            crate::mem::user_stack::bounds(
                process.stack_bottom(),
                process.stack_top(),
                4096,
                |base, bytes| crate::mem::user_stack::collides(process, base, bytes),
            )
        })
        .flatten()
        .ok_or(Error::NotReady)?;
        if !super::is_canonical_user_range(info.lower_bound, info.upper_bound - info.lower_bound) {
            return Err(Error::NotReady);
        }
        // Explicit bytes avoid padding disclosure and unaligned typed writes.
        let mut bytes = [0; core::mem::size_of::<mnu_abi::ProcessInitialStackInfo>()];
        for (index, value) in [
            info.lower_bound,
            info.committed_lower_bound,
            info.upper_bound,
        ]
        .iter()
        .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
        }
        super::copy_to_user_native(output, &bytes)
    })();
    result.map(|_| 0).unwrap_or_else(Error::into_raw)
}
