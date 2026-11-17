//! Validate a retained kernel buffer before publishing a physical span.
//! Translation does not pin memory; the caller owns its mapping throughout use.
pub(crate) fn contiguous_address(
    address: u64,
    length: usize,
    mut translate: impl FnMut(u64) -> Option<u64>,
) -> Option<u64> {
    if length == 0 {
        return None;
    }
    address.checked_add(u64::try_from(length).ok()? - 1)?;
    let physical = translate(address)?;
    physical.checked_add(u64::try_from(length).ok()? - 1)?;
    if physical & 4095 != address & 4095 {
        return None;
    }
    let mut offset = 4096 - (address & 4095);
    while offset < length as u64 {
        if translate(address + offset)? != physical + offset {
            return None;
        }
        offset = offset.checked_add(4096)?;
    }
    Some(physical)
}

#[cfg(test)]
mod tests {
    use super::contiguous_address;
    #[test]
    fn unaligned_kernel_views_resolve_across_every_page() {
        let base = 0xffff_8000_0040_0011;
        let mut visited = Vec::new();
        assert_eq!(contiguous_address(base, 8192, |address| {
            visited.push(address);
            Some(address - 0xffff_8000_0000_0000)
        }), Some(0x0040_0011));
        assert_eq!(visited, [base, base + 4079, base + 8175]);
    }
    #[test]
    fn missing_noncontiguous_or_misaligned_mappings_are_not_published() {
        for fault in 0..3 {
            assert_eq!(contiguous_address(0x1011, 8192, |address| {
                if fault == 2 { return Some(address + 1); }
                if address == 0x3000 {
                    return if fault == 0 { None } else { Some(0x5000) };
                }
                Some(address)
            }), None);
        }
    }
    #[test]
    fn zero_and_overflowing_spans_fail_before_publication() {
        assert_eq!(contiguous_address(4096, 0, |_| panic!("no translation")), None);
        assert_eq!(contiguous_address(u64::MAX, 2, |_| panic!("no translation")), None);
        assert_eq!(contiguous_address(4096, 8192, |_| Some(u64::MAX - 4095)), None);
    }
}
