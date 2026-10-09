/// Overlays only the intersection of two checked byte ranges.
pub(crate) fn copy_overlap(
    output_offset: u64,
    output: &mut [u8],
    cached_offset: u64,
    cached: &[u8],
) -> Result<(), ()> {
    let output_end = output_offset.checked_add(output.len() as u64).ok_or(())?;
    let cached_end = cached_offset.checked_add(cached.len() as u64).ok_or(())?;
    let start = output_offset.max(cached_offset);
    let end = output_end.min(cached_end);
    if start < end {
        let destination = (start - output_offset) as usize;
        let source = (start - cached_offset) as usize;
        let count = (end - start) as usize;
        output[destination..destination + count].copy_from_slice(&cached[source..source + count]);
    }
    Ok(())
}
