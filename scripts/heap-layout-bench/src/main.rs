use linked_list_allocator::LockedHeap;
use std::{
    alloc::{GlobalAlloc, Layout},
    time::Instant,
};
fn measure(padded: bool) {
    let mut arena = vec![0u128; 1024 * 1024];
    let heap = LockedHeap::empty();
    unsafe {
        heap.lock()
            .init(arena.as_mut_ptr().cast(), arena.len() * 16);
    }
    let mut allocations = Vec::with_capacity(24000);
    let start = Instant::now();
    for _ in 0..12000 {
        // Real allocator payloads can be 8 modulo its 16-byte alignment.
        for size in [136, 96] {
            let raw = Layout::from_size_align(size, 16).unwrap();
            let layout = if padded { raw.pad_to_align() } else { raw };
            let pointer = unsafe { heap.alloc(layout) };
            assert!(!pointer.is_null());
            assert_eq!(pointer as usize % 16, 0);
            unsafe {
                pointer.write_bytes(0xA5, layout.size());
            }
            allocations.push((pointer, layout));
        }
    }
    let elapsed = start.elapsed();
    let used = heap.lock().used();
    let footprint = allocations
        .iter()
        .map(|(p, l)| *p as usize + l.size())
        .max()
        .unwrap()
        - arena.as_ptr() as usize;
    for (pointer, layout) in allocations.into_iter().rev() {
        assert!(
            unsafe { std::slice::from_raw_parts(pointer, layout.size()) }
                .iter()
                .all(|v| *v == 0xA5)
        );
        unsafe {
            heap.dealloc(pointer, layout);
        }
    }
    assert_eq!(heap.lock().used(), 0);
    println!(
        "padded={padded}: {} allocations in {:?}, raw bytes={used}, occupied address span={footprint}; alignment, contents, and complete reclamation PASS",
        24000, elapsed
    );
}
fn main() {
    measure(false);
    measure(true);
}
