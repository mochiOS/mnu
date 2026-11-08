//! Exercise actual kernel bounds/handler code with a small address-space model.
#![allow(dead_code)]
use mnu_abi::status::Error;
use std::cell::RefCell;
#[path = "../../../src/syscall/process_stack.rs"]
mod query_impl;
#[path = "../../../src/mem/user_stack.rs"]
pub(crate) mod stack_impl;
#[derive(Clone)]
struct State {
    present: bool,
    bottom: u64,
    top: u64,
    written: Vec<u8>,
}
thread_local! { static STATE: RefCell<State> = const { RefCell::new(State { present:true, bottom:0x7000_007f_0000, top:0x7000_0080_0000, written:Vec::new() }) }; }
mod security {
    pub fn current_process_id() -> Option<u64> {
        super::STATE.with(|s| s.borrow().present.then_some(42))
    }
}
fn is_canonical_user_range(base: u64, length: u64) -> bool {
    base >= 4096
        && base
            .checked_add(length)
            .is_some_and(|v| v <= 0x0000_8000_0000_0000)
}
fn copy_to_user_native(output: u64, bytes: &[u8]) -> Result<(), Error> {
    if output != 123 {
        return Err(Error::InvalidAddress);
    }
    STATE.with(|s| s.borrow_mut().written = bytes.to_vec());
    Ok(())
}
mod task {
    pub struct Region;
    impl Region {
        pub fn end(&self) -> Option<u64> {
            Some(0)
        }
        pub fn start(&self) -> u64 {
            0
        }
    }
    pub struct Process {
        pub bottom: u64,
        pub top: u64,
    }
    impl Process {
        pub fn stack_bottom(&self) -> u64 {
            self.bottom
        }
        pub fn stack_top(&self) -> u64 {
            self.top
        }
        pub fn page_table(&self) -> Option<u64> {
            Some(1)
        }
        pub fn memory_regions(&self) -> &[Region] {
            &[]
        }
        pub fn find_mmio_mapping_by_addr(&self, _: u64, _: u64) -> Option<()> {
            None
        }
        pub fn find_dma_buffer_by_addr(&self, _: u64, _: u64) -> Option<()> {
            None
        }
    }
    pub fn with_process<T>(caller: u64, f: impl FnOnce(&Process) -> T) -> Option<T> {
        assert_eq!(
            caller, 42,
            "the handler must derive its own process identity"
        );
        super::STATE.with(|s| {
            let s = s.borrow();
            s.present.then(|| {
                f(&Process {
                    bottom: s.bottom,
                    top: s.top,
                })
            })
        })
    }
}
mod mem {
    pub(crate) use crate::stack_impl as user_stack;
    pub mod paging {
        pub fn is_user_range_occupied_in_table(_: u64, _: u64, _: u64) -> bool {
            false
        }
    }
}
#[test]
fn record_layout_and_discriminant_are_stable() {
    assert_eq!(size_of::<mnu_abi::ProcessInitialStackInfo>(), 24);
    assert_eq!(align_of::<mnu_abi::ProcessInitialStackInfo>(), 8);
    assert_eq!(mnu_abi::SyscallNumber::ProcessInitialStackRead as u64, 706);
}
#[test]
fn mapped_bytes_and_guard_are_reported_without_inventing_capacity() {
    let top = 0x7000_0000;
    let bottom = top - 16 * 4096;
    let b = stack_impl::bounds(bottom, top, 4096, |_, _| false).unwrap();
    assert_eq!(b.lower_bound, top - stack_impl::MAX_INITIAL_STACK_BYTES);
    assert_eq!(b.committed_lower_bound, bottom);
    assert_eq!(b.upper_bound, top - 4096);
    let b = stack_impl::bounds(bottom, top, 4096, |_, _| true).unwrap();
    assert_eq!(b.lower_bound, bottom);
    let committed = top - 2 * stack_impl::MAX_INITIAL_STACK_BYTES;
    assert_eq!(
        stack_impl::bounds(committed, top, 4096, |_, _| panic!(
            "no uncommitted extension exists"
        ))
        .unwrap()
        .lower_bound,
        committed
    );
}
#[test]
fn malformed_metadata_is_rejected_without_collision_queries() {
    for (bottom, top, page) in [
        (0, 8192, 4096),
        (4096, 8192, 4096),
        (4097, 16384, 4096),
        (4096, 16385, 4096),
        (4096, 16384, 0),
        (4096, 16384, 3),
    ] {
        assert!(stack_impl::bounds(bottom, top, page, |_, _| panic!("invalid metadata")).is_none());
    }
}
#[test]
fn binary_search_matches_a_linear_collision_oracle() {
    const PAGE: u64 = 4096;
    let top = 0x7000_0000;
    let committed = top - 16 * PAGE;
    let floor = top - stack_impl::MAX_INITIAL_STACK_BYTES;
    let count = (committed - floor) / PAGE;
    let mut seed = 1u64;
    for _ in 0..400 {
        let mut blocked = Vec::new();
        for _ in 0..24 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            blocked.push(floor + (seed % count) * PAGE);
        }
        let expected = (0..count)
            .map(|n| floor + n * PAGE)
            .rev()
            .find(|p| blocked.contains(p))
            .map_or(floor, |p| p + PAGE);
        let info = stack_impl::bounds(committed, top, PAGE, |base, len| {
            blocked.iter().any(|p| base < *p + PAGE && *p < base + len)
        })
        .unwrap();
        assert_eq!(info.lower_bound, expected);
        assert!(info.lower_bound <= committed);
    }
}
#[test]
fn self_query_preserves_native_errors_and_encodes_exact_record() {
    assert_eq!(query_impl::read(123, 23), Error::InvalidArgument.into_raw());
    assert_eq!(query_impl::read(123, 25), Error::InvalidArgument.into_raw());
    assert!(STATE.with(|s| s.borrow().written.is_empty()));
    assert_eq!(query_impl::read(0, 24), Error::InvalidAddress.into_raw());
    assert_eq!(query_impl::read(123, 24), 0);
    let data = STATE.with(|s| s.borrow().written.clone());
    assert_eq!(data.len(), 24);
    let values: Vec<_> = data
        .chunks_exact(8)
        .map(|v| u64::from_ne_bytes(v.try_into().unwrap()))
        .collect();
    assert_eq!(
        values,
        vec![0x7000_0000_0000, 0x7000_007f_0000, 0x7000_007f_f000]
    );
    STATE.with(|s| s.borrow_mut().present = false);
    assert_eq!(query_impl::read(123, 24), Error::NotReady.into_raw());
}
