# Guarded heap layout microbenchmark

Run with the host toolchain from the workspace root:

```sh
cargo run --offline --release --manifest-path core/scripts/heap-layout-bench/Cargo.toml
```

This compares unpadded and padded raw layout sizes using the actual
`linked_list_allocator` used by the kernel. Alternating 136-byte and 96-byte
requests at 16-byte alignment exposes the repeated 24-byte leading fragments
created by unpadded allocations. Each run checks alignment, contents and full
reclamation. The occupied address span includes fragmentation; the allocator's
used-byte count alone does not.

The benchmark checks the allocation strategy, not the kernel's header checks,
canaries, quarantine, page mapper or interrupt paths. Native QEMU integration
checks are still required for the actual kernel change. Do not treat host
microbenchmark timings as OS launch-performance results.
