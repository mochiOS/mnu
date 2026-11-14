<div align="center">
    <h1>The mnu kernel</h1>
</div>

The mnu kernel is an independent, capability-oriented kernel. Operating systems may build their
own user space and policy on top of its public ABI; mnu does not contain product-specific desktop,
application, package, or service policy.

## Building
To build the mnu kernel, you will need to have the following dependencies installed:
- [Rust](https://www.rust-lang.org/tools/install)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)
- [QEMU](https://www.qemu.org/download/)

once you have the dependencies installed, you can build the kernel by running the following command in the root directory of the project:

```bash
cargo build
```

## Running
To run the mnu kernel, you can use QEMU. After building the kernel, you can run it with the following command:

```bash
./scripts/runner.sh
```

## Design Principles
- The mnu kernel is not the place to directly implement OS features.
- Policy decisions live in service code; the kernel performs final enforcement only.
- Filesystems and disks are treated as cext boundaries, not kernel features.
- `KernelCapability` is a low-level permission the kernel enforces directly.
- Product policy and high-level permission semantics stay outside mnu.
- `KernelCapability` should bind to concrete kernel objects such as process handles, IPC endpoints, VM objects, MMIO regions, IRQ lines, cext instances, and device handles.
- IPC should center on endpoints, not raw thread IDs.
- Failures should be contained inside the kernel boundary, including process kill, cext stop, endpoint close, capability revoke, MMIO unmap, IRQ release, waiter wake, and audit logging.
- Anything that can be implemented in a service or cext should stay out of the kernel.

## Public Syscall ABI
The native ABI provides process/thread lifecycle, virtual memory, object
Handles and attenuation, endpoint IPC, address/deadline waits, execution
contexts, diagnostics, clocks and generic hardware authority primitives.

The authoritative syscall numbers and wire layouts are in
[`crates/abi/src/lib.rs`](crates/abi/src/lib.rs); implemented dispatch is in
[`src/syscall/mod.rs`](src/syscall/mod.rs). A declared/reserved ABI number is
not proof of an implemented operation: unsupported calls return `Unsupported`.
User image validation and construction live in `syscall/exec/image.rs`; CExt
loading uses the shared ELF64 parser under `elf/`.

High-frequency filesystem, GPU, network, GUI, and device operations are expected to flow through IPC, shared memory, and `memory_map` rather than dedicated syscalls.
