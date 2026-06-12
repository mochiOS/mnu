<div align="center">
    <h1>The mnu kernel</h1>
</div>

The mnu kernel is a [mochiOS](https://github.com/mochiOS/mochiOS) kernel.

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
cargo run --release
```

## Design Principles
- The mnu kernel is not the place to directly implement OS features.
- Policy decisions live in service code; the kernel performs final enforcement only.
- Filesystems and disks are treated as cext boundaries, not kernel features.
- Capabilities are split into `KernelCapability` and `UserCapability`.
- `UserCapability` applies to applications and normal services as a high-level permission.
- `KernelCapability` is a low-level permission the kernel enforces directly.
- `KernelCapability` should bind to concrete kernel objects such as process handles, IPC endpoints, VM objects, MMIO regions, IRQ lines, cext instances, and device handles.
- IPC should center on endpoints, not raw thread IDs.
- Failures should be contained inside the kernel boundary, including process kill, cext stop, endpoint close, capability revoke, MMIO unmap, IRQ release, waiter wake, and audit logging.
- Anything that can be implemented in a service or cext should stay out of the kernel.
