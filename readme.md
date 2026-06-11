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
cargo build --release
```

## Running
To run the mnu kernel, you can use QEMU. After building the kernel, you can run it with the following command:

```bash
cargo run --release
```
