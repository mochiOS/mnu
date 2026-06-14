# cext packages

Each cext directory contains a `cext.toml` manifest.

Supported `kind` values:

- `built-in`: compiled into the kernel binary. No file is copied into `initfs/Modules`.
- `module`: packaged as a `.cext` file and placed under `initfs/Modules/`.

For `module`, the manifest should also provide an artifact path that the build/run step can copy into the initfs image.
