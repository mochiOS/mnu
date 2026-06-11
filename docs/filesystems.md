# ファイルシステム

このカーネルは、複数の層でファイルを扱います。

- 起動時に読む initfs
- 起動時や永続配置で読む rootfs
- 実行時に使う kmod backend
- syscall から見える FD ベースの API

## まず読むページ

- [initfs と rootfs](./filesystems/initfs.md)
- [kmod](./filesystems/kmod.md)

## 関連ファイル

- [`src/init/fs.rs`](../src/init/fs.rs)
- [`src/syscall/fs.rs`](../src/syscall/fs.rs)
- [`src/kmod/mod.rs`](../src/kmod/mod.rs)
