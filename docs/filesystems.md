---
title: ファイルシステム
permalink: /docs/filesystems/
---

# ファイルシステム

このカーネルは、複数の層でファイルを扱います。

- 起動時に読む initfs
- 起動時や永続配置で読む rootfs
- 実行時に使う kmod backend
- syscall から見える FD ベースの API

## まず読むページ

- [initfs と rootfs](/docs/filesystems/initfs/)
- [kmod](/docs/filesystems/kmod/)

## 関連ファイル

- `src/init/fs.rs`
- `src/syscall/fs.rs`
- `src/kmod/mod.rs`
