---
title: initfs と rootfs
permalink: /docs/filesystems/initfs/
---

# initfs と rootfs

initfs は、起動時にメモリへ置かれた read-only filesystem です。

## 役割

- 初期ファイルを読む
- 設定を読む
- 起動に必要な資源を提供する

rootfs は、より永続的な土台として使われます。

## 読み方

このカーネルでは、まず rootfs を見て、なければ initfs を見ます。

## 関連ファイル

- `src/init/fs.rs`
