---
title: fs
permalink: /docs/syscalls/fs/
---

# fs

fs 系 syscall は、ファイルを開く、読む、書く、閉じる、一覧する、といった基本操作を担当します。

## このカーネルの特徴

- initfs と rootfs を統合して扱う
- 一部の path は special file として扱う
- FD テーブルは process ごとに持つ
- `CLOEXEC` を扱う

## 見るべき点

- path 解決
- special file の扱い
- persistent file と一時 file の分岐
- read-only 領域の保護

## 関連ファイル

- `src/syscall/fs.rs`
- `src/init/fs.rs`
- `src/task/fd_table.rs`
