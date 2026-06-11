---
title: 安全なユーザーアクセス
permalink: /docs/syscalls/user-access/
---

# 安全なユーザーアクセス

ユーザー空間のポインタは、そのままでは信用できません。

## このカーネルの方針

- null を拒否する
- ユーザー空間の範囲か確認する
- 実際にマップされているか確認する
- `copy_from_user` と `copy_to_user` を通して扱う

## 何が危険か

ユーザーが渡したアドレスを直接読むと、未マップ領域や不正領域でカーネルが落ちます。
そのため、`validate_user_ptr()` が基礎になります。

## 関連ファイル

- `src/syscall/mod.rs`
- `src/mem/paging.rs`
