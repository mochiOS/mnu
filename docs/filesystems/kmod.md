---
title: kmod
permalink: /docs/filesystems/kmod/
---

# kmod

`kmod` は、カーネルモジュール `cext` を読み込む仕組みです。

## 流れ

1. `/Modules` を列挙する
2. `modules.sha256` で hash を確認する
3. `cext` を読む
4. 依存関係を確認する
5. `mochi_module_init` を呼ぶ
6. disk や fs の ops を登録する

## 何のためにあるか

カーネル本体を大きくしすぎず、実装を差し替えられるようにするためです。

## 関連ファイル

- `src/kmod/mod.rs`
- `src/kmod/registry.rs`
