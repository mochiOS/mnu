---
title: GDT と TSS
permalink: /docs/memory/gdt-tss/
---

# GDT と TSS

GDT と TSS は、x86_64 カーネルの土台です。

## GDT

GDT は、コードセグメントやデータセグメントの定義を持ちます。

このカーネルでは次を登録します。

- kernel code
- kernel data
- user data
- user code
- TSS

## TSS

TSS は、特に次で重要です。

- ダブルフォルト用の IST
- user から kernel に戻るときの RSP0

## 重要な理由

長モードではセグメントの存在感は下がりますが、TSS は今でも必要です。

例外処理とユーザーモード復帰の安全性に直結します。

## 関連ファイル

- `src/mem/gdt.rs`
- `src/mem/tss.rs`
