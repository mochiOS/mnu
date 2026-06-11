---
title: IDT
permalink: /docs/interrupts/idt/
---

# IDT

IDT は、割り込み番号と処理関数を対応づける表です。

## このカーネルでの登録

- ゼロ除算
- デバッグ例外
- NMI
- ブレークポイント
- オーバーフロー
- 無効命令
- ページフォルト
- ダブルフォルト
- keyboard / mouse / timer IRQ
- `int 0x80` の syscall 入口

## ユーザー例外とカーネル例外

ユーザー空間で起きた例外は、対象プロセスを止める方向で扱います。
カーネル空間で起きた例外は、より重い障害として扱います。

## 関連ファイル

- `src/interrupt/idt.rs`
- `src/mem/gdt.rs`
