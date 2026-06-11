# 割り込み

割り込みは、CPU が今の処理を止めて、例外やデバイス通知を処理する仕組みです。

## このカーネルが扱うもの

- CPU 例外
- PIC 経由の IRQ
- PIT タイマー
- syscall 入口

## まず読むページ

- [IDT](./interrupts/idt.md)
- [タイマー](./interrupts/timer.md)
- [syscall 入口](./interrupts/syscall.md)

## 関連ファイル

- [`src/interrupt/mod.rs`](../src/interrupt/mod.rs)
- [`src/interrupt/idt.rs`](../src/interrupt/idt.rs)
- [`src/interrupt/pic.rs`](../src/interrupt/pic.rs)
- [`src/interrupt/timer.rs`](../src/interrupt/timer.rs)
- [`src/interrupt/syscall.rs`](../src/interrupt/syscall.rs)
