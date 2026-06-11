# 開発者向けメモ

このページは、コード変更をするときの入口です。

## 最初に見る順番

1. [`src/entry.rs`](../src/entry.rs)
2. [`src/kernel.rs`](../src/kernel.rs)
3. [`src/init/mod.rs`](../src/init/mod.rs)
4. [`src/mem/mod.rs`](../src/mem/mod.rs)
5. [`src/interrupt/idt.rs`](../src/interrupt/idt.rs)
6. [`src/task/context.rs`](../src/task/context.rs)
7. [`src/task/scheduler.rs`](../src/task/scheduler.rs)
8. [`src/syscall/syscall_entry.rs`](../src/syscall/syscall_entry.rs)
9. [`src/syscall/mod.rs`](../src/syscall/mod.rs)

## 変更時の注意

- ユーザー空間ポインタは直接信用しない
- syscall を増やしたら `dispatch()` だけでなく権限も確認する
- context switch は `TSS.RSP0` と syscall RSP に影響する
- `exec` は ASLR、TLS、stack、capability に触る
- `FD_CLOEXEC` は `exec` 時の資源整理に関係する

## 失敗しやすい場所

- page table の切り替え
- syscall 入口と出口
- 割り込み中の context switch
- heap と stack の寿命
- service 起動時の capability 付与

## テストについて

この crate では `cargo test` は使いません。
QEMU か実機相当の起動経路で確認します。

## 追加で書けるもの

- syscall 一覧
- process lifecycle
- thread state 遷移
- initfs / rootfs の仕様
- `cext` のフォーマット
