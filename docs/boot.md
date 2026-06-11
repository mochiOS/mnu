---
title: 起動
permalink: /docs/boot/
---

# 起動

起動の役割は、カーネルが動くための前提をそろえることです。

## 流れ

1. ブートローダーがカーネルを呼ぶ
2. `src/entry.rs` が `BootInfo` を整える
3. `src/kernel.rs` がカーネル本体へ入る
4. `src/init/mod.rs` が各初期化を順番に実行する
5. `core.service` を起動する
6. カーネルはスケジューラへ引き継ぐ

## `src/entry.rs`

ここは本当に入口だけです。

- カーネルヒープのアドレスを設定する
- `initfs` と `rootfs` のイメージを渡す
- `kernel_entry()` を呼ぶ

## `src/kernel.rs`

ここでは、カーネルの論理的な起動と、SMP の解放が行われます。

- `kernel_entry()` が初期化結果を受け取る
- `create_kernel_proc()` でカーネル用 process と thread を作る
- `kernel_main()` で `core.service` を起動する
- 以後は idle loop に入る

## なぜ順番が大事か

初期化は順番を間違えると壊れます。

- メモリより前に allocator は使えない
- IDT がない状態で例外を受けると困る
- PIT より先に割り込みを有効化すると危険
- syscall MSR より前に syscall 入口は使えない

## 関連ファイル

- `src/init/mod.rs`
- `src/init/fs.rs`
- `src/result.rs`
