---
title: syscall 入口
permalink: /docs/interrupts/syscall/
---

# syscall 入口

syscall は、ユーザー空間からカーネルへ入る速い入口です。

## 構成

- `src/interrupt/syscall.rs` が MSR を設定する
- `src/syscall/syscall_entry.rs` が実際の入口アセンブリを持つ
- `src/syscall/mod.rs` が振り分けを行う

## 入口でやること

- ユーザースタックを退避する
- カーネルスタックへ切り替える
- 引数を保存する
- 必要なら KPTI のために CR3 を切り替える

## 開発者向け

syscall を追加するときは、入口だけでなく、ユーザーコピー、権限、戻り値の errno 体系も必ず確認してください。
