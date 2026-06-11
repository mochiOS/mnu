---
title: capability とポリシー
permalink: /docs/capabilities-policy/
---

# capability とポリシー

このカーネルでは、権限を capability で細かく分けます。

## capability

capability は「何ができるか」を表します。

例:

- `fs.read.all`
- `process.spawn`
- `ipc.server`
- `device.storage`
- `window.create`

## privilege との違い

- privilege は実行層の違い
- capability はできる操作の違い

この 2 つは同じではありません。

## ポリシー

`src/policy/mod.rs` は、どの process をどの privilege で起動するかを決めます。

ここでは、プロセス名、起動パス、親 process、service manager などを見ます。

## 開発者向け

新しい syscall やサービスを追加するときは、privilege だけでなく capability の付与経路も一緒に見直してください。

## 関連ファイル

- `src/capability/mod.rs`
- `src/policy/mod.rs`
- `src/syscall/block.rs`
