# メモリ

このカーネルのメモリ管理は、3 層で見ると理解しやすいです。

- 物理メモリの管理
- 仮想メモリの管理
- カーネルヒープとユーザー領域の管理

## まずは分けて考える

物理メモリは「どの実アドレスを使うか」です。
仮想メモリは「その実アドレスをどの仮想アドレスに見せるか」です。

この 2 つを分けることで、カーネルは安全に自分の空間を保てます。

## 見るべきページ

- [ページング](./memory/paging.md)
- [ヒープ](./memory/heap.md)
- [GDT と TSS](./memory/gdt-tss.md)

## 関連ファイル

- [`src/mem/mod.rs`](../src/mem/mod.rs)
- [`src/mem/frame.rs`](../src/mem/frame.rs)
- [`src/mem/paging.rs`](../src/mem/paging.rs)
- [`src/mem/allocator.rs`](../src/mem/allocator.rs)
- [`src/mem/gdt.rs`](../src/mem/gdt.rs)
- [`src/mem/tss.rs`](../src/mem/tss.rs)
- [`src/mem/user.rs`](../src/mem/user.rs)
