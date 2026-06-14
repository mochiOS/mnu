# PlugKit

PlugKitはmnuカーネルにおいて、ユーザー空間で動作するドライバを作成するためのフレームワークです。
PlugKitを使用することで、ユーザー空間でドライバを実装し、カーネル空間のコードを最小限に保ちながら、デバイスドライバを開発できます。

## 提供する機能

PlugKitは、mnuのデバイスドライバを実装するための共通モデル、API、ライフサイクル、リソース管理、デバイスツリー、ドライバ照合機構を提供します。
mnuのドライバは、PlugKit上のPlugKitDriverとして実装されます。
PlugKitDriverは、特定のデバイスクラスやプロトコルに対応するドライバを表す共通モデルです。

PlugKitDriverは、次の処理を担当します。

- デバイスの検出結果に対する照合
- デバイスの初期化
- 必要なリソースの取得
- MMIO、IRQ、DMAなどの操作
- デバイスイベントの処理
- 上位serviceへ提供するinterfaceの登録
- デバイス停止時のクリーンアップ

PlugKitは、PlugKitDriverがカーネル内部構造へ直接アクセスしなくてもよいように、必要なAPIを提供します。

PlugKitDriverは、カーネルからケーパビリティに基づいて渡されたhandleを通じてデバイスやリソースを操作します。
これにより、ユーザー空間ドライバであっても、許可されていないデバイスやリソースへ直接アクセスできないようにします。

PlugKitDriverは、rootfsの/library/extensions/に配置します。
PlugKitDriverの形式は以下のとおりです。

```
/foo.driver
├─ about.toml
└─ entry.elf
```

about.tomlは、PlugKitDriverのメタデータを記述するファイルです。
entry.elfは、PlugKitDriverの実装を含むELF形式のバイナリファイルです。

メタデータの詳細はまだ未定です。