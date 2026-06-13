# 🛡️ RE-Argo: CLI-Native RE + Malware-Triage Toolkit

`re-argo` は、CLI ネイティブのリバースエンジニアリング＋マルウェアトリアージ・ツールキットです。出発点は **NSA Ghidra** のコア解析エンジンを Rust で再実装することでしたが、その上に独自のマルウェア家族判定（imphash / TLSH / RichHash）、能力検出（Capa スタイル）、IoC 抽出、YARA-lite、FLOSS-lite、パッカー識別、CWE 脆弱性パターン検出、ROP/JOP/COP ガジェット探索、Authenticode 署名解析、埋め込みファイル検出などの層を積み重ね、独立した**マルウェア解析ワークベンチ**へと成長しました。GUI を持たず、CLI とライブラリと AI エージェント（MCP）から直接操作することを設計の中心に置いています。

> 🚢 **Argo** は未知の海へ漕ぎ出した神話の船。RE-Argo は、未知のバイナリへ持ち込む計器です。**RE** = Reverse Engineering。

---

## 🎯 プロジェクトのミッション

本プロジェクトは、Ghidra の強力な解析理論（P-code や SLEIGH 言語）を継承しつつ、現代的なプログラミング言語である Rust を採用することで、以下の価値を提供することを目指しています。

1.  **高性能・安全**: Rust のメモリ安全性と並列処理性能を活かした、高速かつ堅牢な解析基盤。
2.  **CLI / Library First**: GUI に依存せず、CI/CD パイプラインや他のツールからライブラリとして容易に統合可能。
3.  **AI エージェント・ファースト**: Model Context Protocol (MCP) を介して Claude Code などの AI ホストへ直接組み込み可能。
4.  **ポータブル**: 単一のバイナリとして動作し、複雑な Java 環境のセットアップを不要に。

---

## ✨ 主要な機能

### 解析コア（Ghidra スタイル）

#### 1. 多様なプラットフォーム対応
*   **バイナリ形式**: ELF, PE（.pdata / TLS コールバック / IAT / .rsrc VS_VERSIONINFO / Rich Header）, Mach-O（ObjC クラス / メソッド / ivar / プロトコル）, COFF, Raw Binary
*   **アーキテクチャ**: x86/x64, ARM/AArch64, RISC-V, MIPS, PowerPC, SPARC（計 6 種）
*   **デバッグ情報**: DWARF（関数 / 型 / 引数 / 行番号 / ソースプレート）, PDB（型情報 / ヘッダー）の統合

#### 2. 強力な解析パイプライン (68 アナライザー)
*   関数の自動識別（再帰下降＋リニアスイープ）、312 エントリのシグネチャ DB（libc / POSIX / Win32 / libstdc++）、CRT パターン認識。
*   VSA（値集合解析）＋マルチブロック定数トラッカー、RTTI / VTable 復元、呼び出し規約の推定。
*   anti-debug / crypto / loop / exception / wrapper / no-return 伝播、BN スタイルのタグ分類、ホット関数検出、相互参照 (XREFs) の自動構築。

#### 3. P-code IR とエミュレーション
*   命令を 74 種類のオペコードからなる中間表現 (P-code) にリフト。
*   P-code ベースのフルエミュレータを搭載し、実行時の挙動をシミュレーション可能。
*   GDB RSP プロトコル（クライアント＋サーバ）、ブレークポイント、ウォッチポイント、syscall エミュレーション、状態スナップショット。

#### 4. 高度な逆コンパイラ
*   SSA (静的単一代入) 形式への変換と制御フロー解析。
*   6 つの最適化パス（DCE / 定数畳み込み / 伝播 / 強度低減 / 代数簡約 / CSE）によるコードの構造化。
*   構造体 / 配列の型復元、テイント解析。
*   C 言語および Rust 形式の疑似コード出力に対応し、**インライン注釈 + シグネチャ対応のコールレンダリング**付き（`printf@plt()` ではなく `printf("hi %d", 42)`）。

### マルウェアトリアージ層（RE-Argo の独自性）

*   **ワンスクリーン・トリアージ**: `triage` がフルパイプラインを実行し、形式 / アーキ / 識別子 / ハッシュ / パッカー / capa / CWE / IoC / タグ数を 1 枚のレポートに集約。
*   **家族クラスタリング**: imphash, TLSH（内容ファジー）, RichHash（MSVC ツールチェイン）を `info` / `triage` で提示。`tlsh-diff` で類似度比較。
*   **能力検出**: 20 ルールの Capa スタイルエンジンが imports / strings / tags にマッチ。
*   **YARA-lite**: YARA ルールのストリクトサブセット（テキスト＋ワイルドカード hex、ブール条件、`N of them`）をパース＆マッチ。
*   **FLOSS-lite**: XOR / ROL / ADD の難読化文字列ブルートフォースデコーダ。
*   **IoC 抽出**: URL / IPv4 / IPv6 / email / レジストリキー / named-pipe / mutex / posix-path / win-path / ETH / BTC / user-agent / ドメインの 13 種分類。
*   **パッカー識別**: DIE / PEiD スタイルの署名で UPX / ASPack / Themida / VMProtect / MEW / FSG / PECompact / NSPack / Mpress / Yoda ほかを識別。
*   **CWE 脆弱性パターン**: 危険な API を呼ぶ関数に CWE id（78 / 120 / 134 / 242 / 330 / 426 / 676）を付与。
*   **セクション異常**: RWX / 書き込み可能コード / パッカー形状のレイアウト検出。
*   **Authenticode**: PE のコード署名の有無 + CN= / O= サブジェクトのヒューリスティック抽出。
*   **エントロピー**: セクション別 Shannon エントロピー + パッカー閾値フラグ。
*   **ROP / JOP / COP ガジェット**: x86 / x64 のガジェットファインダー（ROPgadget 形式出力）。
*   **埋め込みファイル**: Binwalk-lite による ELF / PE / Mach-O / ZIP / GZIP / 7z / PNG / JPEG / PDF / SQLite リソースの走査。

---

## 🏗️ ソフトウェア・アーキテクチャ

プロジェクトは 10 個の独立したクレートで構成されており、疎結合で再利用性の高い設計となっています。内部クレートは `gr-*` の名前を保持し、公開バイナリは `re-argo` です。

| クレート名 | 役割 |
| :--- | :--- |
| `gr-core` | アドレスモデル、P-code IR（74 オペコード）定義、基本データ型 |
| `gr-loader` | バイナリのロード（ELF / PE / Mach-O / COFF / raw）、DWARF/PDB 解析、リロケーション、ハッシュ |
| `gr-arch` | 6 アーキテクチャの仕様定義（.cspec / .pspec / .ldefs）、アセンブラ |
| `gr-program` | プログラムモデル（シンボル、参照、コメント、**タグ**、コールレンダリング、undo/redo、diff、SARIF） |
| `gr-analysis` | 68 アナライザー（関数探索、シグネチャ、VSA、CRT パターン、タグ、capa / yara / floss / packer / vuln / ioc / authenticode / TLSH / imphash / richhash / rop …） |
| `gr-lift` | 機械語から P-code への変換 (マルチアーキ Lifter) |
| `gr-emulator` | P-code エミュレータ、デバッガ基盤、GDB RSP |
| `gr-decompile` | SSA 構築、6 つの最適化パス、構造化、C / Rust 疑似コード生成（注釈付き） |
| `gr-sleigh` | SLEIGH 仕様ランタイム |
| `gr-cli` | 統合コマンドラインインターフェース（`re-argo` バイナリ、50+ サブコマンド） |

---

## 🚀 クイックスタート

### ビルド
```bash
cargo build --release   # バイナリは target/release/re-argo に生成
```

### バイナリ解析の実行
```bash
# ワンスクリーンのマルウェアトリアージ — 最初に打つ一手
target/release/re-argo triage <binary>

# 名前 / シンボル / コメント / タグを横断検索
target/release/re-argo find <binary> "main"

# 逆コンパイル (疑似コードの表示)
target/release/re-argo decompile <binary> --address <hex_addr>

# IoC（URL / IP / レジストリキー / …）抽出
target/release/re-argo ioc <binary>

# コールグラフの生成 (DOT形式)
target/release/re-argo callgraph <binary> --dot
```

> 全コマンド・全フラグ・出力形式・複数コマンドのレシピは [CLAUDE.md](CLAUDE.md)（AI / オペレータ向け CLI リファレンス）を参照してください。HTML 版のサイトは [`docs/`](docs/index.html) にあります。

---

## 🛠️ 技術スタック
*   **Language**: Rust (Edition 2024)
*   **Binary Parsing**: `goblin`, `object`
*   **Instruction Decoding**: `iced-x86`（x86）, `capstone`（ARM / MIPS / PPC / SPARC / RISC-V）
*   **Debug Info**: `gimli` (DWARF)
*   **Graphs**: `petgraph`（CFG / コールグラフ、Tarjan SCC、支配木）
*   **Format Handling**: `serde`, `quick-xml`, `flate2`
*   **Errors**: `thiserror`

---

## 📄 ライセンス
本プロジェクトは [Apache License 2.0](LICENSE) の下で公開されています。
