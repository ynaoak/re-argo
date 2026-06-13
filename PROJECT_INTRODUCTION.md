# 🛡️ RE-Argo: CLI-Native RE + Malware-Triage Toolkit

`re-argo` は、CLI ネイティブのリバースエンジニアリング＋マルウェアトリアージ・ツールキットです。出発点は **NSA Ghidra** のコア解析エンジンを Rust で再実装することでしたが、その上に独自のマルウェア家族判定（imphash / TLSH / RichHash）、能力検出（Capa）、IoC 抽出、YARA-lite、FLOSS-lite、パッカー識別、CWE 脆弱性パターン検出、ROP/JOP/COP ガジェット探索、Authenticode 署名解析などの層を積み重ね、独立した**マルウェア解析ワークベンチ**へと成長しました。GUI を持たず、CLI とライブラリと AI エージェント（MCP）から直接操作することを設計の中心に置いています。

## 🎯 プロジェクトのミッション

本プロジェクトは、Ghidra の強力な解析理論（P-code や SLEIGH 言語）を継承しつつ、現代的なプログラミング言語である Rust を採用することで、以下の価値を提供することを目指しています。

1.  **高性能・安全**: Rust のメモリ安全性と並列処理性能を活かした、高速かつ堅牢な解析基盤。
2.  **CLI / Library First**: GUI に依存せず、CI/CD パイプラインや他のツールからライブラリとして容易に統合可能。
3.  **ポータブル**: 単一のバイナリとして動作し、複雑な Java 環境のセットアップを不要に。

---

## ✨ 主要な機能

### 1. 多様なプラットフォーム対応
*   **バイナリ形式**: ELF, PE, Mach-O, COFF, Raw Binary
*   **アーキテクチャ**: x86/x64, ARM/AArch64, RISC-V, MIPS, PowerPC, SPARC
*   **デバッグ情報**: DWARF, PDB (型情報/ヘッダー) の統合

### 2. 強力な解析パイプライン (30+ アナライザー)
*   関数の自動識別、スタック解析、呼び出し規約の推定。
*   VTable の検出、文字列検索、相互参照 (XREFs) の自動構築。

### 3. P-code IR とエミュレーション
*   命令を 74 種類のオペコードからなる中間表現 (P-code) にリフト。
*   P-code ベースのフルエミュレータを搭載し、実行時の挙動をシミュレーション可能。

### 4. 高度な逆コンパイラ
*   SSA (静的単一代入) 形式への変換と制御フロー解析。
*   10 以上の最適化ルールによるコードの構造化。
*   C 言語および Rust 形式の疑似コード出力に対応。

---

## 🏗️ ソフトウェア・アーキテクチャ

プロジェクトは 10 個の独立したクレートで構成されており、疎結合で再利用性の高い設計となっています。

| クレート名 | 役割 |
| :--- | :--- |
| `gr-core` | アドレスモデル、P-code IR 定義、基本データ型 |
| `gr-loader` | バイナリのロード、DWARF/PDB 解析 |
| `gr-arch` | 各種プロセッサの仕様定義 (CSPEC/PSPEC) |
| `gr-program` | プログラムモデル（シンボル、参照、コメント管理） |
| `gr-analysis` | 30 種類の解析パスの実装 |
| `gr-lift` | 機械語から P-code への変換 (Lifter) |
| `gr-emulator` | P-code エミュレータ、デバッガ基盤 |
| `gr-decompile` | SSA 構築、データフロー解析、疑似コード生成 |
| `gr-sleigh` | SLEIGH 仕様ランタイム |
| `gr-cli` | 統合コマンドラインインターフェース |

---

## 🚀 クイックスタート

### ビルド
```bash
cargo build --release
```

### バイナリ解析の実行
```bash
# 全自動解析の実行
cargo run -- analyze <binary_path>

# 逆コンパイル (疑似コードの表示)
cargo run -- decompile <binary_path> --address <hex_addr>

# コールグラフの生成 (DOT形式)
cargo run -- callgraph <binary_path> --dot
```

---

## 🛠️ 技術スタック
*   **Language**: Rust (Edition 2024)
*   **Binary Parsing**: `goblin`, `object`
*   **Instruction Decoding**: `iced-x86`, `capstone`
*   **Debug Info**: `gimli` (DWARF)
*   **Format Handling**: `serde`, `quick-xml`, `flate2`

---

## 📄 ライセンス
本プロジェクトは [Apache License 2.0](LICENSE) の下で公開されています。
