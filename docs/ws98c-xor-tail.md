# WS98 C: `xor edx, edx; mov eax, edx; ret` が `return rdx;` になるバグ

branch `fix/ws98-xor-tail`（origin/main 7c188464 から）。
scratch: `%TEMP%/claude/.../scratchpad/ws98c`（`run/` = WS97 C の実行確認一式のコピー、`ra-base.exe` = main のビルド）。

## 症状

gcc -O2/-O3 の `f_sum32` / `f_down`（WS97 C の `run/loops2.c`）。`if (n <= 0)` 側の尾ブロック

```
1828: xor edx, edx
182a: mov eax, edx
182c: ret
```

が `return rdx;` になる（`rdx` の代入なし → 再コンパイルするとゴミ値を返す）。

## 調査（実装前）

`DBGSSA=1`（一時的なデバッグ出力、コミットしない）で最適化の各ラウンドの SSA を varnode id 付きで出した。

- 生の SSA は正しい: `#114 edx = XOR edx0, edx0` / `#115 rdx = ZEXT #114` / `#128 eax = COPY #114` / `#129 rax = ZEXT #128` / `RETURN …, #129`。
- ラウンド 0: XOR → `COPY 0`、copy propagation で `#115 = ZEXT 0`、`#129 = ZEXT 0` → 同じブロックで同じ式 → **CSE が `#129` の op を消す**。
  CSE は消した側の出力 varnode `#129` の **data/version を残す側のキー（rdx_3）に書き換える**だけで、読み手（RETURN）の入力は `#129` のまま。
  WS86 の追記で `#115.uses` に RETURN を足している（DCE 対策）。
- ラウンド 1: `#115 = ZEXT 0` → `COPY 0`（定数畳み込み）。copy propagation は `#115.uses` の読み手の入力を **id で**（`*inp == out_id`）置き換える
  → RETURN の入力は `#129` なので置き換わらず、さらに `uses.retain(|u| inputs.contains(&out_id))` で RETURN が uses から落ちる。
- DCE: `#115` の読み手なし → COPY が死ぬ。RETURN は `#129`（表示は `rdx`、定義なし）を読む → `return rdx;`。

### 根本原因

CSE（`optimize::cse_with_hits`）の書き戻しが「キーの付け替え」だけで、読み手の入力 id は消した op の出力のまま。
他のパス（copy propagation・定数畳み込み・DCE・`def_op` をたどる解析）は値を **varnode id** で扱うので、
CSE 後に「同じ値なのに id が違う」2 つの varnode ができ、id ベースのパスが片方の読み手を取りこぼす。
xor のゼロ化が引き金なのは、`edx = 0` が `rdx = ZEXT(edx)` と `rax = ZEXT(eax = edx)` を同じ式 `ZEXT 0` にするから
（`mov edx, 5; mov eax, edx` のような定数一般・`sub r, r` でも起きる）。

### 方針

1. CSE の書き戻しで、消した値の読み手の入力を残す定義の出力 id に付け替える（uses も移す）。キーの付け替えは残す（他の構造が id を持つ場合の保険）。
2. 回帰テスト: 最小の機械語（`xor edx, edx; mov eax, edx; ret` を分岐の尾に置いたもの、`sub edx, edx`、`mov edx, 5` 版）+ optimize 単体。
3. 実行確認 `run/runcheck3.sh` 全レベルで不一致 0 を確認。他のゼロ化イディオム（`xor r32, r32` / `sub r, r` / 部分レジスタ）も実行確認で見る。
4. テスト全体・decompile-all の時間（CSE はホットパス）を前後で計測。

## 進捗ログ

（以下、作業ごとに追記）

### 1. CSE の読み手の付け替え（Task 1）

- `optimize::cse_with_hits` の書き戻し: 消した重複の出力 varnode（キーを付け替えたもの）の読み手の入力を、残す定義の出力 id に置き換え、
  uses も移す（`std::mem::take`）。その varnode を生きた op がまだ書いている場合（SSA では起きないはず）は従来どおり触らない。
- キーの付け替えをするのは CSE だけ（`grep '\.version = '` で他にない）。
- 回帰テスト `pipeline::tests::zeroed_register_copied_to_the_return_is_returned`:
  分岐の尾の `xor edx, edx` / `sub edx, edx` / `mov edx, 5` + `mov eax, edx; ret`（C と Rust）、gcc -O2 の `f_sum32` の機械語そのもの、
  同じブロックでゼロを 2 回コピーする例（`xor eax, eax; mov edx, eax; mov rcx, rdx; add rcx, rsi`）。修正前は失敗することを確認。
- 実行確認（`run/runall.sh`、loops2 21 + loops3 15 関数 × -O1/-O2/-O3/-Os）: main は loops2 -O2/-O3 で 2 値ずつ不一致 → 修正後 0。
- 新しい実行確認 `run/loops4.c`（h_、C 12 関数 + ゼロ化イディオムを手書きした asm 15 関数: `xor r32,r32` / `sub r,r` / `xor al,al` /
  `sub ax,ax` / `xor ah,ah` / `mov ah, cl` / 32-bit 書き込みでの上位クリア / 分岐の合流など）。main は `h_a1`（`sub edx, edx` の尾）・
  `h_a3`（`mov edx, 5`）・`h_a12` で `return rdx;`、修正後は正しい。
- BDS（1.26.33.2）の出力差分: s40 1 / big 5 / jt2 27 関数。すべて同じ原因の誤りが直ったもの:
  ゼロ化（や定数）したレジスタを渡す呼び出しの引数が別のレジスタ名で出ていた（`memset@plt(rdi, r12, 0x218)` → `memset@plt(rdi, 0, 0x218)`、
  `0x540bc30(rdi, rsi, 5, rdx, r8)` → `(rdi, rsi, 5, 5, r8)`、`0x3fe1400(rbp, rbp, rbp)` → `(0, 0, 0)` など、逆アセンブルで確認）、
  `rax = rax; return rax;` → `return 0;`、`* tmp_2010` → `* 0xcccccccccccccccd`。
- `cargo test --workspace --release`: 1317 passed（+1）。
- decompile-all（8 回、min / 中央値）: py.elf main 6.069 / 6.998 s → 5.971 / 7.028 s、bash.elf 2.606 / 2.704 → 2.557 / 2.737 s（ノイズ内、退行なし）。

### 2. 実行確認の再実行と次の改善（Task 2）

コーパス = `run/runall.sh`（loops2 21 + loops3 15 + loops4 27 関数 × -O1/-O2/-O3/-Os = 252 関数）、計測 `run/stat.py`、BDS は `bstat.py`。

#### 2a. `CONCAT(ah, 0:1)`（commit 08f5b604）

- Task 1 の後、loops4 の `h_a7`（`xor eax, eax; mov ah, cl`）だけ C としてコンパイルできなかった: `ax = CONCAT(ah, 0:1);`。
- PIECE の両半分が結果を埋め、結果が C の整数型（2/4/8/16 バイト）なら `ax = (uint16_t)ah << 8;` / `(T)hi << s | (T)(L)lo`
  （`lo` がそのサイズのレジスタ名ならキャスト 1 つ）。Rust は `ax = (ah as u16) << 8;`。半分が埋まらない形（既存テストの 8+4→16）は従来どおり。
- 実行確認ハーネスの `decomp2c.py` に `bsr` / `bsf` の定義を追加（-Os の `h_clz` が `bsr(edi)` の intrinsic を出す、デコンパイラ側は従来どおり）。
- テスト `pipeline::tests::concatenation_prints_as_shift_and_or`。BDS 3 sample では `CONCAT` 0 件（変化なし）。

#### 2b. return が読むコピー・ゼロ拡張を return の中に（commit 本節）

- 測定（Task 1 後）: 252 関数で `rax = (uint64_t)eax;` 133 回、その直後が `return rax;` 106 回（`eax = edx; rax = (uint64_t)eax; return rax;` 78 回）。
  jt2 でも `rax = (uint64_t)eax; return rax;` 99 回。自己代入 `edx = edx;`（`mov edx, edx`）8 回 / jt2 51 回。
- `emit::return_chains`: return の値から、同じブロックの COPY / INT_ZEXT（出力がレジスタ、読み手が次の段だけ、入力がレジスタか定数、
  入力が出力より広くない）を最大 4 段さかのぼる。条件: その段から return までの間に印字される文がない（dead / noise / folded だけ）、
  間の op が入力のレジスタを書かない。→ `return edx;`（C は戻り値型 uint64_t への変換が同じゼロ拡張）、Rust は `return edx as u64;`。
  消した段は `folded` に入る（宣言も消える）。入力が式（ロード・構造体フィールド）の段は対象外（符号付きの型だと return が符号拡張する）。
  符号拡張 `(int64_t)(int32_t)` も対象外。
- `mov edx, edx` の COPY は印字する右辺と左辺が同じなら文にしない（後ろのゼロ拡張 `rdx = (uint64_t)edx;` が本体）。C / Rust。
- 既存テスト 3 件を新形式に更新（`emit_simple_function` ×2: `return 0x2a;`、`epilogue_frame_restore_is_not_printed`: `return ebx;`）。
  新規 `pipeline::tests::return_prints_the_value_under_its_copies`（C/Rust、間に store がある場合・movsxd・自己コピー）。

#### 結果

| | 行数 | キャスト `(uintN_t)` | 宣言 | `rX = (uint64_t)eX;` | 自己代入 | goto | 実行不一致 / コンパイルエラー |
|---|---|---|---|---|---|---|---|
| コーパス 252 関数 main | — | — | — | — | — | — | loops2 -O2/-O3 で 2 値ずつ / 0 |
| コーパス Task 1 + 2a | 4295 | 630 | 778 | 133 | 8 | 2 | 0 / 0 |
| コーパス + 2b | 4059 | 578 | 713 | 81 | 0 | 2 | 0 / 0 |
| jt2 (273) Task 1 → + 2b | 248681 → 248313 | 23870 → 23771 | | | 51 → 0 | 4910 → 4910 | |
| big (150) | 22458 → 22315 | 2032 → 2023 | | | | 285 → 285 | |
| s40 (40) | 4555 → 4550 | 711 → 711 | | | | 23 → 23 | |

- jt2 の新しい return の内訳: `return r13;` 96、`return r15d;` 62、`return rbx;` 13 など（`mov rax, r13; pop r13; ret` の pop は印字されない
  ので、印字されたプログラムの中では同じ値。逆アセンブルで確認）。
- `cargo test --workspace --release`: 1319 passed（main 1316 + 3）。clippy（reargo-decompile）: 警告なし。
- decompile-all（8 回、min / 中央値）: py.elf main 5.926 / 6.948 s → 5.854 / 6.912 s、bash.elf 2.415 / 2.860 → 2.486 / 2.852 s（ノイズ内）。

## 残り

- `h_max`（gcc -O2 の 2 倍展開ループ）の `goto label_1850;`（展開の端数処理からループの途中へ入る）は構造化の問題で未対応。
- `al = (uint8_t)eax;`（`movzx eax, byte [..]; test al, al`）のようなビューの読み直しは残る（コーパスで多い次の候補）。
- 実行確認ハーネスは C のみ（Rust 出力は単体テストだけで確認）。
