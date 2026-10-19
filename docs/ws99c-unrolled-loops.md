# WS99 C: 展開ループの途中への goto・ビューの読み直し・epilogue で戻る return

branch `feat/ws99-unrolled-loops`（origin/main 03060c98 から）。
scratch: `%TEMP%/claude/.../scratchpad/ws99c`（WS98 C の `run/`・`decx.py`・`bstat.py`・`runbds.sh`・`bench/` をコピー、
`ra-base.exe` = main のビルド）。

## 計画（実装前）

検証は毎回: 実行確認コーパス `run/runall.sh <tag> <exe>`（loops2 21 + loops3 15 + loops4 27 関数 × -O1/-O2/-O3/-Os = 252 関数、
不一致 0・コンパイルエラー 0）、`run/stat.py`、BDS 3 sample（s40 40 / big 150 / jt2 273 関数）の goto 等を `bstat.py`、
`cargo test --workspace --release`（main 1319）、decompile-all の時間（py.elf / bash.elf、`bench/tm.py`）。

### Task 1: gcc -O2 の 2 倍展開ループの途中への goto（`h_max`）

main の出力（-O2/-O3）:

```
if (((uint32_t)(rsi - rdx) & 8) == 0) {
    do { label_1850: …; rdx = rdx + 0x10; } while (rdx != rsi);
    return rax;
}
rdx = *(uint64_t*)rdx; rax = max…; rdx = rdi + 0x10;     // 端数 1 回分
if (rdx != rsi) { goto label_1850; }
return rax;
```

CFG: `B2: if (偶数) goto H; B3: 端数 1 回; if (rdx == rsi) goto RET; H: loop …; RET`。H（ループのヘッダ）は B2 と B3 の
両方から入る（自然ループ・可約）。B2 の if の join は直後支配（= RET）なので、then 腕がループを丸ごと印字し、
else 腕（B3）からの H への辺が goto になる。

方針:
1. **ループヘッダを if の join に**: if の片腕がまだ印字していないループヘッダ H で、もう片腕の領域（H を通らずに
   たどれるブロック）が b に支配されるブロックと短い return tail だけでできていて、直後支配 J に H を通らずに着かない、
   かつ H のループ外の前任がすべて b かその領域のとき、join = H にする（`if (!c) { 端数; if (…) return …; }` のあとに
   ループ）。
2. **腕が walk の stop そのもの**: if の片腕がいま walk している範囲の stop（外側の if の join）なら、それは腕の終わりへの
   落ち込みなので join = stop にする（従来は直後支配が stop の先にあると `goto stop;` になっていた）。
   walk は stop に着いたら止まるので、意味は変わらない。
3. 回帰テスト（h_max の機械語そのもの）、BDS の goto 数を前後で比較し、どの形が何件減ったか分類する。

### Task 2: `al = (uint8_t)eax;`（`movzx eax, byte [..]; test al, al`）

コーパスで 10 回。`eax = ZEXT(load8)` の下位バイトを読み直すビュー。SUBPIECE(ZEXT(x), 0) で x と同じ大きさなら x そのもの。
eax のほかの読み手がないときだけ（ロードの値を 2 か所で使うと tmp が増える）`al = *(uint8_t*)rdi;` にする方向で SSA を見て決める。

### Task 3: `mov rax, r13; pop r13; ret` → `return r13;`

WS98 2b で入った return のコピー畳み込み。印字されたプログラムには pop が出ないので値としては正しいが、
r13 は callee-saved で epilogue で呼び出し元の値に戻る。読む人が「呼び出し元の r13 を返す」と誤読しうるか判断し、
誤読しうるなら epilogue で戻されるレジスタからのコピーは畳まない（`rax = r13; return rax;` のまま）などにする。

### Task 4: Rust 出力のコンパイル確認（安ければ）

コーパスの一部を `--rust` で出し、`rustc --crate-type lib` で型検査だけ通す（実行までは安ければ）。

## 進捗ログ

### 1. 展開ループの途中への goto（Task 1）

計測ツール: `cmp.py <dir> base <tag>`（関数ごとの goto・行数の差）、`gotocls.py <dir>`（goto を「ループの中へ / ループの外へ /
同じ深さ」×「前方 / 後方」に分類）。

#### 試したこと

1. ループヘッダだけを join にする版（計画の方針 1 + 2、片腕がヘッダそのもの）: コーパス goto 2 → 0、
   BDS は s40 23 → 22 / big 285 → 284 / jt2 4910 → 4902（増加 0）。**h_max の形は BDS ではほとんどない**（jt2 で 8 件）。
   最初の版はループ本体の途中に入る腕（既約でない 2 入口ループ）を除外し忘れていた → 除外（`info.body[x]` で不可）。
2. jt2 の残り 4902 件の分類（`gotocls.py`）: 同じ深さで後方 3525・同じ深さで前方 629・ループの外へ 562・**ループの中へ 186**。
   多いのは「片腕が `abort()` / `return` で抜けるので直後支配が関数の出口（`None`）になり、両腕の合流点が join に
   ならない」形（`if (r13 != r15) { realloc; if (!p) abort(); L: … } else { malloc; if (!p) abort(); …; goto L; }`）。
3. そこで一般化: **直後支配が `None` か短い return tail のとき、両腕が合流するブロック m を探して join にする**
   （`merge_join`）。条件: m より前に腕がたどるブロックは b に支配され未印字（または return tail / `break` / `continue`
   で終わる出口）、それらが m から再び到達されない、m は b の外のループに入っていない（そのループのヘッダで、ヘッダから
   だけ入る場合を除く）。h_max は m = ループヘッダの特別な場合。
   - 最初は m に return tail を選んで外側の if がネストに戻った（h_max の goto が復活）→ return tail は候補にも領域にも
     入れない（出口扱い）。
4. 方針 2 の一般化（**stop に合流**）: 腕がそのまま stop でなくても、両腕が stop か出口にしか行かず、stop が b を後支配
   しないとき join = stop。
5. **合流点のコピー**: 合流点 m を follow_stack に積んだことで、腕の奥（入れ子の if の中）から m に着くと `goto m` に
   なる場合が出た（以前は m が印字済みなので短い領域のコピーで済んでいた）→ walk で、follow_stack の未印字の join への
   jump に対して短い領域（`break` / `continue` / return tail で終わる）のコピーを先に試す。

組み合わせの比較（env で切り替えた実験ビルド、goto の増 / 減 は関数ごとの合計）:

| 版 | s40 | big | jt2 |
|---|---|---|---|
| main | 23 | 285 | 4910 |
| ループヘッダのみ（1） | 22 | 284 | 4902 |
| merge_join（m はループヘッダのみ） | 22 | 286（+2/−1） | 4911（+5/−4） |
| merge_join（腕にループなし） | 20 | 298（+26/−13） | 4864（+31/−77） |
| merge_join + stop 合流 | 16 | 282（+15/−18） | 4794（+16/−132） |
| **merge_join + stop 合流 + 合流点のコピー（採用）** | **16** | **279（+12/−18）** | **4788（+15/−137）** |
| m の前任 ≤ 2 に制限 | 19 | 281 | 4827 |

- 採用版で goto が増えた関数（big の 0x44c3340 / 0xacd8b20 の +5 など）は、以前は小さな後始末
  （`r15->field_30 = 0; r15 = r15->field_0; if (r15 == 0) break; continue;`）を 5 か所にコピーしていたのが、
  合流点 1 か所 + goto になったもの（行数は −45）。既約な領域（label が 3 つ互いに goto し合う）の中なので、コピーの深さ
  制限（`MAX_COPY_DEPTH`）にかかる。
- 行数: jt2 248313 → 245108（−1.3%）、big 22315 → 22127、s40 4550 → 4539。
- 採用版の jt2 の分類: 同じ深さ後方 3350（−175）・同じ深さ前方 687・ループの外へ 566・ループの中へ 185（−1）。
  残る「ループの中へ」は h_max 型ではなく、出口が複数あるループ（std::sort の unguarded partition の
  `while (rcx < rsi) { …; if (!lt) continue; label: … goto out; }` のように、ループの途中の出口ブロックを別の経路も使う）。

#### 結果

- コーパス 252 関数: 不一致 0 / コンパイルエラー 0、goto 2 → 0、行 4059 → 4055。
- テスト `pipeline::tests::unrolled_loop_entered_from_the_odd_iteration_prints_without_goto`（h_max の -O2 機械語、C と Rust、
  修正前は失敗を確認）。`cargo test --workspace --release`: 1320 passed。clippy 警告なし。
- decompile-all（8 回、min / 中央値）: py.elf main 5.788 / 6.101 s → 5.588 / 6.121 s、bash.elf 2.274 / 2.580 → 2.367 / 2.507 s
  （ノイズ内）。

### 2. 拡張したロードの下位の読み直し（Task 2）

- SSA（`--ssa`）: `v1280 = LOAD 1, rdi; eax = INT_ZEXT v1280; al = SUBPIECE eax, 0`。eax の読み手は rax / ax / al の
  ビュー（rax・ax は後で死ぬ）と al だけ。
- `optimize::try_algebraic_simplify_op` に SUBPIECE の規則: `SUBPIECE(ZEXT/SEXT(x), 0)` で x と出力が同じ大きさ、x が一時値
  （unique 空間 = ロードなどの式の値）、拡張の出力の生きた読み手がこの SUBPIECE だけのとき `COPY x`
  （拡張は死に、x は 1 回だけ読まれる）。拡張の値がほかでも読まれる場合（`return eax;` 等）は従来どおり。
  x がレジスタの場合は対象外（版の衝突を避ける）。
- テスト `pipeline::tests::low_byte_of_a_zero_extended_load_is_the_load`（gcc -O2 の f_count の機械語、C / Rust、
  拡張値も返す場合は残る。修正前は失敗を確認）。

| | 行数 | キャスト | `xl = (uint8_t)exx;` |
|---|---|---|---|
| コーパス Task 1 → Task 2 | 4055 → 4049 | 578 → 566 | 10 → 4 |
| jt2 | 245108 → 243999 | 23562 → 21273 | 1738 → 1359 |
| big | 22127 → 22105 | 2024 → 1983 | 122 → 115 |
| s40 | 4539 → 4529 | 711 → 693 | 13 → 11 |

- 例（jt2）: `eax = (uint32_t)*(uint16_t*)(r12 + 0x7c); ax = (uint16_t)eax;` → `ax = *(uint16_t*)(r12 + 0x7c);`。
  残る `al = (uint8_t)eax;` は拡張した値もほかで使うもの（`eax = (uint32_t)r15->field_18; al = (uint8_t)eax; if ((al & 1) == 0)
  { edx = eax; …`）や計算結果の下位（f_bytes の `al = (uint8_t)eax; p[i] = al;`）。
- コーパス不一致 0 / コンパイルエラー 0、goto は不変。`cargo test --workspace --release`: 1321 passed。

### 3. `mov rax, r13; pop r13; ret` → `return r13;`（Task 3、判断のみ・コード変更なし）

- 確認: jt2 / big の callee-saved レジスタ（rbx / rbp / r12〜r15 と 32-bit ビュー）を返す `return` 206 / 75 件は
  **すべて本体で代入した値**（`retcs.py`: 本体で代入されていない callee-saved を返すものは 0 件）。典型は
  `local_20 = r13; …; r13 = rdi; …; *(uint64_t*)r13 = r14; return r13;`（sret / this を返す）。
- 印字されたプログラムでは、prologue の push は `local_20 = r13;`（呼び出し元の値の退避）として見え、epilogue の pop は
  その値がどこからも読まれないので印字されない。したがって `return r13;` の r13 は本体の r13 で、印字されたプログラムの
  意味どおり。`rax = r13; return rax;` と書いても「pop の前の r13」を読む点は同じで、区別の情報は増えない。
- pop の**後**で読む場合（`pop rbx; mov rax, rbx; ret`、呼び出し元の rbx を返す）は、pop が `rbx = local_8;` として印字される
  （値が読まれるため）ので `local_8 = rbx; rbx = local_8; return rbx;` になり、取り違えは起きない（手で組んで確認）。
- **判断: 誤読の余地はないので `return r13;` のままにする。** 実行確認コーパスに callee-saved を返す手書き関数 4 つ
  （`h_a16`〜`h_a19`: `push r13; …; mov rax, r13; pop r13; ret`、分岐の合流、32-bit ビュー `lea ebx; mov eax, ebx`、
  2 レジスタ）を追加（loops4 27 → 31 関数、コーパス 252 → 268 関数）。main・本ブランチとも不一致 0。
- 副次的に見つけたもの（未対応）: `h_a18` で `local_8 = rbx;` の `rbx` が宣言されない（`ebx` だけ宣言）。C ハーネスは
  レジスタファイルで吸収するが、出力単体では未宣言。

### 4. Rust 出力の型検査（Task 4）

ハーネス（scratch `run/`）: `rscheck.sh <src> <prefix> <opt> <tag> <exe>`（C 実行確認と同じ ELF の各関数を `--rust` で出し、
`rs2lib.py` で 1 つの lib にまとめて `rustc --crate-type lib --emit=metadata`）、`rsall.sh <tag> <exe>`（12 ビルド分の集計）。
rs2lib は型検査に要らない差だけを吸収する: 引数を `mut` に、引数を再宣言する `let mut rdi: u64;` を消す、宣言に `= 0`、
出力が宣言しないレジスタのビュー（引数 `rdi` の `edi` 等。C ハーネスのレジスタファイルに相当）を宣言。実行はしない
（Rust 出力のビューは別々の変数なので、レジスタファイルを模さないと値が合わない）。

main の Rust 出力（268 関数）: **エラー 138**（型の不一致 112、未宣言の値 20、`bool | u8` 4、`bsr` 1、`return;` 1）。
型の不一致の内訳: `eax = (rax as u32) as u64;`（SUBPIECE が `as u64` まで戻す）、`eax = rdi.wrapping_add(rdi);`
（`lea eax, [rdi+rdi]` の 8 バイトの演算を 4 バイトへ）、`al = a < b;`（比較の bool をバイトへ）、`eax = (x as i16 as i64) as u64;`
（SEXT が常に u64）、`if neg_0 {`（フラグが u8 宣言）。未宣言 = 複数回読まれる一時値 `tmp_600`（**C 出力でも未宣言**、
C ハーネスが補っていた）。

修正（`rust_emit.rs`、C 出力は一時値の宣言だけ）:
- SUBPIECE / SEXT / 符号付きシフト・除算・剰余を出力の型で（`al = rax as u8;`、`eax = (x as i16 as i32) as u32;`）。
- 文を変数の型に（`typed_statement`、印字する文だけ。インライン・条件に畳む右辺は従来どおり）: 比較・bool 演算を
  整数レジスタへ代入するとき `(…) as uN`、広い値の演算・コピーを狭いレジスタへ代入するとき `(…) as uN`（C の代入の暗黙の切り詰め）。
- 比較のフラグ（`lt_0` / `neg_0` 等、WS90 の名前付きフラグ）は C と同じく `bool` で宣言。
- 比較の bool を整数演算の被演算子にインラインするとき `(…) as uN`。
- 一時値（unique 空間）で文として印字されるもの（インラインされないもの）を C / Rust とも宣言（`uint64_t tmp_600;` /
  `let mut tmp_600: u64;`、`old_N` も）。jt2 で 471 件、big・s40 も含めて差分は宣言の追加だけ。

| | Rust エラー（268 関数） | C 実行確認 |
|---|---|---|
| main | 138 | 不一致 0 / コンパイルエラー 0 |
| 本ブランチ | **6**（`bool \| u8` 4 = 条件の畳み込み（condition.rs）の 1 関数 × 4 最適化レベル、`bsr` の intrinsic 1、`void` 関数の `return;` 1） | 不一致 0 / コンパイルエラー 0 |

- テスト `pipeline::tests::rust_statements_have_their_variables_types`（`lea eax, [rdi+rdi]`、`setl al`、3 回読む一時値の
  宣言 C / Rust。修正前は失敗を確認）。`cargo test --workspace --release`: 1322 passed、clippy 警告なし。
- decompile-all（8 回、min / 中央値）: py.elf main 5.411 / 5.965 s → 5.401 / 6.018 s、bash.elf 2.257 / 2.477 → 2.263 / 2.376 s（ノイズ内）。

## まとめ（main 03060c98 → 本ブランチ）

| | main | 本ブランチ |
|---|---|---|
| コーパス 268 関数: 不一致 / コンパイルエラー | 0 / 0 | 0 / 0 |
| コーパス goto | 2 | 0 |
| コーパス行数 / キャスト | 4223 / 578 | 4219 / 566 |
| コーパス Rust エラー | 138 | 6 |
| jt2 goto / 行 / キャスト | 4910 / 248313 / 23771 | 4788 / 244529 / 21273 |
| big goto / 行 / キャスト | 285 / 22315 / 2023 | 279 / 22144 / 1983 |
| s40 goto / 行 / キャスト | 23 / 4550 / 711 | 16 / 4545 / 693 |
| `cargo test --workspace --release` | 1319 | 1322 |

残り:
- jt2 の goto 4788 の大半は同じ深さの後方 goto（3350）。既約な領域・出口が複数あるループ（ループの中へ 185）。
- Rust: 条件の畳み込みで `bool | u8`（condition.rs の Rust 描画）、`bsr` 等の intrinsic、`void` 関数の推定。
- `rbx` の push だけが印字されビュー（`ebx`）しか宣言されない場合の未宣言（C / Rust）。
