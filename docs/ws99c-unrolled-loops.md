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
