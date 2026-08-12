<!-- doc-type: decision -->

# 0002. file 権限を単一の read/write ではなく 10 種の `FileEffect` に分割する

[決定記録](README.md) / 0002

> **対象読者:** file 権限を扱う実装者、effect を増やそうとしている人

## Status

Accepted (2026-08-12)

## 背景と課題

agent に workspace を触らせる。読み取りだけを許す場合と、書き換えを許す場合と、file を消せる場合は、失敗したときの被害が違う。権限の単位をどこで切るかを決める必要があった。

判断材料。

- agent の典型的な作業は「読んで、既存 file を書き換えて、新しい file を作る」で、削除と rename は必要な場面が限られる。
- 権限の単位が粗いと、必要な操作 1 つのために不要な操作までまとめて渡すことになる。
- 単位が細かいと、authority を組み立てる側の記述量が増え、渡し忘れが起きる。
- Lean 側では effect 集合の包含を証明する。variant 数は有限列挙で扱うので、増えると証明の場合分けが増える。
- FUSE operation と effect の対応表は、実装者が毎回参照する。

## 検討した選択肢

1. **`Read` / `Write` の 2 値** — POSIX の慣習に近い
2. **`Read` / `Write` / `Execute` の 3 値** — Unix permission bit と同じ形
3. **操作ごとに分けた 10 種の effect**

### `Read` / `Write` の 2 値

`ReadData` と `ListDirectory` を `Read` に、残りを `Write` にまとめる。

- 利点: 記述が最も短い。誰でも意味が分かる。集合が 2 要素なので証明の場合分けが最小。
- 欠点: 「file の内容を書き換えてよい」と「file を削除してよい」が同じ権限になる。agent が既存 file を編集する作業に、workspace 全体を削除する権限が付いてくる。
- **採用しなかった理由:** 想定する事故が防げない。agent が生成したコードの誤りで `rm -rf` 相当が走る場面と、file を 1 つ書き換える場面は、同じ `Write` では区別できない。この基盤の目的が「生成されたコードを実際に動かす」ことである以上、破壊的操作を通常の書き込みから分離できないのは致命的だった。

### `Read` / `Write` / `Execute` の 3 値

Unix の permission bit と同じ形にする。

- 利点: 既存の知識がそのまま使える。file system の mode と対応付けやすい。
- 欠点: Unix の 3 bit は「誰が」を owner / group / other で分ける前提の設計で、「何を」の分解ではない。`Execute` は directory では意味が変わる。削除の権限が file ではなく親 directory の `Write` に紐づくのも、Capability として渡すには扱いにくい。
- **採用しなかった理由:** 3 値でも削除と書き込みが分離しない。加えて、Unix の意味論を借りると「削除の権限は親 directory にある」という間接性まで持ち込むことになり、`FileAuthority` が単一の path 範囲で権限を表す設計と噛み合わなかった。

## 決定

**`FileEffect` を 10 variant に分ける。**

| effect | 許可する操作 |
|---|---|
| `ReadData` | file 内容を読む |
| `ListDirectory` | directory entry を列挙する |
| `WriteData` | 事前 truncate なしで内容を書く |
| `Truncate` | file size を変える |
| `CreateFile` | regular file を作る |
| `CreateDirectory` | directory を作る |
| `RemoveFile` | regular file を削除する |
| `RemoveDirectory` | directory を削除する |
| `Rename` | file / directory を rename する |
| `SetMetadata` | mode や timestamp を変える |

分割の基準は「その操作を許さないことに実際の意味があるか」。`ReadData` と `ListDirectory` を分けたのは、内容を読まずに構造だけ見せる場面があるから。`WriteData` と `Truncate` を分けたのは、既存内容を保ったまま追記する場合と、size を 0 にする場合で被害が違うから。

10 という数は「必要な区別を全部入れた結果」であって、目標値ではない。Rust は private な `u16` bitset、Lean は `FileEffect → Bool` の membership 関数として持つ。

## 結果

- authority を組み立てる側の記述量が増えた。`FileEffects::from_effects` に必要な effect を列挙する。
- `Truncate` を独立させた結果、下位層でも同じ粒度が要求される。Landlock の `LANDLOCK_ACCESS_FS_TRUNCATE` は ABI 3 で入った bit で、これが [runtime-isolation の Landlock ABI 3 要求](../runtime-isolation/landlock-envelope.md)の理由の半分になっている。粒度を上げると、それを維持できる下位層が必要になる。
- Lean の `allFileEffects` が 10 要素の列挙になり、`fileEffectsBelow` の計算がその上を走る。variant を増やすとここも増える。
- `mask()` が `u16` なので 16 variant までしか入らない。17 個目を足すときは bitset の型を広げる必要がある。
- effect を増やす変更は Rust enum、Lean inductive、`allFileEffects`、両言語の test、capfs の対応表の 5 箇所に同時に現れる。1 箇所で静かに増えない。
- 空 effect 集合の扱いについては [ADR 0003](0003-require-repository-and-path-match-for-empty-effects.md) を参照する。

## 関連

- [File authority](../authority-core/file-authorities.md)
- [Direct-I/O FUSE adapter](../capfs/read-only-fuse.md)
- [Landlock envelope](../runtime-isolation/landlock-envelope.md)
- [0003](0003-require-repository-and-path-match-for-empty-effects.md)
- [用語集](../glossary.md)
