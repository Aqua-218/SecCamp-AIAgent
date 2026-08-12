<!-- doc-type: decision -->

# 0005. object の identity を path から分離し `ObjectId` で持つ

[決定記録](README.md) / 0005

> **対象読者:** capfs を触る実装者、rename 競合をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

Capability は path 範囲で権限を表す。`Prefix(src)` を持つ subject は `src` 以下を操作できる。判定は path に対して行う。

一方、file 操作は path で始まっても、実体に対して起きる。`open` して `read` する間に、その file は rename されうる。VM 内には複数の subject がいて、それぞれが同じ workspace を見ている。

判断材料。

- 認可は path で行う。これは Capability モデルが path 範囲で権限を表す以上、変えられない。
- 実 I/O は fd に対して行う。fd は path ではなく実体に紐づく。
- rename は path を変える。実体は変わらない。
- FUSE の `nodeid` は kernel が保持する識別子で、mount ごとに独立している。

## 検討した選択肢

1. **path を identity として使う** — 現在 path で object を識別する
2. **backing の `(device, inode)` を identity として使う** — OS の識別子をそのまま使う
3. **registry が独自に `ObjectId` を割り当てる**

### path を identity として使う

`nodeid` から path を引き、path で backing を開く。

- 利点: 認可の単位と identity の単位が一致する。追加の対応表が要らない。
- 欠点: rename が起きると、同じ object を指す名前が変わる。open 済みの handle が持つ path は古くなり、その path で開き直すと別の object に当たる。
- **採用しなかった理由:** rename 中に別 object を触る経路ができる。subject A が `src/a.rs` を開いている間に subject B が `src/a.rs` を消して別の file を同じ名前で作ると、A の次の操作は B が作った file に当たる。認可は `src/a.rs` に対して通っているので、判定は正しく見える。path が identity を兼ねられないのは、path が可変だから。

### backing の `(device, inode)` を identity として使う

OS が持つ識別子をそのまま object identity にする。

- 利点: 新しい識別子を作らなくてよい。backing との対応が自明。
- 欠点: inode は再利用される。file を消して新しく作れば、同じ inode が別の内容を指す。`(device, inode)` を key にした対応表は、削除と作成をまたぐと古い entry が新しい object に当たる。加えて、これは backing filesystem の実装に依存する値で、capfs の抽象がその下に漏れる。
- **採用しなかった理由:** 再利用が防げない。[ADR 0006](0006-never-reuse-object-node-and-capability-ids.md) が要求する非再利用を、OS の識別子では満たせない。`(device, inode)` は backing の整合性確認には使うが（[Backing repository の事前検証](../capfs/backing-preflight.md)）、identity としては使わない。

## 決定

**共有 namespace registry が `ObjectId` を割り当て、`ObjectId -> 現在 path` の対応を持つ。**

`ObjectId` は path から導出しない。startup import で manifest を path 順に走査しながら順番に割り当て、以降は新しい object を作るたびに新しい値を出す。再利用しない。

registry が持つのは 3 つ。`ObjectId` から現在 path への対応、`NamespaceGeneration`、object ごとの open count。rename は path の対応を書き換え、generation を進める。`ObjectId` は変わらない。

FUSE 側は subject ごとに `nodeid -> ObjectId` の node table を持つ。`nodeid` は subject-local、`ObjectId` は VM 共通。この 2 段構えで、kernel が保持する識別子と VM 全体の identity を分離する。

## 結果

- 対応表が 2 つになった。`nodeid -> ObjectId`（subject ごと）と `ObjectId -> path`（VM 共通）。両方の lock 順序を決める必要があり、[共有 namespace registry](../capfs/namespace-registry.md) の lock 契約がその制約になっている。
- open handle が `ObjectId` に紐づくので、rename されても同じ実体を指し続ける。認可は現在 path に対して毎回やり直す（[ADR 0007](0007-use-direct-io-so-revocation-cannot-be-bypassed.md)）ので、rename で権限範囲の外に出た object はそこで拒否される。
- `ObjectId` が path から独立している結果、`ObjectId` だけでは認可できない。認可のたびに registry から現在 path を引く必要がある。これは性能上のコストだが、rename と認可の競合を閉じるために必要。
- `NamespaceGeneration` を cache の key に含める必要が出た。generation を進める箇所を増やすとき、cache を持つ側を全部洗う作業が付いてくる。
- backing の `(device, inode)` は identity としては使わないが、startup の整合性確認と、fd を取った前後の再照合には使う。用途が違う 2 つの識別子が並存している。

## 関連

- [共有 namespace registry](../capfs/namespace-registry.md)
- [mount ごとの node table](../capfs/node-tables.md)
- [Backing repository の事前検証](../capfs/backing-preflight.md)
- [0006](0006-never-reuse-object-node-and-capability-ids.md)
- [0007](0007-use-direct-io-so-revocation-cannot-be-bypassed.md)
- [capfs 設計](../design/capfs.md)
- [用語集](../glossary.md)
