<!-- doc-type: decision -->

# 0006. `ObjectId`、`nodeid`、capability ID を再利用しない

[決定記録](README.md) / 0006

> **対象読者:** 識別子を払い出す実装者、失効境界をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

この基盤は複数種類の識別子を払い出す。`ObjectId`、FUSE の `nodeid`、`CapId`、`HandleId`、`SubjectId`、そして session 側の 7 種の 128-bit identity。

識別子を払い出す実装には 2 つの方針がある。使い終わった値を再利用するか、単調に増やして再利用しないか。

判断材料。

- 再利用しないと、値の空間をいずれ使い切る。`u64` なら現実的には尽きないが、`u32` や小さい空間では問題になる。
- 保持側が識別子を長く持つ。FUSE の kernel は `nodeid` を `FORGET` するまで保持し、その timing は制御できない。open handle は close まで `CapId` を参照する。
- 失効は識別子の単位で起きる。revoke した `CapId` は無効になる。
- 再利用が起きるのは、解放と再割り当ての間だけ。正常系では衝突しない。

## 検討した選択肢

1. **解放済みの値を再利用する** — free list や bitmap で管理する
2. **世代番号を付けて再利用する** — `(index, generation)` の組にし、index を再利用する
3. **単調に増やして再利用しない**

### 解放済みの値を再利用する

解放した識別子を free list に戻し、次の割り当てで使う。

- 利点: 値の空間が有限でも足りる。index として配列に直接使える。
- 欠点: 保持側が古い識別子を持ったまま、その値が別の対象に再割り当てされうる。revoke した `CapId` が再利用されると、失効させたはずの識別子が再び有効になる。
- **採用しなかった理由:** 失効の意味が壊れる。revoke は「この Capability はもう使えない」を意味するが、同じ `CapId` が別の Capability に付けば、その主張が偽になる。同じことが `nodeid` でも起きる。kernel が `FORGET` を送る前に値が再利用されると、kernel が保持している `nodeid` が別の object を指す。`FORGET` の timing は kernel が決めるので、実装側で「もう使われていない」を保証できない。

### 世代番号を付けて再利用する

`(index, generation)` の組を識別子にし、index を再利用しつつ generation で区別する。

- 利点: index を配列の添字に使えるので、対応表が高速になる。generation の比較で古い参照を検出できる。
- 欠点: generation 自体が有限で、これも溢れる。溢れた後は再利用と同じ問題が起きる。加えて、識別子が組になるので、比較と受け渡しの実装が増える。protocol で運ぶときの表現も決める必要がある。
- **採用しなかった理由:** 問題を先送りしているだけだった。generation が 32 bit なら 42 億回の再割り当てで一周する。長寿命の session ではあり得ない数ではない。溢れたときの挙動を決めるくらいなら、最初から溢れない空間を使うほうが単純。

## 決定

**識別子は単調に増やし、再利用しない。**

- `ObjectId` は registry が startup import で path 順に割り当て、以降は新しい object ごとに新しい値を出す。
- `nodeid` は subject ごとの node table が単調に払い出す。`FORGET` で entry は消えるが、値は再利用しない。
- `CapId` は revoke 後も再割り当てされない。
- `HandleId` は close 後の rebinding を許さない。
- session 側の 7 種の identity は 128-bit の乱数で、no-reuse ledger が過去に使った値を拒否する。domain をまたいで拒否するので、VM identity として使った値は session identity にもならない。

`nodeid` の非再利用は subject-local な性質である。別 mount の同じ数値は無関係の object を指す。

## 結果

- 値の空間を消費し続ける。`u64` の単調増加なので、1 秒間に 100 万回払い出しても 50 万年以上かかる。実質的な制約にはならない。
- 対応表を配列の添字で引けない。`HashMap` が要る。性能上のコストはあるが、認可判定のほうが支配的なので問題になっていない。
- session の identity については、no-reuse ledger が別途必要になった。乱数なので衝突確率は無視できるが、「衝突しないはず」ではなく「衝突したら拒否する」を実装している。失敗した startup で割り当てた値も予約済みのまま残る。
- ledger を restart にまたがらせるかは別の決定になった。[ADR 0015](0015-persist-the-identity-ledger-across-restarts.md) を参照する。
- 「もう使われていない」を判定する必要が消えた。`FORGET` の timing、handle の close、revoke の伝播のいずれについても、値の解放を待つ処理が要らない。これが実装上の最大の利点で、非再利用を選んだ理由の半分はここにある。

## 関連

- [mount ごとの node table](../capfs/node-tables.md)
- [共有 namespace registry](../capfs/namespace-registry.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [Capability state](../authority-core/capability-state.md)
- [0005](0005-separate-object-identity-from-path.md)
- [0015](0015-persist-the-identity-ledger-across-restarts.md)
- [用語集](../glossary.md)
