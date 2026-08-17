<!-- doc-type: decision -->

# 0015. production host の identity ledger を永続化し、restart をまたいで非再利用にする

[決定記録](README.md) / 0015

> **対象読者:** orchestrator を運用する人、identity の一意性をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

[ADR 0006](0006-never-reuse-object-node-and-capability-ids.md) は識別子を再利用しないと決めた。session 側の 7 種の identity（VM、session、subject、workspace、capability、request、Broker session）は 128-bit の乱数で、no-reuse ledger が過去に使った値を拒否する。

問題は ledger の寿命である。process 内の `HashSet` で持つと、orchestrator が再起動した時点で「過去に使った値」の記録が消える。

判断材料。

- 128-bit の乱数が衝突する確率は無視できる。ledger は衝突を防ぐためではなく、entropy source が壊れた場合に検出するためにある。
- audit record は identity で session を指す。restart をまたいで同じ値が現れると、record の指す先が曖昧になる。
- host は再起動する。crash も、計画的な更新もある。
- 永続化すると、書き込みの失敗と破損を扱う必要が出る。

## 検討した選択肢

1. **process 内の ledger だけを持つ** — restart で記録が消えることを受け入れる
2. **乱数の品質に任せる** — ledger を持たず、衝突しない前提で進む
3. **永続 ledger file を持ち、restart をまたいで拒否する**

### process 内の ledger だけを持つ

`HashSet` で保持し、restart でリセットする。

- 利点: 実装が単純。file I/O も破損処理も要らない。
- 欠点: restart 前後で同じ値が使われうる。確率は極小だが、検出できるはずのものを検出しない状態になる。
- **採用しなかった理由:** ledger の目的が「衝突の防止」ではなく「entropy source の異常検出」だったため。壊れた entropy source が同じ値を返し続ける場合、process 内 ledger は 1 回の起動中は検出するが、restart のたびに検出をやり直す。しかも「起動直後に必ず同じ値を返す」壊れ方は、`/dev/urandom` が初期化前に読まれる場合に実際に起こりうる形をしている。restart 直後こそ検出したい場面だった。

### 乱数の品質に任せる

ledger を持たず、128-bit の乱数は衝突しないものとして扱う。

- 利点: 実装が最小。実際、正常な entropy source では衝突しない。
- 欠点: entropy source が壊れた場合に何も起きない。同じ identity を持つ 2 つの session が並走し、audit record が混ざり、Broker の replay guard が sequence 空間を共有する（[snapshot と identity gate](../firecracker-runtime/snapshot-and-identity.md)と同じ故障）。
- **採用しなかった理由:** 「壊れないはず」を前提にした設計を、この基盤の中心に置きたくなかった。identity の一意性は subject 分離の土台で、それが確率的な仮定の上にあると、上に積んだ保証が全部その仮定に依存する。検出は安価なので、入れない理由が無い。

## 決定

**production host は `SessionOrchestrator::new_durable` と永続 ledger file を使う。**

durable ledger の要求は 3 つ。

| 要求 | 何のため |
|---|---|
| exclusive ownership | 2 つの orchestrator が同じ ledger を書くと、片方の記録がもう片方から見えない |
| version / checksum 検証 | 破損した ledger を読んで「過去に使った値が無い」と判断しない |
| append 後の `sync_data` | crash 直前に払い出した値が記録から落ちない |

`SessionOrchestrator::new`（process-local ledger）は test と組み込み用途に残す。restart をまたがないことを明記している。

ledger は domain をまたいで拒否する。VM identity として使った値は session identity にもならない。失敗した startup で割り当てた値も予約済みのまま残る。

## 結果

- production の起動に ledger file の path と、その排他取得が必要になった。file が壊れている、あるいは他 process が持っている場合、orchestrator は起動しない。fail closed であって、ledger 無しで動く縮退は無い。
- ledger が単調に増える。session ごとに 7 値を追加するので、長期運用では file が育つ。圧縮や打ち切りの仕組みは無い。古い値を捨てると非再利用の保証が切れるので、捨てるなら「どこまで遡って拒否するか」を決める別の決定が要る。
- `sync_data` を毎 append で呼ぶので、session 起動のたびに fsync 相当のコストがかかる。
- durable ledgerの破損、path swap、排他取得、cross-process contention、write／sync fault、crash point recoveryは実fileと子processを使うhosted testで確認済み。storage hardwareやfilesystemがfsync契約を破る場合はTCBである。
- `reserve_batch` の `Err` は「その identity がまだ free である」ことを意味する。2 つの `sync_data` が終われば予約は commit しており、それ以降の失敗は `Ok` を返して ledger を poison するだけにしてある。ここを `Err` にすると、disk 上に残った値を caller が free と解釈する。
- [firecracker-runtime](../firecracker-runtime/snapshot-and-identity.md) 側は snapshot の `forbidden_identities` しか見ない。host が割り当てた identity を ledger 全体と照合するのは orchestrator の責務で、2 つの検査は別の層にある。

## 関連

- [Session orchestrator](../session-orchestrator/README.md)
- [snapshot と identity gate](../firecracker-runtime/snapshot-and-identity.md)
- [0006](0006-never-reuse-object-node-and-capability-ids.md)
- [0014](0014-keep-the-workspace-when-vm-kill-fails.md)
- [用語集](../glossary.md)
