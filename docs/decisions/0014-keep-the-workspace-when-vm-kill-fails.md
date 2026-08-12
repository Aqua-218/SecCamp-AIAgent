<!-- doc-type: decision -->

# 0014. VM kill が失敗した場合に workspace isolation を実行しない

[決定記録](README.md) / 0014

> **対象読者:** orchestrator の停止経路を触る実装者、resource 解放をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

session の停止は 4 段階を順に試みる。root capability の revoke、VM の kill、Broker session の close、workspace の isolation。

`rollback` も `stop` も同じ containment order を使う。問題は、途中の段階が失敗したときに残りを続けるかどうか。

判断材料。

- 各段階の失敗は独立しうる。VM kill が失敗しても、workspace の isolation 自体は成功する。
- workspace は session ごとに clone した tree で、isolation は次の session が使えるようにする操作である。
- VM kill の失敗は「VM がまだ生きている可能性がある」を意味する。プロセスが応答しない、signal が届かない、いずれも kill 失敗として返る。
- 停止が完了しないと、その host は次の session を受け付けない。

## 検討した選択肢

1. **失敗した段階を飛ばして残りを続ける** — できる後始末は全部やる
2. **失敗した段階で完全に止める** — 以降を一切行わない
3. **依存関係のある段階だけを止める**

### 失敗した段階を飛ばして残りを続ける

VM kill が失敗しても、Broker close と workspace isolation は実行する。

- 利点: 解放できる resource が最大になる。host の資源が無駄に押さえられない。停止処理が「できるだけ片付ける」という直感に合う。
- 欠点: 生きている VM が掴んだままの workspace を解放することになる。
- **採用しなかった理由:** workspace が次の session に再割り当てされたとき、生き残った VM がその tree を読み書きできる。session A の VM が session B の workspace を見る状態で、これは subject 分離の破れそのものになる。しかも VM が生きているので、Broker session を close しても vsock 以外の経路が残る可能性がある。「片付ける」ことが分離を壊す唯一の経路になっていた。

### 失敗した段階で完全に止める

VM kill が失敗したら、Broker close も行わない。

- 利点: 判断が単純。失敗の後に何かをしない。
- 欠点: Broker session は host 側の resource で、生きている VM が掴んでいるわけではない。close しないまま残すと、Broker 側の session slot と budget が解放されない。
- **採用しなかった理由:** 依存が無い段階まで止める理由が無かった。Broker session を close すると VM は外部へ出られなくなるので、むしろ VM が生きている場合こそ close したい。

## 決定

**VM kill が失敗した場合、workspace isolation を実行しない。他の段階は続ける。**

```text
root capability revoke
  -> VM kill          ← 失敗したら
  -> Broker close        ここは実行する
  -> workspace isolation ここは実行しない
```

どれかが失敗した場合、session は `Stopping` を保持する。次回の停止要求では未完了の段階だけを retry する。cleanup が全部 commit したときにだけ `Closed` になる。

startup rollback が失敗した場合も同じ。`Ready` へ戻らず、未解決の host resource がある間は新しい session を受け付けない。

## 結果

- VM kill が失敗し続ける host は、その session の workspace を解放できない。手動介入が要る。resource が押さえられたまま残るのは受け入れたコストで、分離を壊すよりはよいという判断。
- 停止が冪等でなければならない。`Stopping` からの retry で、成功済みの段階を再実行しない。[firecracker-runtime](../firecracker-runtime/launch-sequence.md) 側が `process_stopped` / `verity_opened` / `workspace_removed` の 3 つの bool を持ち、成功した操作を記録しているのはこのため。
- 「VM が生きている可能性がある」を kill の失敗だけで判断している。kill が成功を返しても VM が生きている場合は検出しない。process の生存確認を別途行う仕組みは無い。
- `Stopping` に留まる session がある間、その orchestrator は新しい session を受け付けない。1 つの `SessionOrchestrator` で active session は 1 つだけという制約と組み合わさって、失敗が host 全体を止める。運用上はここが一番効く。
- 段階を増やすときは、その段階が「VM が生きていても安全か」を判定する必要がある。安全でないものは workspace isolation と同じ扱いにする。

## 関連

- [Session orchestrator](../session-orchestrator/README.md)
- [production backend 契約](../session-orchestrator/contracts.md)
- [起動の順序と rollback](../firecracker-runtime/launch-sequence.md)
- [0015](0015-persist-the-identity-ledger-across-restarts.md)
- [用語集](../glossary.md)
