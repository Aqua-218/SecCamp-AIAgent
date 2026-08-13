<!-- doc-type: concept -->

# frame から adapter までの 1 本道

[Host Egress Broker](README.md) / frame から adapter までの 1 本道

> **対象読者:** Broker の認可境界を触る実装者、外部副作用の重複をレビューする人

[`dispatch.rs`](../../crates/egress-broker/src/dispatch.rs) は、guest の control frame から外部副作用の adapter までの唯一の経路である。frame を 1 つ decode し、canonical CBOR に復元し、replay guard に通し、budget を予約し、`CapabilityKernel::authorize_and_commit` の内側で adapter を呼ぶ。

## 何を防ぎたいのか

外部副作用は取り返しがつかない。`CreatePullRequest` が 2 回走れば pull request が 2 つできる。だから経路の各段が、次の段へ進む条件を狭めていく。

```mermaid
flowchart TB
    f["ControlFrame::decode_complete<br/>trailing bytes を許さない"] --> c["CanonicalBrokerRequest::decode<br/>payload hash を host が再計算"]
    c --> r["SessionReplayGuard::accept<br/>session / sequence / request ID"]
    r -->|Duplicate| cache["cache 済み outcome を返す"]
    r -->|New| b["SessionBudget::start<br/>request 数・並行数・byte を予約"]
    b --> k["CapabilityKernel::authorize_and_commit"]
    k --> a["adapter<br/>authority family が一致する側だけ"]
    a --> done["budget.complete で実測 byte を計上"]
```

## payload hash は host が計算し直す

wire には payload hash が載っているが、それを信用しない。

```rust
let payload_hash = PayloadHash::of_canonical_payload(&canonical_payload);
if payload_hash.as_bytes() != &received_payload_hash {
    return Err(CborError::PayloadHashMismatch);
}
```

replay guard は `(session, sequence, request ID, payload hash)` の 4 つ揃いで retry を判定する。hash を wire から取ると、この判定が guest の申告になる。

具体的な破れ方はこう。guest が request ID `R` に、以前受理された無害な payload の hash を載せて、中身だけ別の operation にする。guard は `RequestIdentityMismatch` ではなく `Duplicate` を返し、cache された outcome の経路に入る。frame が別の operation を主張しているのに、cache 済みの結果が返る。

## budget を adapter より先に取る

`budget.start` は request 数の token、並行 slot、応答 byte の予約を同時に取る。これが `executor.execute` より前にある。

逆にすると、`max_concurrent_requests` が in-flight な外部 I/O を縛らなくなる。fixture の `max_response_bytes = 128` に対して、32 MiB を宣言した fetch は、session の上限に当たる前に 32 MiB を network から読み終えている。

認可されない request も token を消費する。これは意図的で、探索の costs になる。

予約する量は operation によって出所が違う。

| operation | 予約量 |
|---|---|
| `PublicFetch` | operation が宣言した `max_response_bytes` |
| `GitHub` | host が持つ `github_response_cap` |

guest が宣言した値を public fetch で使えるのは、`http_fetch_matches` が `request.max_response_bytes <= authority.max_response_bytes` を要求し、`PublicFetcher::fetch` が redirect hop ごとに再検査するから。GitHub 側を guest 宣言にすると、provider 応答の予約量を guest が決めることになる。

`github_response_cap` は construction 時に `MAX_GITHUB_RESPONSE_BYTES` で clamp する。host が `u64::MAX` を渡しても、そこで止まる。

## 認可と副作用を 1 つの guard の内側に置く

`CapabilityKernel::authorize_and_commit` は、`state.authorizes(...)` から `commit_to_linearization(capability)` までの間、`state` の read guard を保持する。adapter の呼び出しはその内側にある。

外すと、認可の判定と HTTPS / GitHub 呼び出しの間に `revoke` が入りうる。失効した capability で pull request が作られる。audit の attempt も副作用を挟まなくなる。

## adapter は authority family で選ぶ

```rust
match (operation, capability.authority()) {
    (BrokerOperation::PublicFetch(_), AuthorityBody::HttpFetch(_)) => ...,
    (BrokerOperation::GitHub(_), AuthorityBody::GitHub(_)) => ...,
    _ => Err(AdapterError::OperationMismatch),
}
```

tuple で両方を同時に見る。`operation` だけで分岐して authority を arm の中で取り出す形にすると、arm 漏れが panic か誤った adapter 呼び出しになる。

kernel の `state.authorizes` が既に `AuthorityRequest` の variant を比較しているので、これは二重の検査である。外れると、公開 HTTP だけの capability で `CredentialProvider::credential_for` に到達し、GitHub の installation credential を取得できる。

## 実測 byte を計上してから成功を返す

```rust
if self.budget.complete(request_id, effect.response_bytes()).is_err() {
    let _ = self.budget.abort(request_id);
    (Self::rejected(request_id, BrokerRejection::AccountingInvariant), None)
}
```

`SessionBudget::complete` は予約を超える実測値に `ResponseExceedsReservation` を返し、**予約を解放しない。** だから直後の `abort` が要る。この 2 行は必ず対で置く。

計上しないと `committed_response_bytes` が増えず、`max_response_bytes` が session 合計ではなく 1 request の上限に退化する。

## 完全一致 retry が adapter を再実行しない仕組み

`dispatch_frame` は `New` 分岐でも `Duplicate` 分岐でも、`dispatch_new` の結果を `outcomes` に書き戻す。

```rust
self.outcomes.insert(
    envelope.request(),
    cached.unwrap_or_else(|| CachedOutcome::Final(response.clone())),
);
```

`dispatch_new` が `Some(CachedOutcome::RetryableBudget(_))` を返すのは、一時的な budget 拒否のときだけ。成功、executor の error、`AccountingInvariant` はいずれも `None` を返し、その場合は `Final` として確定する。

**両分岐で同じ書き戻しをすることが要点。** `Duplicate` 分岐だけ「`Some` のときだけ書き戻す」形にすると、いったん `RetryableBudget` になった entry が二度と `Final` に置き換わらず、以降の完全一致 retry がすべて adapter を再実行する。`CreatePullRequest` なら retry 1 回につき pull request 1 つになる。実際にその欠陥があり、`dispatcher_retries_transient_budget_denial_without_double_charging` が 3 回目の dispatch で cache から返ることを固定している。

## 監査の失敗を認可拒否と混ぜない

executor の失敗は 5 種類に分かれ、そのうち 2 つは「外部副作用が起きたかどうか」が違う。

| `ExecutorError` | 副作用 | budget | rejection |
|---|---|---|---|
| `NotAuthorized` | 起きていない | abort | `NotAuthorized` |
| `AuditUnavailable` | 起きていない（attempt を journal できず executor を呼んでいない） | abort | `AuditUnavailable` |
| `LockPoisoned` | 起きていない | abort | `AuditUnavailable` |
| `CommittedButUnrecorded` | **起きた可能性がある** | 予約額を計上 | `CommittedButUnrecorded` |
| `Adapter(_)` | 線形化点の前に失敗 | abort | adapter ごとの型付き rejection |

`CommittedButUnrecorded` は kernel の `EffectCommitError::CommittedButAudit` に対応する。kernel はこれを「executor は成功したが terminal な durable receipt を永続化できなかった。外部副作用は既に存在しうるので、呼び出し側は provider の冪等性か reconciliation で解決すること」と定義している。

したがって、これを `NotAuthorized` として返してはいけない。作成された pull request が「認可されなかった」と報告される。budget も abort しない。副作用が起きた分の byte を解放すると、guest が同じ量を二度使える。予約額をそのまま計上する。

[server](server.md) はこの rejection でも connection を閉じる。`AccountingInvariant` と同じく、operator が provider と突き合わせる必要がある状態だから。

## 時刻は request ごとに読む

`serve_connection` は caller / capability の identity と clock を別々に受け取り、request ごとに `DispatchContext` を作り直す。1 connection で 1 つの時刻を使い回すと、connection の途中で `TimeWindow` が閉じた capability が最後まで認可を通る。

## 検証済みの frame を再 encode しない

入口は 2 つある。`dispatch_frame` は bytes を受けて `decode_complete` で `ControlFrame` にし、`dispatch_control_frame` は transport が既に検証した `ControlFrame` をそのまま受ける。`dispatch_transport` と `RequestDispatcher::dispatch_request` は後者を使う。

以前は後者も `frame.encode()` してから `dispatch_frame` に渡していた。1 request あたり最大 1 MiB の copy が 2 回増えるうえ、production 経路が `decode_complete` を通ることになる。この関数の doc は「buffered な test input 用であり、確保順序の代わりにはならない」と述べていて、transport が持つ「長さを検査してから payload を確保する」順序を再現しない。

## その他の既知の問題

**HEAD が byte 予算を消費しない。** `BrokerEffect::response_bytes()` は public fetch で `response.body.len()` を返し、HEAD の応答は常に空。`start` で `max_response_bytes` を予約し、`complete` で 0 を計上する。HEAD は `max_requests` と並行 slot だけに縛られる。

**GitHub の byte 数は adapter の自己申告。** `response.response_bytes` をそのまま使う。検証するのは `TypedGitHubAdapter` だけで、別の `GitHubAdapter` 実装は過少申告できる。trait の signature には、この field が accounting の入力であることを示すものが無い。

## 正確な保証範囲

- adapter はすべて trait 越し。fake resolver / connector / provider を注入した module test で検証している。
- Firecracker guest-to-host の closed authorization rejection は opt-in KVM test で確認済み。direct kernel `AF_VSOCK`、外部 DNS / HTTPS、実 GitHub API は未検証。
- `CommittedButUnrecorded` を返した後の reconciliation 経路は、この crate に無い。rejection として区別するところまでで、provider との突き合わせは運用側の責務。
- GitHub の byte 自己申告を悪用する第三者 adapter 実装は、この crate では防げない。

## 変更時の確認点

- `Duplicate` 分岐と `New` 分岐の cache 書き戻しを揃えたままにする。片方を「`Some` のときだけ」に戻すと、retry が adapter を再実行する。
- `budget.complete` の失敗と直後の `abort` は必ず対で置く。`complete` が失敗しても予約は解放されない。
- `budget.start` を `executor.execute` の後ろへ動かさない。
- adapter の選択を tuple match 以外に変えない。arm 漏れが panic か誤 adapter になる。
- `MAX_GITHUB_RESPONSE_BYTES` を上げるときは `SessionBudgetLimits::max_response_bytes` も上げる。上げないと全 GitHub request が `budget.start` で `ResponseBytesExhausted` になる。clamp は `dispatch.rs` と `github.rs` の 3 箇所にあり、揃えて直す。
- rejection の種類を増やすときは `dispatch.rs`、`server.rs`、`BrokerWireRejection` の 3 箇所を同時に直す。wire の code は追記のみで、既存の番号を再割り当てしない。
- `CommittedButUnrecorded` の budget 処理を abort に変えない。副作用が起きた分の byte を guest が二度使える。

## 関連

- [Host Egress Broker](README.md)
- [transport 契約](transport.md)
- [公開 HTTPS policy](network-policy.md)
- [GitHub 型付き adapter](github.md)
- [検証対応表](verification.md)
- [Broker session envelope](../egress-protocol/session-envelopes.md)
- [Authorization guard](../authority-core/authorization-guard.md)
- [用語集](../glossary.md)
