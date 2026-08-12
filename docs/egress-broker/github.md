# GitHub 型付き adapter

[Host Egress Broker](README.md) / GitHub 型付き adapter

> **対象読者:** GitHub provider adapter 実装者、認証情報境界のレビュー担当者

この adapter には汎用 HTTP fallback がなく、`egress-protocol` の二つの操作だけを provider 呼び出しへ変換する。

| 操作 | provider へ渡す入力 | 必須の安全確認 |
| --- | --- | --- |
| `PublishBranch` | 認可済み要求と、ホスト側の `PublishBranchPlan` | 現在の ref object が expected-old object と一致すること。更新は `force: false` |
| `CreatePullRequest` | 認可済みの base/head 要求 | 固定 endpoint と Broker が生成する固定 title |

要求の installation は opaque な `CredentialHandle` を選ぶ。この handle は token ではなく、token bytes への変換もない。production の `RustlsGitHubProvider` は host adapter 内だけで環境変数 `EGRESS_GITHUB_TOKEN` を読み、`Debug` では token を `<redacted>` と表示し、redirect と proxy を無効にする。token は guest request、broker outcome、provider error のいずれにも入らない。

`GitHubProviderError` と `GitHubAdapterError` は unauthorized、forbidden、not found、conflict、server、transport、invalid response、rate limit を型付きで区別する。rate limit には provider が返した場合だけ remaining、reset、retry-after を保持する。生の provider body は返さない。

`PublishBranch` は要求に対応する plan がなければ provider 呼び出し前に `MissingPublishPrecondition` で拒否する。plan の object ID は 40 文字または 64 文字の hexadecimal に検証される。repository route と branch component は長さと文字種を検査してから、二つの固定 GitHub endpoint を組み立てる。branch の予約文字は path segment として percent encode される。

## 検証状態

`TypedGitHubAdapter` と fake provider の module test で、opaque credential、publish plan、rate-limit metadata、provider 呼び出し前の拒否、branch route の encoding を検証済みである。`RustlsGitHubProvider` が実 GitHub API と接続する test、実環境変数を使う test、実際の credential を使う test は実施していない。

## 関連

- [Host Egress Broker](README.md)
- [公開 HTTPS policy](network-policy.md)
- [検証対応表](verification.md)
