<!-- doc-type: decision -->

# 0008. Broker は型付きの閉じた操作だけを公開し、生 URL と任意 HTTP メソッドを持たない

[決定記録](README.md) / 0008

> **対象読者:** egress を設計する人、新しい外部操作を足そうとしている人

## Status

Accepted (2026-08-12)

## 背景と課題

guest は network device を持たない。外部へ届く手段は vsock 越しの Broker だけで、その API の形が guest にできることの上限を決める。

agent には少なくとも 2 種類の外部アクセスが要る。公開 web の取得（ドキュメント、パッケージ index）と、認証付きの GitHub 操作（branch の publish、pull request の作成）。

判断材料。

- Broker は host 側にいて、GitHub token を持つ。
- guest は信用しない。API が許すことは全部やられる前提で設計する。
- 必要な操作は増える。今は 2 つでも、後から追加要求が来る。
- API が広いほど、認可の対象が曖昧になる。「この URL を叩いてよいか」は「この操作をしてよいか」より判定しにくい。

## 検討した選択肢

1. **HTTPS proxy として公開する** — guest が普通の HTTP client を使い、Broker が proxy として検査する
2. **URL を Capability の単位にする** — 「この URL に GET してよい」という権限を渡す
3. **型付きの閉じた操作だけを公開する**

### HTTPS proxy として公開する

Broker が `CONNECT` を受け、許可した host だけ通す。

- 利点: guest 側の実装が要らない。既存の HTTP client、パッケージマネージャ、git がそのまま動く。移植性が高い。
- 欠点: `CONNECT` を通した後は TLS の中身が見えない。host 単位でしか制御できず、method も path も body も検査できない。TLS を終端すれば見えるが、今度は Broker が全通信の平文を持つことになる。
- **採用しなかった理由:** GitHub 操作を扱えない。proxy として `api.github.com` を許可すると、その時点で token の権限全体が使える。公開 web だけなら proxy でも成立するが、認証付き操作と同じ経路に載せられない。経路を 2 つに分けるくらいなら、最初から操作単位で設計するほうがよかった。

### URL を Capability の単位にする

`https://docs.example/guide/**` に `GET` してよい、という権限を渡し、Broker はその範囲の URL を取得する。

- 利点: 公開 web の取得には十分な表現力がある。実際、[HTTP fetch authority](../authority-core/http-fetch-authorities.md) はこの形に近い。
- 欠点: 認証付き操作を URL で表すと、`POST https://api.github.com/repos/*/pulls` のような権限になる。この形は body の中身を制御できない。同じ endpoint に別の body を送れば、別のことが起きる。
- **採用しなかった理由:** 認証付き操作の安全条件が URL に現れない。`PublishBranch` の安全性は expected-old object の一致で決まる（[ADR 0011](0011-require-an-expected-old-object-plan-for-publish-branch.md)）が、これは URL でも method でも表現できない。URL を単位にすると、その条件を強制する場所が無くなる。

## 決定

**Broker が公開するのは 2 種類の型付き操作だけにする。**

```text
公開 HTTPS: 認証情報を使わない GET と HEAD
GitHub:     PublishBranch と CreatePullRequest
```

生の URL、任意の HTTP メソッド、任意の header や body、proxy 認証情報、guest が指定した credential を受け付ける API は存在しない。

公開 HTTPS は host / path / method / 応答上限の 4 軸を持つ authority で認可する。URL に近い形だが、scheme は HTTPS 固定、port は 443 固定、query と fragment は型の入口で拒否する。

GitHub 操作は operation 名で認可する。endpoint は adapter が固定文字列から組み立て、guest が渡すのは検証済みの branch 名と repository identity だけ。

新しい操作を足すには、`BrokerOperation` に variant を足し、authority の enum を広げ、adapter に request builder を書き、canonical CBOR の schema を拡張し、Lean 側の定義と corpus を更新する。設定変更では増えない。

## 結果

- guest 側で普通の HTTP client、パッケージマネージャ、`git` が動かない。agent が `cargo fetch` を実行するといった作業は、そのままでは成立しない。これが最も大きな代償で、実運用で最初に当たる制約になる。
- 操作を増やすコストが高い。5 箇所を同時に変更する必要がある。意図的にそうしているが、開発速度は落ちる。
- 認可の対象が「操作」なので、レビューで「この subject は何ができるか」を列挙できる。URL の集合を眺めて推測する必要がない。
- `CreatePullRequest` の title は Broker が生成する固定文字列。guest が任意の text を外部へ出す経路を作らない。
- token は `CredentialHandle` として扱い、guest の request にも outcome にも provider error にも現れない。
- 公開 HTTPS で `POST` を必要とする作業（パッケージの publish、API への書き込み）は、この設計では扱えない。必要になったら、その操作を型付き操作として設計し直す。`POST` を許すのではない。

## 関連

- [Host Egress Broker](../egress-broker/README.md)
- [HTTP fetch authority](../authority-core/http-fetch-authorities.md)
- [GitHub authority](../authority-core/github-authorities.md)
- [GitHub 型付き adapter](../egress-broker/github.md)
- [0011](0011-require-an-expected-old-object-plan-for-publish-branch.md)
- [ネットワークと外部副作用の設計](../design/network-egress.md)
- [用語集](../glossary.md)
