# 公開 HTTPS policy

[Host Egress Broker](README.md) / 公開 HTTPS policy

> **対象読者:** 公開 egress の実装者、SSRF 対策をレビューする担当者

`PublicFetcher` は型付き `HttpFetchRequest` と `HttpFetchAuthority` を受け取り、次の制約を適用する。

- HTTPS の port 443 だけを許可する。
- `GET` と `HEAD` だけを許可する。
- request body と caller-controlled header を受け付けない。
- host policy の response 上限は既定 32 MiB とし、request の上限でさらに狭める。
- redirect は最大 5 hop とする。
- connector の接続 timeout は既定 10 秒、fetch 全体の timeout は既定 60 秒とする。
- redirect の各 hop で DNS を再解決する。
- DNS 応答に public でない address が一つでもあれば、応答全体を拒否する。
- 検証済みの address へ接続し、canonical host を TLS/SNI と HTTP authority に使う。
- 自動 redirect と ambient proxy を無効にする。

redirect の `Location` は、canonical な HTTPS origin、port 443、userinfo なし、query なし、fragment なしでなければならない。redirect 後の host と path は元の HTTP authority と照合してから、次の DNS 解決へ進む。したがって、private address や public/private 混在の DNS 応答は、別の address が public であっても fail closed になる。

組み込み deny set は private、loopback、link-local、metadata、multicast、unspecified、CGNAT、documentation、benchmarking などの IPv4/IPv6 special-purpose range を含む。host は deny CIDR を追加できるが、組み込み範囲を削除できない。IPv4-mapped IPv6 address は対応する IPv4 address として判定する。

connector が受け取るのは検証済みの `FetchTarget`、検証済みの `SocketAddr`、閉じた `HttpFetchMethod` だけである。生 URL、任意の header map、body bytes、credential は connector の API に現れない。本文は `GET` の場合だけ bounded streaming で読み、上限を最初に越えた read で拒否する。`HEAD` の本文は読まず、返却本文も空にする。

## 検証状態

fake resolver と fake connector を使う module test で、GET/HEAD、private または混在 DNS 応答、redirect ごとの再解決、authority 外 redirect、unsafe redirect、response 上限を検証済みである。実 DNS、外部 HTTPS、実際の redirect chain、実ネットワークの rebinding は未検証である。

## 関連

- [Host Egress Broker](README.md)
- [transport 契約](transport.md)
- [ネットワークと外部副作用の設計](../design/network-egress.md)
- [検証対応表](verification.md)
