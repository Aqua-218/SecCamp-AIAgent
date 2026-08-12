<!-- doc-type: decision -->

# 0011. `PublishBranch` に expected-old object の plan を必須とする

[決定記録](README.md) / 0011

> **対象読者:** GitHub 操作の実装者、branch 更新をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

agent が書いたコードを branch として publish する。これは guest が起こせる外部副作用のうち、取り返しがつかない側にある。

git の ref 更新には 2 通りある。fast-forward だけを許す通常の push と、既存 commit を捨てる force push。GitHub の ref 更新 API は `force` flag を持ち、既定は非 force だが、呼び出し側が指定できる。

判断材料。

- agent が publish する branch は、他の agent や人間が同時に触りうる。
- guest は自分が何を上書きするか把握していない。branch の現在の内容を知る手段は Broker 経由の取得だけで、それと publish の間に時間が空く。
- 一度消えた commit を GitHub から復元するのは、reflog に頼る操作で確実ではない。
- Broker は host 側にいて、GitHub の現在状態を読める。

## 検討した選択肢

1. **`force: false` だけを固定する** — GitHub の非 force 更新に任せる
2. **guest が expected-old object を指定する** — 要求に含めさせる
3. **host が用意した plan を必須にし、無ければ provider を呼ばない**

### `force: false` だけを固定する

adapter が常に `force: false` で ref を更新する。GitHub は fast-forward でない更新を拒否する。

- 利点: 実装が最小。GitHub 側の判定に任せられる。
- 欠点: fast-forward であれば通る。agent が古い base から作った branch を publish するとき、その間に他者が積んだ commit の上に載る形なら通ってしまう。何が起きたかは通った後にしか分からない。
- **採用しなかった理由:** 「上書きされない」ことは保証されるが、「意図した状態から更新した」ことは保証されない。agent の作業は非同期で、plan を立ててから publish するまでに branch が動く。fast-forward だから安全、という判断は人間が git を対話的に使う前提のもので、agent の作業単位には合わない。

### guest が expected-old object を指定する

`PublishBranch` の要求に expected-old object を含めさせ、adapter がそれを使う。

- 利点: guest が「この状態から更新する」を明示できる。実装も追加が少ない。
- 欠点: guest が指定する値なので、guest が現在の ref object をそのまま入れれば検査は常に通る。取得と publish の間に branch が動いても、guest が取得し直せば通る。
- **採用しなかった理由:** 検査の値を guest が決められる時点で、検査ではなくなる。guest が正しく振る舞えば安全になるが、この基盤は guest を信用しない前提で組んでいる。信用しない側が渡した値を安全条件に使うのは、認可を wire 上の claim に頼らないという [ADR 0013](0013-resolve-caller-identity-from-the-connection.md) と同じ間違い方をしている。

## 決定

**host が用意した `PublishBranchPlan` が無ければ、provider を呼ぶ前に `MissingPublishPrecondition` で拒否する。**

plan は expected-old object と expected-new object を持つ。provider は現在の ref object を読み、expected-old と一致することを確認してから `force: false` で更新する。一致しなければ `ProviderConflict`。

plan の object ID は 40 文字（SHA-1）または 64 文字（SHA-256）の hexadecimal として検証する。長さと文字種だけの検査だが、これが無いと任意の文字列が ref の比較対象として API に届く。

拒否は provider 呼び出しの**前**に行う。`publish_branch_without_expected_old_object_is_rejected` が固定しているのはこの順序で、「呼んでから失敗する」のではなく「呼ばない」ことが要点。呼んでしまうと rate limit を消費し、失敗の形が provider の実装に依存する。

## 結果

- plan を作る責務が host 側に移った。guest は publish を要求できるが、何から何へ更新するかは host が決める。plan を作る側を見れば、何が上書きされうるかが分かる。
- host が plan を作るためには、GitHub の現在状態を読む必要がある。読み取りと publish の間の window は残っている。閉じているのは「plan を立てた時点から動いていたら失敗する」ところまでで、window そのものは消えていない。
- `PublishBranch` に対応する plan が無い状態は正常系にもある。host がまだ plan を作っていない場合で、これも `MissingPublishPrecondition` になる。guest から見ると「拒否された」だけなので、原因の切り分けは host 側の log に依存する。
- expected-old object の比較そのものは provider の実装にある。この adapter は plan の有無と形式しか見ていない。定理でも test でも、比較が正しいことは示していない。
- 実 GitHub API との接続は未検証。`force: false` が実際に効くことは GitHub の仕様に依存する。

## 関連

- [GitHub 型付き adapter](../egress-broker/github.md)
- [GitHub authority](../authority-core/github-authorities.md)
- [0013](0013-resolve-caller-identity-from-the-connection.md)
- [ネットワークと外部副作用の設計](../design/network-egress.md)
- [用語集](../glossary.md)
