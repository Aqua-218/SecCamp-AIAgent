<!-- doc-type: decision -->

# 0013. caller identity を受理済み connection から解決し、wire 上の claim を認可に使わない

[決定記録](README.md) / 0013

> **対象読者:** supervisor を触る実装者、認可の入口をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

VM の中で、複数の subject が supervisor に control request を送る。supervisor は要求ごとに「誰が送ってきたか」を決め、その subject の権限で処理する。

wire protocol の request には subject を表す field がある。guest が組み立てる bytes の一部なので、値は guest が決められる。

判断材料。

- subject の分離がこの基盤の第 1 の境界である。[設計書](../design/README.md)が挙げる 3 段のうち一番上で、これが破れると他が無意味になる。
- transport は local socket で、OS が peer の identity を持っている。
- request の decode は、subject を決めた後でも前でも書ける。
- guest 内の実装は信用しない。supervisor は VM の中にいるが、agent と tool は信用しない側にいる。

## 検討した選択肢

1. **wire の `claimed_subject` を使う** — request が名乗った subject で認可する
2. **claim を connection の identity と照合する** — 一致すれば claim を使う
3. **connection から解決し、claim は診断用にしか使わない**

### wire の `claimed_subject` を使う

request の subject field をそのまま認可に使う。

- 利点: 実装が最も単純。1 connection で複数 subject の要求を多重化できる。
- 欠点: guest が任意の subject を名乗れる。`CloseSubject` に他人の `SubjectId` を書けば、その subject を閉じられる。
- **採用しなかった理由:** subject 境界が消える。この基盤で最初に守るべき境界を、信用しない側が書いた 16 bytes に委ねることになる。認可の入口としてこれ以上悪い形は無い。

### claim を connection の identity と照合する

connection から subject を解決し、request の claim と一致することを確認してから claim を使う。

- 利点: 一致検査があるので、他人を名乗る要求は落ちる。claim が残るので、要求の意図が wire 上に明示される。
- 欠点: 一致するなら claim を使う理由が無い。connection から解決した値をそのまま使えば同じ結果になり、検査 1 つ分が不要になる。加えて、照合を書き忘れても正常系は通る。
- **採用しなかった理由:** 冗長な検査は、いつか外れる。「claim と一致するから claim を使う」という構造は、一致検査が認可の必須条件であることをコードから読み取りにくくする。認可に使う値が 2 系統あること自体が事故の余地になる。

## 決定

**`CallerResolver` が `ConnectionIdentity` から `SubjectId` を解決する。`Supervisor::dispatch_wire` は request の `claimed_subject` を認可に使わない。**

`ConnectionIdentity` は受理済み socket identity と peer credential を持つ。`claimed_subject` は診断用に保持してよいが、認可経路には現れない。

production の caller resolver は、**request bytes を decode する前に** subject binding を確定させる。`SOCK_SEQPACKET` または同等の認証済み connection を使う。decode より前に決めるのは、decode の失敗が subject の決定に影響しないようにするため。誰からの要求か分からないまま parse を始めない。

結果として、別 subject を claim した `CloseSubject` や `CloseHandle` は、claim を根拠に権限を得ない。要求は connection の subject の権限で処理され、その subject が対象を持っていなければ拒否される。

## 結果

- 1 connection = 1 subject になる。複数 subject の要求を 1 本の socket で多重化できない。connection の数が subject の数だけ要る。
- `claimed_subject` は request に残っている。認可に使わないので、値が間違っていても要求は通る。診断で読むときは「guest が名乗った値」であって事実ではないことを踏まえる。
- 同じ方針が Broker 側にもある。[transport 契約](../egress-broker/transport.md)の listener が peer identity を運び、認可に使う subject は connection から解決する。
- [ADR 0011](0011-require-an-expected-old-object-plan-for-publish-branch.md) が expected-old object を guest に決めさせなかったのと同じ形の判断。信用しない側が渡した値を安全条件に使わない。
- production の caller resolver は [`control_socket.rs`](../../crates/supervisor/src/control_socket.rs) にある。`SubjectControlListener` が subject ごとの `SOCK_SEQPACKET` socket を持ち、`SO_PEERCRED` から `ConnectionIdentity` を作り、`SubjectCredentialResolver` へ binding を登録してから connection を返す。request bytes へ到達する唯一の経路が accept 後の `receive_request` なので、「decode より前に subject を決める」がコードの規律ではなく型の性質になっている。実socket module testに加え、KVM gateがguest supervisorからlistener／Supervisor／isolation launcherまでのcompositionを確認する。

## 関連

- [Supervisor adapter](../supervisor/README.md)
- [transport 契約](../egress-broker/transport.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [0011](0011-require-an-expected-old-object-plan-for-publish-branch.md)
- [脅威モデル](../design/threat-model.md)
- [用語集](../glossary.md)
