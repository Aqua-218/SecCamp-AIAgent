<!-- doc-type: decision -->

# 0018. host と guest の authority を policy digest と revocation barrier で結ぶ

[決定記録](README.md) / 0018

> **対象読者:** authority、session orchestration、guest-control、Firecracker runtime の実装者

## Status

Accepted (2026-08-17)

## 背景と課題

host Broker と guest CapFS は別 process、別 `CapabilityKernel` で動く。host の
`AuthorityCoreBackend` が発行する guest 用 root は guest VM へ転送されず、guest は
immutable image の boot arguments から同じ形の root を独立に構築している。したがって
現在の identity injection だけでは、host grant と guest が強制する policy が同一である
ことも、host の revoke が生存中の guest kernel に到達したことも証明できない。

- guest に host credential や汎用 authority API を渡してはならない。
- snapshot restore ごとの identity 非再利用と既存 wire v1 の fail-closed 性を維持する。
- revoke 完了後に新しい file/egress effect が開始してはならない。
- guest が応答不能でも、VM kill によって authority domain を閉じられなければならない。

## 検討した選択肢

1. **guest kernel を唯一の authority owner にする** — Broker は効果ごとに guest の証明を受け取る
2. **host kernel を唯一の authority owner にする** — guest は host へ全 filesystem 判定を問い合わせる
3. **二つの local kernel を policy digest と revocation barrier で結ぶ** — 定常判定は local、境界遷移だけ同期する

### guest kernel を唯一の authority owner にする

- 利点: revoke state は一つになり、guest 内の file authority と自然に一致する。
- 欠点: host credential を使う Broker が untrusted guest の可用性と protocol に依存し、effect ごとの往復が増える。guest compromise 時の host egress 強制点も弱くなる。
- **採用しなかった理由:** credential と external effect の最終強制点を host に残すという Broker の境界を壊す。

### host kernel を唯一の authority owner にする

- 利点: policy と revoke state を完全に一元化できる。
- 欠点: FUSE の全操作が VM 境界を往復し、host control channel が filesystem hot path と単一障害点になる。guest isolation だけで閉じる file authority も host availability に依存する。
- **採用しなかった理由:** local CapFS の guard と性能特性を失い、接続断時の open handle semantics が複雑になる。

## 決定

**二つの local kernel を policy digest と revocation barrier で結ぶ案を採用する。**

root policy は encoding version、validity、delegable flag、typed `AuthorityBody` の全 field を
length-delimited canonical bytes にし、SHA-256 digest を取る。Rust の `Hash`、enum
discriminant の暗黙 layout、debug text は wire contract に使わない。

host は grant 発行前に digest を計算する。guest-control v2 は restoration challenge、全
identity と同じ canonical request に digest/version を含める。guest supervisor は image に
焼かれた typed policy から同じ digest を独立計算し、一致しなければ subject を作らず
workload readiness も返さない。snapshot manifest は image/rootfs digest と policy digest を
同時に束縛し、legacy v1 image と v2 production host の混在を拒否する。

停止は二段階である。host kernel の guest/Broker roots を先に revoke し、新しい host
effect を止める。その後、認証済み guest revoke ACK を受けるか VM とその cgroup の
termination を確認するまで cross-domain revoke は完了扱いにしない。ACK が期限内に来なければ
VM kill へ移る。kill も確認できない場合は session を `Stopping` に残し、workspace と
snapshot clone を再利用しない。

## 結果

- 定常時の file/Broker authorization は local のままで、cross-domain traffic は session 境界だけになる。
- `AuthorityPolicyDigest` の encoding version は snapshot/control protocol の compatibility field になる。authority field を追加したら version と migration が必要になる。
- v1 wire bytes は parser compatibility のため残せるが、production composition は unbound v1 を受理しない。
- host root revoke だけを「guest revoke 完了」と呼べなくなる。orchestrator の cleanup receipt は host revoke と guest barrier/VM termination を別 stage で保持する。
- guest ACK は可用性上の最適化であり、security fallback は cgroup ごとの VM termination である。
- guest v2 verification、snapshot template/request/manifest の policy digest binding、起動前に
  永続化される session recovery intent、host revoke 後の VM/cgroup termination barrier を実装した。
  guest 応答に依存せず kill 確認まで cleanup を完了扱いにしないため、この決定を Accepted とする。

## 関連

- [設計書](../design/architecture.md)
- [snapshot と identity gate](../firecracker-runtime/snapshot-and-identity.md)
- [0014](0014-keep-the-workspace-when-vm-kill-fails.md)
- [0015](0015-persist-the-identity-ledger-across-restarts.md)
- [用語集](../glossary.md)
