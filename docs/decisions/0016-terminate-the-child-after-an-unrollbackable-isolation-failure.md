<!-- doc-type: decision -->

# 0016. rollback 不可能な isolation step の失敗後は child を再利用せず終了させる

[決定記録](README.md) / 0016

> **対象読者:** 隔離 backend を触る実装者、起動失敗時の後始末をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

`RuntimeIsolation::apply` は 13 step を順に実行し、失敗したら完了済みの step を逆順に rollback する。ところが 13 step のうち大半は kernel 上で戻せない。

namespace から出ることはできない。`pivot_root` の前の root には帰れない。Landlock ruleset、消した capability、`no_new_privs`、seccomp filter も一方向にしか進まない。

step 10 の Landlock が失敗したとき、その時点で child は次の状態にある。

```text
完了: namespace、UID/GID map、cgroup、rootfs pivot、
      workspace、tmpfs、/proc mask、/dev mask、fd close
未完了: Landlock、capability drop、no_new_privs、seccomp
```

この child をどう扱うかを決める必要があった。

判断材料。

- 完了済みの step は、それ自体が制限である。この child は既にかなり閉じ込められている。
- 未完了の step も制限である。seccomp が無ければ workload は `socket` を呼べる。capability を消していなければ mount を張り直せる。
- rollback を試みて失敗したこと自体が、host の状態を正確に把握できていない兆候である。
- child を作り直すコストは、process 1 つ分。VM の再起動ではない。

## 検討した選択肢

1. **完了済みの制限で続行する** — 部分的に隔離された child で workload を走らせる
2. **失敗した step だけ retry する** — child を保持したまま、その step をやり直す
3. **child を終了させ、再利用しない**

### 完了済みの制限で続行する

「namespace も cgroup も mount も効いている。seccomp が無いだけ」として exec を続ける。

- 利点: 起動が成功する。一時的な資源不足で Landlock が失敗した場合でも、workload が動く。
- 欠点: 欠けた step が何を防いでいたかによって、実質的な隔離レベルが変わる。しかもその判断は失敗時にしかできない。
- **採用しなかった理由:** 境界が 1 つ欠けた状態は、欠けていない状態と質的に違う。seccomp が無ければ workload は network syscall を呼べるので、[ADR 0009](0009-reject-the-whole-dns-answer-on-any-non-public-address.md) と [0010](0010-re-resolve-and-re-authorize-on-every-redirect.md) で組み立てた egress の制御が丸ごと迂回される。capability を消していなければ mount を張り直せるので、capfs を経由しない file 経路ができる。「ほぼ隔離されている」を成功として扱うと、その「ほぼ」の内訳が起動ごとに変わる。

### 失敗した step だけ retry する

child を保持したまま、失敗した `apply_step` を呼び直す。

- 利点: 一時的な失敗から回復できる。child を作り直すコストが要らない。
- 欠点: 失敗の原因が一時的かどうかを、`BackendError` から判定できない。errno があっても、それが再試行で解決するかは step ごとに違う。加えて、失敗した step が部分的に適用されている可能性がある。mount のように途中まで進む操作では、retry が同じ状態から始まらない。
- **採用しなかった理由:** retry が安全な step とそうでない step を区別できなかった。区別するには step ごとに冪等性を保証する必要があり、`pivot_root` や seccomp のように 1 度しか実行できない操作では成立しない。判定できない条件で retry を許すより、作り直すほうが状態が明確になる。

## 決定

**`IsolationError::Rollback` が返ったら、supervisor は child を再利用せず終了させる。**

`apply` は完了済み step を逆順に rollback し、失敗したものを集める。

```rust
IsolationError::Rollback {
    original: BackendError,
    failures: Vec<BackendError>,
}
```

production backend は、戻せない step について `rollback_step` から `BackendError` を返す。実装漏れではなく明示的な申告である。したがって、rollback 不可の step を 1 つでも完了していれば `Rollback` が返る。

呼び出し側は `original` を起動失敗として記録し、child を終了させる。新しい child を fork して最初からやり直す。

## 結果

- 起動失敗のコストが上がった。Landlock ABI の query が一時的に失敗しただけでも child を作り直す。
- `IsolationReceipt` は全 step が成功したときにだけ返る。receipt が存在することが、exec 前の境界が完成したことの機械的な証拠になる。部分的な receipt は無い。
- 「rollback 可能」と申告した step が実際に戻ることは検証していない。unmount と cgroup 削除の失敗経路は実機で確認していない。申告だけ変えると、部分成功を成功と誤認する経路ができる。
- `apply` を呼ぶ場所の制約と組で効く。`CLONE_NEWPID` は次の `fork` から適用されるので、この取引は workload を exec する child 側で開始する。親 supervisor は child の lifecycle を監視する立場にいて、終了させる判断ができる。
- 一時的な失敗が繰り返される環境では、起動が繰り返し失敗する。retry の上限や backoff はこの crate に無く、呼び出し側の責務。

## 関連

- [13 step の固定順序と rollback](../runtime-isolation/apply-order.md)
- [ポリシーの事前検査](../runtime-isolation/isolation-config.md)
- [seccomp allowlist](../runtime-isolation/seccomp-allowlist.md)
- [Landlock envelope](../runtime-isolation/landlock-envelope.md)
- [隔離基盤の設計](../design/runtime-isolation.md)
- [用語集](../glossary.md)
