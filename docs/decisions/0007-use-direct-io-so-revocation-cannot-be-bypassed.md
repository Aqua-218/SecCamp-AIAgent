<!-- doc-type: decision -->

# 0007. FUSE adapter を Direct-I/O にし、page cache に revoke を迂回させない

[決定記録](README.md) / 0007

> **対象読者:** capfs を触る実装者、失効の実効性をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

revoke は Capability を失効させる。失効した後、その Capability を根拠にした操作は通ってはいけない。

FUSE では、guest の `read(2)` が必ず filesystem daemon に届くとは限らない。kernel は page cache を持ち、一度読んだ内容を保持する。同じ範囲を再度読むと、cache から返る。daemon は呼ばれない。

判断材料。

- revoke は VM 内のいつでも起きる。open してから read するまでの間にも起きる。
- page cache は kernel が管理する。daemon から明示的に無効化する手段はあるが、範囲と timing の制御は限定的。
- Direct-I/O は cache を経由しない。すべての read が daemon に届く。
- Direct-I/O は性能を落とす。同じ内容を繰り返し読む作業で顕著になる。

## 検討した選択肢

1. **page cache を使い、revoke 時に無効化する** — `FUSE_NOTIFY_INVAL_INODE` を送る
2. **open 時にだけ認可する** — cache から返る read は認可済みとみなす
3. **Direct-I/O にして、毎 read を認可する**

### page cache を使い、revoke 時に無効化する

通常の cached I/O を使い、revoke が起きたら該当 inode の cache を無効化する。

- 利点: 性能が出る。FUSE の一般的な使い方で、周辺の挙動も枯れている。
- 欠点: 無効化と revoke の間に window がある。revoke が返った後、無効化が完了するまでに cache から読める。無効化の完了を待つ API はあるが、待っている間に別の read が進む。
- **採用しなかった理由:** [設計書](../design/README.md)が掲げる revoke の約束を満たせない。「revoke が返った後に commit される副作用は、失効した Capability を根拠には実行されない」という主張が、cache 無効化の完了 timing に依存することになる。kernel 側の非同期処理に安全性を預ける形で、証明も test もできない。

### open 時にだけ認可する

`OPEN` で認可し、以降の `READ` は fd の存在を根拠に通す。

- 利点: 認可のコストが 1 回で済む。POSIX の一般的な意味論と一致する。
- 欠点: open している間の revoke が効かない。長時間開いたままの fd に対して、revoke が事実上意味を持たない。
- **採用しなかった理由:** revoke の粒度が open handle の寿命になってしまう。agent が file を開いたまま長時間作業する場合、その間の失効が反映されない。失効を「次に開くときから」ではなく「今から」にしたかった。

## 決定

**FUSE adapter を Direct-I/O で動かし、`READ` / `WRITE` / `SETATTR` / `READDIR` のたびに現在 path で再認可する。**

すべての read が daemon に届くので、認可を通さずに内容が返る経路が無い。認可は `ObjectId` から引いた**現在の** path に対して行う（[ADR 0005](0005-separate-object-identity-from-path.md)）ので、rename で権限範囲の外に出た object もそこで拒否される。

実 mount 上の test で、revoke 後の既存 file descriptor からの read / write / size 変更 / mode 変更、既存 directory stream からの次の listing、既存 parent directory fd に対する `mkdirat` が拒否されることを確認している。

directory listing は cookie で位置を保持する。listing の途中で create / remove / rename が成功した場合、古い cookie を使わず `EAGAIN` で再開を要求する。既に消えた entry を返さないため。

## 結果

- 性能が落ちる。同じ file を繰り返し読む作業で、毎回 daemon への往復と認可判定が走る。これがこの決定の主要なコストで、workload の性質によっては無視できない。
- 認可判定が hot path に入った。判定を純粋関数にし、allocation を避ける実装（`FileEffects` の `u16` bitset など）が要求されるのは、ここから来ている。
- `ObjectId` を引いてから現在 path を得る手順が、read ごとに走る。registry の lock 契約がこの頻度で呼ばれる前提になっている。
- revoke の意味が「今から効く」になった。open handle の寿命に縛られない。
- FUSE の `writeback_cache` や `auto_inval_data` といった最適化は使えない。将来これらを検討する場合、この ADR を `Superseded` にする必要がある。
- 実 mount test はあるが、変更系 operation と revoke を同時に競合させる統合 test は無い。並行での実効性は未検証。

## 関連

- [Direct-I/O FUSE adapter](../capfs/read-only-fuse.md)
- [共有 namespace registry](../capfs/namespace-registry.md)
- [0005](0005-separate-object-identity-from-path.md)
- [状態機械と revoke](../design/state-and-revocation.md)
- [capfs 設計](../design/capfs.md)
- [用語集](../glossary.md)
