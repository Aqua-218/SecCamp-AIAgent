<!-- doc-type: decision -->

# 0017. alias を持つ inode は全ての名前で認可する

[決定記録](README.md) / 0017

> **対象読者:** capfs の実装者、link 対応の範囲を判断する人

## Status

Accepted (2026-08-12)

## 背景と課題

初期の capfs は link-free だった。symlink と hard link を preflight で拒否し、`SYMLINK` / `LINK` を `EPERM` で返し、「生きている object は必ず 1 つの canonical path を持つ」を不変条件にしていた。

一般的な Git repository はこれを満たさない。Git は symlink を mode `120000` の tree entry として表現する。link を含む workspace を扱えなければ、checkout そのものが失敗する。

link を入れると 2 つの前提が同時に壊れる。

- **hard link**: 1 つの inode に複数の canonical path が付く。認可は path に対して与えられているので、「どの path の権限で判定するか」が一意に決まらない。
- **symlink**: path 解決を行うのは capfs ではなく OS である。FUSE kernel は `READLINK` で target 文字列を受け取り、その後の walk を自分で進める。`..` の解決に capfs は呼ばれない。

後者が意味するのは、**capfs が返す文字列が唯一の強制点**だということである。target が mount の外へ出る形なら、kernel はそれを caller の mount namespace で解決してしまう。

## 検討した選択肢

### hard link をどう認可するか

1. **caller が使った名前だけで認可する**
2. **import 時に alias を解消し、各 path を別 inode へ複製する**
3. **inode の全ての名前で認可する（authority を交差で取る）**

#### caller が使った名前だけで認可する

- 利点: 実装が単純で、既存の path 単位の認可がそのまま使える。
- 欠点: **これは権限昇格そのものである。** `/secret/data.txt` への authority を持たない subject が、自分が支配する `/allowed/alias` に hard link を作れば、以後 `/allowed/alias` への `ReadData` だけで `/secret/data.txt` の中身が読める。inode は同じである。
- **採用しなかった理由:** path containment で証明できる性質が何も残らない。

#### import 時に alias を解消して複製する

- 利点: 不変条件を一切変えずに、hard link を含む repository を受け入れられる。
- 欠点: repository 内で完結している alias まで壊れる。片方への write がもう片方に見えない。Git が hard link を使う場面（object store の共有など）では、複製が容量と一貫性の両方を壊す。runtime の `LINK` も依然として作れない。
- **採用しなかった理由:** 全ての alias に適用する形では、「link を含む repository を拒否しない」だけで link に対応したことにならない。ただし**境界をまたぐ alias に限れば**この手段が最善であり、下の決定 4 でそこにだけ使う。

### symlink target をどう制限するか

1. **任意の target を保存し、そのまま返す**
2. **capfs が解決して、正規化した target を返す**
3. **解決が mount 内に留まると証明できる形だけ受理する**

#### 任意の target を保存し、そのまま返す

- **採用しなかった理由:** `/etc/shadow` を指す link を 1 つ置けば sandbox が終わる。kernel は絶対 path を caller の namespace で解決する。

#### capfs が解決して正規化した target を返す

registry 側で resolve し、`../` × depth + 解決後の repository 相対 path を返す。

- 利点: 全ての形の target を受理できる。
- 欠点: `readlink(2)` が書き込んだ値と違う値を返す。Git は symlink の blob 内容と `readlink` 出力を比較するので、全ての symlink が変更済みに見える。
- **採用しなかった理由:** 機能としては通るが、Git workspace という本来の用途を壊す。

## 決定

### 1. alias を持つ inode の authority は、全ての名前の authority の交差とする

`NamespaceObject` は自分を指す canonical path の**集合**を持つ。認可は `NamespaceObject::paths()` の全要素に対して行い、1 つでも許可されなければ操作は失敗する。可視性（`LOOKUP` / `GETATTR` / `READDIR`）も同じ規則に従う。

この規則の下では、**alias を増やすことで誰かの権限が広がることは決してない**。増えるのは要求される authority の方である。逆に、権限を持たない object を到達不能にする嫌がらせは可能なので、`LINK` は新しい名前と既存の全ての名前の両方に `CreateHardLink` を要求する。

directory は alias を持てない。Linux 自身が禁じており、`..` と subtree 規則が扱えない。

### 2. symlink target は「解決が mount 内に留まると証明できる形」だけ受理する

文法を次に限る。

- 相対 path のみ。絶対 path は拒否する。
- `..` は**先頭の連続部分にのみ**現れてよい。
- 各名前付き component は canonical path segment の規則を満たす。
- 4096 byte 以内。

先頭の `..` だけを許すのは、それが link 自身の祖先 directory を辿るからである。registry 上、path の親は必ず directory であり、この pop は一意に決まる。名前付き component の後ろの `..` は、その component 自身が浅い directory を指す symlink だった場合、字句上の containment 検査が通っても kernel の walk は root の上に出る。この形を予測するのではなく、受理しないことで穴を消す。

target は registry が保持し、`READLINK` のたびに**link の現在の path から**再解決する。rename は同じ literal の意味を変えるので、登録時の判定を使い回さない。解決が repository の外へ出るなら `EXDEV` を返し、文字列そのものを kernel に渡さない。`FUSE_CACHE_SYMLINKS` は要求しない。要求すれば、この再検査を経ずに kernel が古い body を辿り続ける。

### 3. repository の外に名前がある inode は、境界をまたぐ関係だけを切る

外に名前がある inode は repository の部分的な view でしかない。決定 1 の交差規則は「object の全ての名前」を列挙できることを前提にしており、外の名前は列挙できない。ここだけは alias を維持したまま安全にする方法がない。

既定では preflight が**内容を repository 内の新しい inode へ複製し、repository 側の名前をその複製へ移す**。外の名前は元の inode を持ったまま触らない。repository 内で互いに alias だった名前は複製の alias として残るので、切れるのは境界をまたぐ関係だけである。

repository 全体を拒否する選択肢も残す（`ExternalAliasPolicy::Reject`）が、既定にはしない。stray な hard link が1本あるだけで workspace ごと使えなくなり、手で直す以外の道がなくなるためである。

実体化は backing tree を書き換えるので、次を課す。

- 複製する総 byte 数に上限を置く。敵対的な tree が startup を無制限の copy に変えられない。
- 置き換えは一時名の上に作り、`renameat` で名前へ移す。repository の名前が一瞬でも消えない。
- 実体化した名前を呼び出し側へ返す。tree を書き換えた事実は報告される。
- 修復 pass は1回だけ。その後もう一度 scan して厳密に照合し、まだ外部 alias があれば拒否する。

import 後に外部 alias が現れた場合（`nlink` 不一致）は fail closed のままにする。その時点で、その名前が敵対的かどうかを判断する材料が capfs にない。

### 4. effect を 3 つ増やす

| effect | 許可する操作 |
|---|---|
| `ReadLink` | symlink の target を読む |
| `CreateSymlink` | symlink を作る |
| `CreateHardLink` | 既存 inode に名前を増やす |

`FileEffect` は 13 variant になった。discriminant は durable audit record に符号化されるため、追加は末尾のみとし、既存の値を動かさない。`u16` bitset の上限 16 まで残り 3。

## 結果

- `NamespaceObject` は `primary` と `aliases` を分けて持つ。「生きている object は必ず名前を 1 つ以上持つ」が型の性質になり、registry が覚える規則ではなくなった。
- 最後の 1 つでない名前の削除は、inode を孤立させないので open handle の有無に依らず許される。最後の名前の削除は従来どおり `EBUSY` を返す。
- runtime の link count 検査は `nlink == 1` から `nlink == 名前の数` に変わった。capfs 経由で作られた link は registry が知っているので、**capfs の外で作られた名前は依然として検出される**。preflight も同様に、inode の名前が全て repository 内にあることを要求し、満たさない inode は決定 3 に従って実体化するか拒否する。
- `RepositoryEntry` は inode 番号を持ち、manifest import が同一 inode の名前を 1 つの object にまとめる。
- preflight が startup 中に backing tree を書き換えうるようになった。これは新しい副作用であり、`materialized_aliases` として報告される。書き込みを許さない配置では `rejecting_external_aliases` を使う。
- 実体化の後に tree を再 scan するため、preflight の走査は最大 2 回になる。root fd の複製は directory offset を共有するので、scan は `openat(root, ".")` で開き直す。
- 交差規則は保守的な方向にしか働かないが、**利用者から見て驚きうる**。capability の範囲外に別名を持つ file は、範囲内の名前からも読めず listing にも出ない。これは事故ではなく設計である。workspace 自体が非信頼である以上、片方の名前だけで認可すれば hostile な tree が secret を範囲内へ hard link するだけで読めてしまう。
- `SYMLINK` / `LINK` / `MKNOD` の 3 つが fuser の default 実装任せだった問題も併せて閉じた。`MKNOD` は「未実装」ではなく policy による拒否なので、`ENOSYS` ではなく `EPERM` を明示的に返す。

## 関連

- [capfs の設計](../design/capfs.md)
- [Direct-I/O FUSE adapter](../capfs/read-only-fuse.md)
- [Backing repository の事前検証](../capfs/backing-preflight.md)
- [共有 namespace registry](../capfs/namespace-registry.md)
- [0002](0002-split-file-permissions-into-ten-effects.md)
- [0005](0005-separate-object-identity-from-path.md)
- [用語集](../glossary.md)
