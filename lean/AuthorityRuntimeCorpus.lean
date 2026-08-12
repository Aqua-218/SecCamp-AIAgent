import Authority.Refinement.RuntimeCorpus

/-!
# Runtime Corpus Executable

Reads proof-free Rust TSV observations, validates them with the existing Lean
refinement checkers, and emits their canonical normalized form.
-/

namespace AuthorityRuntimeCorpus

private def corpusPathFromArgs : List String → Except String String
  | [path] => .ok path
  | [] => .error "missing corpus path; usage: authority_runtime_corpus <runtime-corpus.tsv>"
  | _ => .error "too many arguments; usage: authority_runtime_corpus <runtime-corpus.tsv>"

private def runCorpus (path : String) : IO UInt32 := do
  try
    let input ← IO.FS.readFile path
    match Authority.Refinement.RuntimeCorpus.evaluateCorpus input with
    | .error error =>
        IO.eprintln s!"runtime corpus failed: {error}"
        pure 1
    | .ok lines =>
        for line in lines do
          IO.println line
        pure 0
  catch error =>
    IO.eprintln s!"runtime corpus failed: failed to read `{path}`: {error}"
    pure 1

end AuthorityRuntimeCorpus

def main (arguments : List String) : IO UInt32 :=
  match AuthorityRuntimeCorpus.corpusPathFromArgs arguments with
  | .ok path => AuthorityRuntimeCorpus.runCorpus path
  | .error error => do
      IO.eprintln s!"runtime corpus failed: {error}"
      pure 1
