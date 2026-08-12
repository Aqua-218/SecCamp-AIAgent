//! Evaluates the shared authority decision corpus with the Rust implementation.

use std::{collections::HashSet, env, fs, path::PathBuf, process};

use authority_core::{
    capability::{
        AuthorityBody, AuthorityRequest, CapId, Capability, CapabilityMetadata, CapabilityRequest,
        IssuerId, SubjectId, capability_matches, weaker_than,
    },
    file::{FileAuthority, FileEffect, FileEffects, FileRequest, file_body_below, file_matches},
    path::{CanonicalPath, PathPattern, path_below, path_matches},
    repository::RepoId,
    time::{MonotonicTime, TimeWindow},
};

const CORPUS_HEADER: &str = "# authority-corpus-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseResult {
    name: String,
    actual: bool,
}

struct Fields<'a> {
    values: std::str::Split<'a, char>,
    consumed: usize,
}

impl<'a> Fields<'a> {
    fn new(line: &'a str) -> Self {
        Self {
            values: line.split('\t'),
            consumed: 0,
        }
    }

    fn take(&mut self, label: &str) -> Result<&'a str, String> {
        let value = self.values.next().ok_or_else(|| {
            format!(
                "missing {label} at field {}; check the corpus schema",
                self.consumed + 1
            )
        })?;
        self.consumed += 1;
        Ok(value)
    }

    fn finish(mut self) -> Result<(), String> {
        match self.values.next() {
            Some(extra) => Err(format!(
                "unexpected field {} with value `{extra}`; check the corpus schema",
                self.consumed + 1
            )),
            None => Ok(()),
        }
    }
}

fn parse_bool(value: &str, label: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!(
            "invalid {label} `{value}`; expected `true` or `false`"
        )),
    }
}

fn parse_ticks(value: &str, label: &str) -> Result<MonotonicTime, String> {
    value
        .parse::<u64>()
        .map(MonotonicTime::from_ticks)
        .map_err(|error| format!("invalid {label} `{value}`; expected u64 ticks: {error}"))
}

fn decode_segments(encoded: &str) -> Vec<String> {
    if encoded == "-" {
        Vec::new()
    } else {
        encoded
            .split('|')
            .map(|segment| segment.replace("\\0", "\0"))
            .collect()
    }
}

fn parse_path(encoded: &str, label: &str) -> Result<CanonicalPath, String> {
    CanonicalPath::new(decode_segments(encoded))
        .map_err(|error| format!("invalid {label} `{encoded}`: {error}"))
}

fn parse_pattern(fields: &mut Fields<'_>, role: &str) -> Result<PathPattern, String> {
    let kind = fields.take(&format!("{role} pattern kind"))?;
    let encoded_path = fields.take(&format!("{role} pattern path"))?;
    let path = parse_path(encoded_path, &format!("{role} pattern path"))?;

    match kind {
        "exact" => Ok(PathPattern::Exact(path)),
        "prefix" => Ok(PathPattern::Prefix(path)),
        _ => Err(format!(
            "invalid {role} pattern kind `{kind}`; expected `exact` or `prefix`"
        )),
    }
}

fn parse_effect(value: &str, label: &str) -> Result<FileEffect, String> {
    match value {
        "read_data" => Ok(FileEffect::ReadData),
        "list_directory" => Ok(FileEffect::ListDirectory),
        "write_data" => Ok(FileEffect::WriteData),
        "truncate" => Ok(FileEffect::Truncate),
        "create_file" => Ok(FileEffect::CreateFile),
        "create_directory" => Ok(FileEffect::CreateDirectory),
        "remove_file" => Ok(FileEffect::RemoveFile),
        "remove_directory" => Ok(FileEffect::RemoveDirectory),
        "rename" => Ok(FileEffect::Rename),
        "set_metadata" => Ok(FileEffect::SetMetadata),
        _ => Err(format!("invalid {label} `{value}`; expected a file effect")),
    }
}

fn parse_effects(encoded: &str, label: &str) -> Result<FileEffects, String> {
    if encoded == "-" {
        return Ok(FileEffects::empty());
    }

    encoded
        .split('|')
        .map(|value| parse_effect(value, label))
        .collect::<Result<Vec<_>, _>>()
        .map(FileEffects::from_effects)
}

fn parse_file_authority(fields: &mut Fields<'_>, role: &str) -> Result<FileAuthority, String> {
    let repository = RepoId::new(fields.take(&format!("{role} repository"))?);
    let encoded_effects = fields.take(&format!("{role} effects"))?;
    let effects = parse_effects(encoded_effects, &format!("{role} effects"))?;
    let path = parse_pattern(fields, role)?;
    Ok(FileAuthority::new(repository, effects, path))
}

fn parse_file_request(fields: &mut Fields<'_>, role: &str) -> Result<FileRequest, String> {
    let repository = RepoId::new(fields.take(&format!("{role} repository"))?);
    let encoded_effect = fields.take(&format!("{role} effect"))?;
    let effect = parse_effect(encoded_effect, &format!("{role} effect"))?;
    let encoded_path = fields.take(&format!("{role} path"))?;
    let path = parse_path(encoded_path, &format!("{role} path"))?;
    Ok(FileRequest::new(repository, effect, path))
}

fn parse_time_window(fields: &mut Fields<'_>, role: &str) -> Result<TimeWindow, String> {
    let not_before = parse_ticks(
        fields.take(&format!("{role} not_before"))?,
        &format!("{role} not_before"),
    )?;
    let expires_at = parse_ticks(
        fields.take(&format!("{role} expires_at"))?,
        &format!("{role} expires_at"),
    )?;
    TimeWindow::new(not_before, expires_at)
        .map_err(|error| format!("invalid {role} time window: {error}"))
}

fn corpus_metadata() -> CapabilityMetadata {
    CapabilityMetadata::new(
        CapId::new("corpus-capability"),
        SubjectId::new("corpus-subject"),
        IssuerId::new("corpus-runner"),
    )
}

fn parse_capability(fields: &mut Fields<'_>, role: &str) -> Result<Capability, String> {
    let validity = parse_time_window(fields, role)?;
    let authority = parse_file_authority(fields, role)?;
    Ok(Capability::new(
        corpus_metadata(),
        validity,
        AuthorityBody::File(authority),
    ))
}

fn parse_capability_request(
    fields: &mut Fields<'_>,
    role: &str,
) -> Result<CapabilityRequest, String> {
    let time = parse_ticks(
        fields.take(&format!("{role} time"))?,
        &format!("{role} time"),
    )?;
    let request = parse_file_request(fields, role)?;
    Ok(CapabilityRequest::new(
        time,
        AuthorityRequest::File(request),
    ))
}

fn evaluate_operation(kind: &str, fields: &mut Fields<'_>) -> Result<bool, String> {
    match kind {
        "path_valid" => {
            let encoded = fields.take("path")?;
            Ok(CanonicalPath::new(decode_segments(encoded)).is_ok())
        }
        "path_matches" => {
            let pattern = parse_pattern(fields, "authority")?;
            let encoded_path = fields.take("request path")?;
            let path = parse_path(encoded_path, "request path")?;
            Ok(path_matches(&pattern, &path))
        }
        "path_below" => {
            let child = parse_pattern(fields, "child")?;
            let parent = parse_pattern(fields, "parent")?;
            Ok(path_below(&child, &parent))
        }
        "time_valid" => {
            let not_before = parse_ticks(fields.take("not_before")?, "not_before")?;
            let expires_at = parse_ticks(fields.take("expires_at")?, "expires_at")?;
            Ok(TimeWindow::new(not_before, expires_at).is_ok())
        }
        "time_matches" => {
            let window = parse_time_window(fields, "authority")?;
            let time = parse_ticks(fields.take("request time")?, "request time")?;
            Ok(window.contains(time))
        }
        "time_below" => {
            let child = parse_time_window(fields, "child")?;
            let parent = parse_time_window(fields, "parent")?;
            Ok(child.is_subset_of(parent))
        }
        "file_matches" => {
            let authority = parse_file_authority(fields, "authority")?;
            let request = parse_file_request(fields, "request")?;
            Ok(file_matches(&authority, &request))
        }
        "file_below" => {
            let child = parse_file_authority(fields, "child")?;
            let parent = parse_file_authority(fields, "parent")?;
            Ok(file_body_below(&child, &parent))
        }
        "capability_matches" => {
            let capability = parse_capability(fields, "authority")?;
            let request = parse_capability_request(fields, "request")?;
            Ok(capability_matches(&capability, &request))
        }
        "weaker_than" => {
            let child = parse_capability(fields, "child")?;
            let parent = parse_capability(fields, "parent")?;
            Ok(weaker_than(&child, &parent))
        }
        _ => Err(format!(
            "unknown case kind `{kind}`; expected a supported authority decision"
        )),
    }
}

fn evaluate_case(line: &str, line_number: usize) -> Result<CaseResult, String> {
    let mut fields = Fields::new(line);
    let kind = fields
        .take("case kind")
        .map_err(|error| format!("line {line_number}: {error}"))?;
    let name = fields
        .take("case name")
        .map_err(|error| format!("line {line_number}: {error}"))?
        .to_owned();
    let expected = parse_bool(
        fields
            .take("expected result")
            .map_err(|error| format!("line {line_number} ({name}): {error}"))?,
        "expected result",
    )
    .map_err(|error| format!("line {line_number} ({name}): {error}"))?;
    let actual = evaluate_operation(kind, &mut fields)
        .map_err(|error| format!("line {line_number} ({name}): {error}"))?;
    fields
        .finish()
        .map_err(|error| format!("line {line_number} ({name}): {error}"))?;

    if actual != expected {
        return Err(format!(
            "line {line_number} ({name}): expected {expected}, but Rust returned {actual}"
        ));
    }

    Ok(CaseResult { name, actual })
}

fn evaluate_corpus(input: &str) -> Result<Vec<CaseResult>, String> {
    let mut saw_header = false;
    let mut names = HashSet::new();
    let mut results = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let line_number = index + 1;
        if line == CORPUS_HEADER {
            saw_header = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !saw_header {
            return Err(format!(
                "line {line_number}: missing `{CORPUS_HEADER}` before the first case"
            ));
        }

        let result = evaluate_case(line, line_number)?;
        if !names.insert(result.name.clone()) {
            return Err(format!(
                "line {line_number}: duplicate case name `{}`; names must be unique",
                result.name
            ));
        }
        results.push(result);
    }

    if !saw_header {
        return Err(format!("missing corpus header `{CORPUS_HEADER}`"));
    }
    if results.is_empty() {
        return Err("authority corpus contains no cases".to_owned());
    }

    Ok(results)
}

fn corpus_path_from_args() -> Result<PathBuf, String> {
    let mut arguments = env::args_os().skip(1);
    let path = arguments.next().ok_or_else(|| {
        "missing corpus path; usage: authority-corpus <tests/fixtures/authority-core.tsv>"
            .to_owned()
    })?;
    if arguments.next().is_some() {
        return Err(
            "too many arguments; usage: authority-corpus <tests/fixtures/authority-core.tsv>"
                .to_owned(),
        );
    }
    Ok(PathBuf::from(path))
}

fn run() -> Result<(), String> {
    let path = corpus_path_from_args()?;
    let input = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read authority corpus `{}`: {error}",
            path.display()
        )
    })?;
    let results = evaluate_corpus(&input)?;

    for result in results {
        println!("{}\t{}", result.name, result.actual);
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("authority corpus failed: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    //! Specification: `docs/design/verification.md`, shared corpus differential testing.
    //! Coverage: valid execution plus malformed, mismatched, and ambiguous fixtures.

    use std::fs;

    use super::{CORPUS_HEADER, evaluate_corpus};

    const CORPUS_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/authority-core.tsv"
    );

    // Category: contract/boundary. Mutation target: any changed authority decision or bound.
    #[test]
    fn shared_corpus_matches_all_rust_decisions() {
        let input = fs::read_to_string(CORPUS_PATH).expect("shared corpus must be readable");

        let results = evaluate_corpus(&input).expect("all Rust decisions must match the corpus");

        assert_eq!(results.len(), 101, "every version-one case must execute");
        assert_eq!(results[0].name, "path-root-is-valid");
        assert_eq!(
            results.last().map(|result| result.name.as_str()),
            Some("empty-capability-does-not-bypass-structure")
        );
    }

    // Category: error. Mutation target: accepting unversioned fixture formats.
    #[test]
    fn corpus_rejects_a_case_before_the_version_header() {
        let error = evaluate_corpus("path_valid\troot\ttrue\t-\n")
            .expect_err("an unversioned corpus must fail closed");

        assert!(error.contains("missing `# authority-corpus-v1`"));
    }

    // Category: error. Mutation target: silently ignoring unknown decision families.
    #[test]
    fn corpus_rejects_an_unknown_case_kind() {
        let input = format!("{CORPUS_HEADER}\nunknown\tcase-name\ttrue\n");

        let error = evaluate_corpus(&input).expect_err("an unknown case kind must fail closed");

        assert!(error.contains("unknown case kind `unknown`"));
    }

    // Category: error. Mutation target: missing-field defaults and permissive parsing.
    #[test]
    fn corpus_rejects_a_missing_required_field() {
        let input = format!("{CORPUS_HEADER}\npath_valid\tcase-name\ttrue\n");

        let error = evaluate_corpus(&input).expect_err("a truncated case must fail closed");

        assert!(error.contains("missing path at field 4"));
    }

    // Category: boundary/error. Mutation target: accepting ticks outside Rust's u64 domain.
    #[test]
    fn corpus_rejects_a_tick_above_the_u64_maximum() {
        let input =
            format!("{CORPUS_HEADER}\ntime_valid\toverflow\ttrue\t0\t18446744073709551616\n");

        let error = evaluate_corpus(&input).expect_err("out-of-domain ticks must fail closed");

        assert!(error.contains("expected u64 ticks"));
    }

    // Category: contract. Mutation target: two implementations agreeing on the wrong answer.
    #[test]
    fn corpus_rejects_a_result_that_disagrees_with_the_oracle() {
        let input = format!("{CORPUS_HEADER}\npath_valid\troot\tfalse\t-\n");

        let error = evaluate_corpus(&input).expect_err("an oracle mismatch must fail the run");

        assert!(error.contains("expected false, but Rust returned true"));
    }

    // Category: contract. Mutation target: ambiguous output keys in the differential report.
    #[test]
    fn corpus_rejects_duplicate_case_names() {
        let input =
            format!("{CORPUS_HEADER}\npath_valid\troot\ttrue\t-\npath_valid\troot\ttrue\t-\n");

        let error = evaluate_corpus(&input).expect_err("duplicate names must fail the run");

        assert!(error.contains("duplicate case name `root`"));
    }
}
