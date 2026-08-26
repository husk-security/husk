//! Jupyter kernels + notebooks (`*.ipynb`, `kernel.json`) → trait id
//! `jupyter`. Jupyter itself has no OSV namespace, so `parse` emits found
//! coordinates under the *existing* OSV-covered ecosystems (like `docker.rs`
//! / `precommit.rs` do):
//!
//!   * `pip`/`uv` install magics → `"pypi"`, names PEP 503-normalized,
//!     version only for exact `==` pins.
//!   * `npm`/`yarn`/`pnpm`/`bun` install lines → `"npm"`, names verbatim
//!     (scope preserved), version only for exact `pkg@x.y.z` pins.
//!
//! Coordinates with no usable version are valid inventory rows (version ""
//! = "present, version unknown") and must NOT be sent to OSV with a
//! fabricated version. A `kernel.json` yields at most one versionless
//! presence entry. Only `cells[].source` is walked, never the potentially
//! huge `outputs[]`.

use super::support::{Emitter, read_text, unquote};
use super::{ScanTarget, exact_semver_pin, file_name, pep503_name};
use serde_json::Value as JsonValue;
use std::path::Path;

/// Trait-level id only; `parse()` deliberately emits `pypi`/`npm` coords.
const ECOSYSTEM_ID: &str = "jupyter";

pub struct JupyterTarget;

impl ScanTarget for JupyterTarget {
    fn ecosystem_id(&self) -> &'static str {
        ECOSYSTEM_ID
    }

    fn detects(&self, path: &Path) -> bool {
        let Some(name) = file_name(path) else {
            return false;
        };
        name.ends_with(".ipynb") || name == "kernel.json"
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if file_name(path) == Some("kernel.json") {
            parse_kernel_json(&contents, out);
        } else {
            parse_notebook(&contents, out);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Coord {
    ecosystem: &'static str,
    name: String,
    version: String,
}

fn parse_notebook(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("notebook is not valid JSON");
        return;
    };
    let Some(cells) = root.get("cells").and_then(JsonValue::as_array) else {
        return;
    };
    for cell in cells {
        if cell.get("cell_type").and_then(JsonValue::as_str) != Some("code") {
            continue;
        }
        let Some(source) = cell.get("source") else {
            continue;
        };
        let text = normalize_source(source);
        for coord in scan_cell_text(&text) {
            let line = super::find_line(contents, &coord.name);
            out.pkg_in(coord.ecosystem, &coord.name, &coord.version, line);
        }
    }
}

/// nbformat `source` is either a single string or an array of strings, where
/// each array element already ends in `\n`; join array elements with `""`.
fn normalize_source(source: &JsonValue) -> String {
    match source {
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(parts) => parts
            .iter()
            .filter_map(JsonValue::as_str)
            .collect::<String>(),
        _ => String::new(),
    }
}

fn scan_cell_text(text: &str) -> Vec<Coord> {
    let mut out = Vec::new();
    for logical in join_continuations(text) {
        out.extend(scan_line(&logical));
    }
    out
}

/// Join trailing-backslash physical-line continuations into logical lines.
fn join_continuations(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw in text.split('\n') {
        if let Some(stripped) = raw.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
        } else {
            current.push_str(raw);
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// A line may chain several installs via `&&`, `;` or `|`.
fn scan_line(line: &str) -> Vec<Coord> {
    let mut out = Vec::new();
    for segment in split_chains(line) {
        out.extend(scan_segment(&segment));
    }
    out
}

fn split_chains(line: &str) -> Vec<String> {
    let normalized = line
        .replace("&&", "\n")
        .replace("||", "\n")
        .replace([';', '|'], "\n");
    normalized.split('\n').map(str::to_string).collect()
}

/// Strip a leading magic prefix (`!`, `%`, `%%`), detect the package manager,
/// and tokenize the install args.
fn scan_segment(segment: &str) -> Vec<Coord> {
    let stripped = strip_magic_prefix(segment.trim());
    let tokens: Vec<&str> = stripped.split_whitespace().collect();
    if tokens.is_empty() {
        return Vec::new();
    }

    let Some((ecosystem, verb_idx)) = classify(&tokens) else {
        return Vec::new();
    };
    let args = &tokens[verb_idx + 1..];

    let mut out = Vec::new();
    let mut skip_next = false;
    for &tok in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if flag_takes_value(tok) {
            skip_next = true;
            continue;
        }
        if tok.starts_with('-') {
            continue;
        }
        let cleaned = unquote(tok);
        if cleaned.is_empty() {
            continue;
        }
        if let Some(coord) = parse_spec(ecosystem, cleaned) {
            out.push(coord);
        }
    }
    out
}

/// Flags that consume the following token as a value (a file, URL, host, or
/// directory, never a package spec). The `--flag=value` form needs no entry:
/// it is skipped by the generic `-` branch. One combined pip+npm list keeps
/// the code dumb; the tools' flags don't collide in practice.
fn flag_takes_value(flag: &str) -> bool {
    matches!(
        flag,
        // pip / uv: files and constraints
        "-r" | "--requirement" | "-c" | "--constraint"
        // pip / uv: index and host selection
        | "-i" | "--index-url" | "--extra-index-url" | "--trusted-host"
        // pip: install destinations
        | "-t" | "--target" | "--prefix" | "--root" | "--src"
        // pip: platform/interpreter overrides
        | "--platform" | "--python-version" | "--implementation" | "--abi" | "--python"
        // npm / pnpm / yarn / bun
        | "-w" | "--workspace" | "--registry" | "--tag"
    )
}

fn strip_magic_prefix(segment: &str) -> &str {
    let s = segment.strip_prefix('!').unwrap_or(segment);
    let s = s.strip_prefix("%%").unwrap_or(s);
    let s = s.strip_prefix('%').unwrap_or(s);
    s.trim_start()
}

/// Map a tokenized command to `(ecosystem, verb_index)`. Conda installs are
/// deliberately not routed (they belong to `conda.rs`, not OSV PyPI).
fn classify(tokens: &[&str]) -> Option<(&'static str, usize)> {
    let first = *tokens.first()?;
    match first {
        "pip" | "pip3" => find_verb(tokens, 0, &["install"]).map(|i| ("pypi", i)),
        "python" | "python3" => {
            let m = tokens.get(1)?;
            let pip = tokens.get(2)?;
            if *m == "-m" && (*pip == "pip") {
                find_verb(tokens, 2, &["install"]).map(|i| ("pypi", i))
            } else {
                None
            }
        }
        "uv" => {
            let sub = *tokens.get(1)?;
            if sub == "pip" {
                find_verb(tokens, 1, &["install"]).map(|i| ("pypi", i))
            } else if sub == "add" {
                Some(("pypi", 1))
            } else {
                None
            }
        }
        "conda" | "mamba" | "micromamba" => None,
        "npm" | "pnpm" | "bun" => {
            find_verb(tokens, 0, &["install", "i", "add"]).map(|i| ("npm", i))
        }
        "yarn" => find_verb(tokens, 0, &["add"]).map(|i| ("npm", i)),
        _ => None,
    }
}

/// First verb token at or after `start`; global flags before the verb don't
/// confuse the index.
fn find_verb(tokens: &[&str], start: usize, verbs: &[&str]) -> Option<usize> {
    tokens
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|&(_, &t)| verbs.contains(&t))
        .map(|(i, _)| i)
}

fn parse_spec(ecosystem: &'static str, spec: &str) -> Option<Coord> {
    if ecosystem == "pypi" {
        parse_pip_spec(spec)
    } else {
        parse_npm_spec(spec)
    }
}

/// Version only for exact `==` / `===` pins; name PEP 503-normalized with
/// extras stripped. VCS/URL/path installs skipped.
fn parse_pip_spec(spec: &str) -> Option<Coord> {
    if spec == "."
        || spec.starts_with("git+")
        || spec.starts_with("hg+")
        || spec.starts_with("svn+")
        || spec.starts_with("bzr+")
        || spec.contains("://")
        || spec.starts_with('.')
        || spec.starts_with('/')
        || spec.ends_with(".whl")
        || spec.ends_with(".tar.gz")
    {
        return None;
    }

    let (name_part, version) = if let Some(idx) = spec.find("===") {
        (&spec[..idx], spec[idx + 3..].to_string())
    } else if let Some(idx) = spec.find("==") {
        (&spec[..idx], spec[idx + 2..].to_string())
    } else {
        // Any other specifier is a range: keep the name, version unknown.
        let cut = spec
            .find(['<', '>', '~', '!', '=', '*', ' ', ','])
            .unwrap_or(spec.len());
        (&spec[..cut], String::new())
    };

    let name = pep503_name(strip_extras(name_part));
    if name.is_empty() {
        return None;
    }
    Some(Coord {
        ecosystem: "pypi",
        name,
        version: version.trim().to_string(),
    })
}

/// Only `pkg@x.y.z` exact pins carry a version; ranges, tags and
/// git/url/file specs do not. Split on the LAST `@`: a leading `@` is a
/// scope, not a version separator.
fn parse_npm_spec(spec: &str) -> Option<Coord> {
    if spec.starts_with("git+")
        || spec.contains("://")
        || spec.starts_with('.')
        || spec.starts_with('/')
        || spec.starts_with("file:")
        || spec.starts_with("github:")
    {
        return None;
    }

    let (name, raw_version) = match spec.rfind('@') {
        Some(0) | None => (spec, ""),
        Some(idx) => (&spec[..idx], &spec[idx + 1..]),
    };
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let version = exact_semver_pin(raw_version).unwrap_or_default();
    Some(Coord {
        ecosystem: "npm",
        name: name.to_string(),
        version,
    })
}

fn strip_extras(name: &str) -> &str {
    match name.find('[') {
        Some(idx) => &name[..idx],
        None => name,
    }
}

/// `kernel.json` → at most one versionless presence entry. `argv[0]` points
/// at a backing interpreter/venv, not a coordinate. Kernel name = parent
/// directory (jupyter kernelspec layout), else display_name, else "kernel".
fn parse_kernel_json(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("kernel.json is not valid JSON");
        return;
    };
    let dir_name = out
        .path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str());
    let name = dir_name
        .map(str::to_string)
        .or_else(|| {
            root.get("display_name")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "kernel".to_string());
    if name.is_empty() {
        return;
    }
    out.pkg_in(ECOSYSTEM_ID, &name, "", None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pip_exact_pin_normalizes_and_versions() {
        let c = parse_pip_spec("Flask_Cors==4.0.0").unwrap();
        assert_eq!(c.ecosystem, "pypi");
        assert_eq!(c.name, "flask-cors");
        assert_eq!(c.version, "4.0.0");
    }

    #[test]
    fn pip_range_is_inventory_only() {
        let c = parse_pip_spec("numpy>=1.26").unwrap();
        assert_eq!(c.name, "numpy");
        assert_eq!(c.version, "");
    }

    #[test]
    fn pip_extras_stripped() {
        let c = parse_pip_spec("flask[async]==3.0.0").unwrap();
        assert_eq!(c.name, "flask");
        assert_eq!(c.version, "3.0.0");
    }

    #[test]
    fn pip_vcs_skipped() {
        assert!(parse_pip_spec("git+https://example.com/x.git").is_none());
        assert!(parse_pip_spec(".").is_none());
    }

    #[test]
    fn npm_exact_pin() {
        let c = parse_npm_spec("left-pad@1.3.0").unwrap();
        assert_eq!(c.ecosystem, "npm");
        assert_eq!(c.name, "left-pad");
        assert_eq!(c.version, "1.3.0");
    }

    #[test]
    fn npm_scope_no_version() {
        let c = parse_npm_spec("@org/pkg").unwrap();
        assert_eq!(c.name, "@org/pkg");
        assert_eq!(c.version, "");
    }

    #[test]
    fn npm_scoped_with_version() {
        let c = parse_npm_spec("@org/pkg@1.2.3").unwrap();
        assert_eq!(c.name, "@org/pkg");
        assert_eq!(c.version, "1.2.3");
    }

    #[test]
    fn npm_tag_is_not_version() {
        let c = parse_npm_spec("lodash@latest").unwrap();
        assert_eq!(c.name, "lodash");
        assert_eq!(c.version, "");
    }

    #[test]
    fn npm_range_is_not_version() {
        let c = parse_npm_spec("react@^18.0.0").unwrap();
        assert_eq!(c.name, "react");
        assert_eq!(c.version, "");
    }

    #[test]
    fn npm_exact_pin_normalization_matches_catalogs() {
        let c = parse_npm_spec("pkg@v1.2.3-beta.1+build.5").unwrap();
        assert_eq!(c.name, "pkg");
        assert_eq!(c.version, "1.2.3-beta.1");

        let partial = parse_npm_spec("pkg@1.2").unwrap();
        assert_eq!(partial.version, "");
    }

    #[test]
    fn array_source_joined_without_separator() {
        let src = serde_json::json!([
            "%pip install requests==2.31.0 numpy>=1.26\n",
            "!pip install pandas==2.2.2 'scikit-learn'\n"
        ]);
        let text = normalize_source(&src);
        let coords = scan_cell_text(&text);
        // requests==, pandas==, scikit-learn (no ver), numpy (no ver)
        let req = coords.iter().find(|c| c.name == "requests").unwrap();
        assert_eq!(req.version, "2.31.0");
        let nm = coords.iter().find(|c| c.name == "numpy").unwrap();
        assert_eq!(nm.version, "");
        let sk = coords.iter().find(|c| c.name == "scikit-learn").unwrap();
        assert_eq!(sk.version, "");
    }

    #[test]
    fn conda_install_skipped() {
        let coords = scan_cell_text("!conda install numpy=1.26\n");
        assert!(coords.is_empty());
    }

    #[test]
    fn requirement_file_not_a_package() {
        let coords = scan_cell_text("!pip install -r requirements.txt\n");
        assert!(coords.is_empty());
    }

    #[test]
    fn value_taking_option_arguments_are_not_packages() {
        // pip: `--trusted-host mirror.example` must not emit `mirror.example`.
        let coords =
            scan_cell_text("!pip install --trusted-host mirror.example requests==2.31.0\n");
        assert_eq!(coords.len(), 1);
        assert_eq!(coords[0].name, "requests");
        assert_eq!(coords[0].version, "2.31.0");

        // npm: `--workspace app` must not emit `app`.
        let coords = scan_cell_text("!npm install --workspace app lodash@4.17.21\n");
        assert_eq!(coords.len(), 1);
        assert_eq!(coords[0].name, "lodash");
        assert_eq!(coords[0].version, "4.17.21");

        // The `=`-joined form does not consume the next token.
        let coords = scan_cell_text("!pip install --index-url=https://mirror.example flask\n");
        assert_eq!(coords.len(), 1);
        assert_eq!(coords[0].name, "flask");
    }

    #[test]
    fn python_m_pip_install() {
        let coords = scan_cell_text("!python -m pip install httpx==0.27.0\n");
        let c = coords.iter().find(|c| c.name == "httpx").unwrap();
        assert_eq!(c.ecosystem, "pypi");
        assert_eq!(c.version, "0.27.0");
    }

    #[test]
    fn backslash_continuation_joined() {
        let coords = scan_cell_text("!pip install \\\n  django==5.0\n");
        let c = coords.iter().find(|c| c.name == "django").unwrap();
        assert_eq!(c.version, "5.0");
    }

    #[test]
    fn malformed_notebook_is_empty() {
        use crate::scan::targets::support::run_parser;
        assert!(run_parser("jupyter", "{not json", parse_notebook).is_empty());
        assert!(run_parser("jupyter", "[]", parse_notebook).is_empty());
    }
}
