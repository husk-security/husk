//! Read-only source excerpts: the file a finding sits in, tokenized once here
//! so the TUI and the web UI colour the same line the same way.
//!
//! The lexer is deliberately small. Husk flags config files (manifests,
//! lockfiles, workflows, dotfiles, MCP configs) far more often than it flags
//! source code, and those need four token classes, not a grammar. Two families
//! cover the set: `#`-comment (YAML, TOML, shell, Python, ini) and
//! `//`-comment with `/* */` blocks (JSON, JS/TS, Rust, Go, C-likes).
//!
//! ponytail: token classes, not grammars. Nothing here parses structure, so a
//! keyword inside a template literal is coloured as a keyword. Swap in a real
//! grammar (syntect, tree-sitter) only when a surface needs semantics; the
//! `Class` vocabulary both front ends render against would not change.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::Serialize;

/// Largest file the viewer opens. Above this the excerpt is not worth the read:
/// a bundled lockfile or a vendored blob has nothing to show a reader, and the
/// TUI reads it on the UI thread.
const MAX_BYTES: u64 = 1024 * 1024;

/// Lines kept either side of the finding's line. Both surfaces scroll, so this
/// is one window wide enough to give the flagged line its context.
pub const RADIUS: u32 = 40;

/// Bytes sampled when deciding a file is binary.
const SNIFF_BYTES: usize = 8192;

/// What a token is, at the resolution both front ends render. Serialized in
/// lowercase as the `class` field of `/api/source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Whitespace, identifiers, and anything unclassified.
    Plain,
    /// The left-hand side of a `key: value` or `key = value` line.
    Key,
    Str,
    Num,
    Comment,
    Keyword,
    Punct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Token {
    pub class: Class,
    pub text: String,
}

impl Token {
    fn new(class: Class, text: impl Into<String>) -> Self {
        Self {
            class,
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceLine {
    /// 1-based line number in the file, not in the excerpt.
    pub number: u32,
    pub tokens: Vec<Token>,
}

/// A window of one file, ready to render.
#[derive(Debug, Clone, Serialize)]
pub struct Excerpt {
    pub path: PathBuf,
    /// The finding's line, when it named one. Both surfaces mark it.
    pub focus: Option<u32>,
    /// Lines in the whole file, so a surface can say what it is not showing.
    pub total_lines: u32,
    pub lines: Vec<SourceLine>,
}

/// Read `path` and tokenize the window around `focus`.
///
/// The caller owns the decision that this path may be read: the web handler
/// checks it against the current report, the TUI passes a finding's own path.
/// Nothing here consults the report, so nothing here may take a path straight
/// from a request.
pub fn excerpt(path: &Path, focus: Option<u32>, radius: u32) -> Result<Excerpt> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => bail!("cannot read {}: {err}", path.display()),
    };
    if !meta.is_file() {
        bail!("not a file: {}", path.display());
    }
    if meta.len() > MAX_BYTES {
        bail!(
            "{} is too large to preview ({} KB). Open it in your editor.",
            path.display(),
            meta.len() / 1024
        );
    }
    let bytes = std::fs::read(path)?;
    if bytes.iter().take(SNIFF_BYTES).any(|b| *b == 0) {
        bail!("{} is a binary file", path.display());
    }
    let text = String::from_utf8_lossy(&bytes);

    let span = radius * 2 + 1;
    let first = match focus {
        Some(line) => line.saturating_sub(radius).max(1),
        None => 1,
    };
    let last = first.saturating_add(span - 1);

    // Lexed from the top of the file rather than from `first` so a block
    // comment opened above the window is still open inside it.
    let mut lexer = Lexer::new(lang_for(path));
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate().take(last as usize) {
        let number = index as u32 + 1;
        let tokens = lexer.line(raw);
        if number >= first {
            lines.push(SourceLine { number, tokens });
        }
    }

    Ok(Excerpt {
        path: path.to_path_buf(),
        focus,
        total_lines: text.lines().count() as u32,
        lines,
    })
}

/// Words worth a colour in any of the families husk shows. One shared set: a
/// superset only mis-colours an identifier that happens to spell a keyword,
/// and per-language sets would be five lists to keep in step for that.
const KEYWORDS: &[&str] = &[
    "true", "false", "null", "nil", "none", "yes", "no", "on", "off", "if", "then", "else", "elif",
    "fi", "for", "in", "do", "done", "while", "case", "esac", "return", "function", "fn", "def",
    "class", "struct", "impl", "trait", "enum", "pub", "use", "mod", "const", "let", "var",
    "import", "from", "export", "async", "await", "match", "new", "this", "self", "try", "catch",
    "throw", "raise", "with", "as", "and", "or", "not", "run", "env", "copy",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lang {
    /// `#` line comments: YAML, TOML, shell, Python, ini, dotfiles.
    Hash,
    /// `//` line comments and `/* */` blocks: JSON, JS/TS, Rust, Go, C-likes.
    Curly,
    /// Everything else. Markdown, logs, certificates: one Plain token per line.
    Plain,
}

fn lang_for(path: &Path) -> Lang {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "json" | "jsonc" | "json5" | "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts"
        | "cts" | "rs" | "go" | "java" | "kt" | "kts" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs"
        | "php" | "swift" | "scala" | "gradle" | "css" | "scss" | "proto" => return Lang::Curly,
        "yaml" | "yml" | "toml" | "lock" | "sh" | "bash" | "zsh" | "fish" | "py" | "rb" | "ini"
        | "cfg" | "conf" | "properties" | "env" | "tf" | "tfvars" | "nix" | "pl" | "r" | "mk" => {
            return Lang::Hash;
        }
        _ => {}
    }
    // Config files husk reads constantly have no extension, or an extension
    // that is really a suffix (`.env.local`, `.bashrc`).
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let hash = name.starts_with(".env")
        || name.starts_with(".bash")
        || name.starts_with(".zsh")
        || matches!(
            name.as_str(),
            "dockerfile"
                | "containerfile"
                | "makefile"
                | "gemfile"
                | "rakefile"
                | "procfile"
                | ".profile"
                | ".gitconfig"
                | ".npmrc"
                | ".netrc"
                | ".curlrc"
                | "credentials"
                | "config"
                | ".gitignore"
                | ".dockerignore"
        );
    if hash { Lang::Hash } else { Lang::Plain }
}

/// Line-at-a-time lexer carrying only what genuinely spans lines: whether a
/// `/* */` block is open.
struct Lexer {
    lang: Lang,
    in_block: bool,
}

impl Lexer {
    fn new(lang: Lang) -> Self {
        Self {
            lang,
            in_block: false,
        }
    }

    fn line(&mut self, raw: &str) -> Vec<Token> {
        // Expanded here so a tab is one width in both a terminal cell grid and
        // a browser, and every column count downstream is the same count.
        let text: Vec<char> = raw.replace('\t', "    ").chars().collect();
        if self.lang == Lang::Plain {
            return vec![Token::new(
                Class::Plain,
                text.into_iter().collect::<String>(),
            )];
        }

        let mut out: Vec<Token> = Vec::new();
        let mut i = 0;
        while i < text.len() {
            if self.in_block {
                i = self.block(&text, i, &mut out);
                continue;
            }
            let c = text[i];
            let next = text.get(i + 1).copied();
            match c {
                '#' if self.lang == Lang::Hash => {
                    out.push(Token::new(Class::Comment, rest(&text, i)));
                    break;
                }
                '/' if self.lang == Lang::Curly && next == Some('/') => {
                    out.push(Token::new(Class::Comment, rest(&text, i)));
                    break;
                }
                '/' if self.lang == Lang::Curly && next == Some('*') => {
                    self.in_block = true;
                    i = self.block(&text, i, &mut out);
                }
                '"' | '\'' | '`' => i = string(&text, i, &mut out),
                c if c.is_ascii_digit() => i = number(&text, i, &mut out),
                c if c.is_alphabetic() || c == '_' => i = word(&text, i, &mut out),
                c if c.is_whitespace() => {
                    i = run(&text, i, Class::Plain, &mut out, char::is_whitespace);
                }
                c if PUNCT.contains(c) => {
                    out.push(Token::new(Class::Punct, c.to_string()));
                    i += 1;
                }
                c => {
                    out.push(Token::new(Class::Plain, c.to_string()));
                    i += 1;
                }
            }
        }
        mark_key(&mut out);
        out
    }

    /// Consume an open `/* */` block from `start` to its close or to the end of
    /// the line, whichever comes first.
    fn block(&mut self, text: &[char], start: usize, out: &mut Vec<Token>) -> usize {
        // A block opening on this line starts past its own `/*`, so the scan
        // for the close cannot read that `*` as the closing one: `/*/` is an
        // open comment, not a closed one.
        let mut i = if text.get(start) == Some(&'/') && text.get(start + 1) == Some(&'*') {
            start + 2
        } else {
            start
        };
        while i < text.len() {
            if text[i] == '*' && text.get(i + 1) == Some(&'/') {
                i += 2;
                self.in_block = false;
                break;
            }
            i += 1;
        }
        out.push(Token::new(
            Class::Comment,
            text[start..i].iter().collect::<String>(),
        ));
        i
    }
}

const PUNCT: &str = "{}[]()<>,:;=+-*/&|!?%^~@$\\.";

fn rest(text: &[char], from: usize) -> String {
    text[from..].iter().collect()
}

fn run(
    text: &[char],
    from: usize,
    class: Class,
    out: &mut Vec<Token>,
    take: impl Fn(char) -> bool,
) -> usize {
    let mut i = from;
    while i < text.len() && take(text[i]) {
        i += 1;
    }
    out.push(Token::new(class, text[from..i].iter().collect::<String>()));
    i
}

/// A quoted run. An unterminated quote takes the rest of the line: YAML and
/// TOML both have multi-line strings, and colouring the tail as code is the
/// worse of the two wrong answers.
fn string(text: &[char], from: usize, out: &mut Vec<Token>) -> usize {
    let quote = text[from];
    let mut i = from + 1;
    while i < text.len() {
        if text[i] == '\\' {
            i += 2;
            continue;
        }
        if text[i] == quote {
            i += 1;
            break;
        }
        i += 1;
    }
    let end = i.min(text.len());
    out.push(Token::new(
        Class::Str,
        text[from..end].iter().collect::<String>(),
    ));
    end
}

fn number(text: &[char], from: usize, out: &mut Vec<Token>) -> usize {
    run(text, from, Class::Num, out, |c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_'
    })
}

fn word(text: &[char], from: usize, out: &mut Vec<Token>) -> usize {
    let mut i = from;
    while i < text.len() && (text[i].is_alphanumeric() || text[i] == '_') {
        i += 1;
    }
    let word: String = text[from..i].iter().collect();
    let class = if KEYWORDS.contains(&word.to_ascii_lowercase().as_str()) {
        Class::Keyword
    } else {
        Class::Plain
    };
    out.push(Token::new(class, word));
    i
}

/// Re-class the first token of a `key: value` / `key = value` line.
///
/// The one piece of structure worth showing: in a manifest, a workflow, or a
/// dotfile the key is what the reader is looking for, and it is the token a
/// grammar-free lexer would otherwise leave indistinguishable from a value.
fn mark_key(tokens: &mut [Token]) {
    let mut positions = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.text.trim().is_empty())
        .map(|(i, _)| i);
    let Some(mut first) = positions.next() else {
        return;
    };
    // A YAML list item is `- key: value`; the dash is not the key.
    if tokens[first].class == Class::Punct && tokens[first].text == "-" {
        let Some(next) = positions.next() else {
            return;
        };
        first = next;
    }
    let Some(after) = positions.next() else {
        return;
    };
    let assigns =
        tokens[after].class == Class::Punct && matches!(tokens[after].text.as_str(), ":" | "=");
    let nameable = matches!(
        tokens[first].class,
        Class::Str | Class::Plain | Class::Keyword
    );
    if assigns && nameable {
        tokens[first].class = Class::Key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(lang: Lang, line: &str) -> Vec<(Class, String)> {
        Lexer::new(lang)
            .line(line)
            .into_iter()
            .filter(|t| !t.text.trim().is_empty())
            .map(|t| (t.class, t.text))
            .collect()
    }

    #[test]
    fn json_key_and_value_are_told_apart() {
        let got = classes(Lang::Curly, r#"  "version": "1.2.3","#);
        assert_eq!(
            got,
            vec![
                (Class::Key, "\"version\"".into()),
                (Class::Punct, ":".into()),
                (Class::Str, "\"1.2.3\"".into()),
                (Class::Punct, ",".into()),
            ]
        );
    }

    #[test]
    fn yaml_key_survives_a_list_dash() {
        let got = classes(Lang::Hash, "  - uses: actions/checkout@v4 # pinned");
        assert_eq!(got[0], (Class::Punct, "-".into()));
        assert_eq!(got[1], (Class::Key, "uses".into()));
        assert_eq!(got.last().unwrap().0, Class::Comment);
    }

    #[test]
    fn a_hash_is_only_a_comment_in_its_own_family() {
        assert_eq!(classes(Lang::Hash, "# note")[0].0, Class::Comment);
        assert_ne!(classes(Lang::Curly, "#note")[0].0, Class::Comment);
    }

    #[test]
    fn a_block_comment_stays_open_across_lines() {
        let mut lexer = Lexer::new(Lang::Curly);
        assert_eq!(lexer.line("/* open").last().unwrap().class, Class::Comment);
        assert_eq!(lexer.line("still").last().unwrap().class, Class::Comment);
        let closed = lexer.line("done */ let x = 1;");
        assert_eq!(closed[0].class, Class::Comment);
        assert!(closed.iter().any(|t| t.class == Class::Keyword));
        assert!(!lexer.in_block);
    }

    #[test]
    fn a_one_line_block_comment_does_not_run_away() {
        let mut lexer = Lexer::new(Lang::Curly);
        let got = lexer.line("/* here */ 42");
        assert!(!lexer.in_block);
        assert_eq!(got[0], Token::new(Class::Comment, "/* here */"));
        assert_eq!(got.last().unwrap().class, Class::Num);
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let got = classes(Lang::Curly, r#"x = "a\"b" + 1"#);
        assert!(got.contains(&(Class::Str, r#""a\"b""#.into())));
        assert!(got.contains(&(Class::Num, "1".into())));
    }

    #[test]
    fn an_unknown_extension_is_one_plain_token() {
        let got = Lexer::new(Lang::Plain).line("-----BEGIN PRIVATE KEY-----");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].class, Class::Plain);
    }

    #[test]
    fn language_comes_from_the_extension_then_the_name() {
        assert_eq!(lang_for(Path::new("a/package-lock.json")), Lang::Curly);
        assert_eq!(lang_for(Path::new("a/Cargo.lock")), Lang::Hash);
        assert_eq!(lang_for(Path::new("a/.env.local")), Lang::Hash);
        assert_eq!(lang_for(Path::new("a/Dockerfile")), Lang::Hash);
        // Extensionless config files are most of what a home-directory secret
        // finding points at.
        assert_eq!(lang_for(Path::new(".aws/credentials")), Lang::Hash);
        assert_eq!(lang_for(Path::new(".ssh/config")), Lang::Hash);
        assert_eq!(lang_for(Path::new("a/README.md")), Lang::Plain);
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn the_window_is_centred_on_the_finding_and_clamped_at_the_edges() {
        let dir = tempfile::tempdir().unwrap();
        let body = (1..=100).map(|n| format!("l{n}\n")).collect::<String>();
        let path = write(dir.path(), "f.txt", &body);

        let mid = excerpt(&path, Some(50), 2).unwrap();
        assert_eq!(mid.lines.first().unwrap().number, 48);
        assert_eq!(mid.lines.last().unwrap().number, 52);
        assert_eq!(mid.total_lines, 100);
        assert_eq!(mid.focus, Some(50));

        // Near the top the window cannot start before line 1, and near the
        // bottom it ends at the last line rather than inventing rows.
        assert_eq!(excerpt(&path, Some(1), 2).unwrap().lines[0].number, 1);
        assert_eq!(
            excerpt(&path, Some(100), 2)
                .unwrap()
                .lines
                .last()
                .unwrap()
                .number,
            100
        );
        // No line at all: the head of the file.
        assert_eq!(excerpt(&path, None, 2).unwrap().lines[0].number, 1);
    }

    #[test]
    fn binary_and_oversized_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let binary = write(dir.path(), "b.bin", "ok\0nope");
        assert!(
            excerpt(&binary, None, 4)
                .unwrap_err()
                .to_string()
                .contains("binary")
        );

        let big = write(dir.path(), "big.json", &"x".repeat(MAX_BYTES as usize + 1));
        assert!(
            excerpt(&big, None, 4)
                .unwrap_err()
                .to_string()
                .contains("too large")
        );

        assert!(excerpt(&dir.path().join("missing"), None, 4).is_err());
        assert!(excerpt(dir.path(), None, 4).is_err());
    }

    #[test]
    fn a_block_comment_above_the_window_is_still_open_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.js", "/* start\n2\n3\n4\n5\n");
        let got = excerpt(&path, Some(4), 1).unwrap();
        assert_eq!(got.lines[0].number, 3);
        assert!(
            got.lines
                .iter()
                .all(|line| line.tokens.iter().all(|t| t.class == Class::Comment))
        );
    }
}
