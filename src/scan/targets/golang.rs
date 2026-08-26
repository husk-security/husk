//! Go modules. go.sum (coordinate hints) + go.mod (require directives).
//! Both resolve to OSV ecosystem `Go`. Versions are kept verbatim (with the
//! leading `v`), matching the coordinate form the providers already query.
//! `replace`/`exclude` directives are deliberately ignored (a replaced module
//! still appeared in the build at some point), and go.sum + go.mod both
//! emitting the same coordinate is fine (discovery dedups per manifest).

use super::support::Emitter;

/// go.sum: `module version hash` lines; the `version/go.mod` hash rows are
/// skipped (they duplicate every module entry).
pub(super) fn go_sum(contents: &str, out: &mut Emitter<'_>) {
    for (idx, line) in contents.lines().enumerate() {
        let mut parts = line.split_whitespace();
        let (Some(module), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        if version.ends_with("/go.mod") {
            continue;
        }
        out.pkg(module, version, Some(idx + 1));
    }
}

/// go.mod: single-line `require m v1.2.3` and `require ( … )` blocks.
pub(super) fn go_mod(contents: &str, out: &mut Emitter<'_>) {
    let mut in_block = false;
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            emit_require(line, idx + 1, out);
        } else if line == "require (" {
            in_block = true;
        } else if let Some(rest) = line.strip_prefix("require ") {
            emit_require(rest.trim(), idx + 1, out);
        }
    }
}

fn emit_require(spec: &str, line: usize, out: &mut Emitter<'_>) {
    let mut parts = spec.split_whitespace();
    let (Some(module), Some(version)) = (parts.next(), parts.next()) else {
        return;
    };
    if module.is_empty() || !version.starts_with('v') {
        return;
    }
    out.pkg(module, version, Some(line));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn go_sum_skips_go_mod_hash_rows() {
        let sum = "golang.org/x/crypto v0.1.0 h1:abc=\n\
                   golang.org/x/crypto v0.1.0/go.mod h1:def=\n\
                   github.com/gin-gonic/gin v1.9.0 h1:ghi=\n";
        let found: Vec<(String, String)> = run_parser("go", sum, go_sum)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("golang.org/x/crypto".to_string(), "v0.1.0".to_string()),
                ("github.com/gin-gonic/gin".to_string(), "v1.9.0".to_string()),
            ]
        );
    }

    #[test]
    fn go_mod_parses_inline_and_block_requires() {
        let gomod = "module example.com/app\n\n\
                     require github.com/solo/dep v1.0.0\n\
                     require (\n\
                     \tgolang.org/x/text v0.14.0\n\
                     \tgithub.com/other/dep v2.1.0+incompatible // indirect\n\
                     )\n";
        let found: Vec<(String, String)> = run_parser("go", gomod, go_mod)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("github.com/solo/dep".to_string(), "v1.0.0".to_string()),
                ("golang.org/x/text".to_string(), "v0.14.0".to_string()),
                (
                    "github.com/other/dep".to_string(),
                    "v2.1.0+incompatible".to_string()
                ),
            ]
        );
    }

    #[test]
    fn go_mod_requires_a_v_version() {
        assert!(run_parser("go", "require example.com/x latest\n", go_mod).is_empty());
    }
}
