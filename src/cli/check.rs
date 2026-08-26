//! The live single-package verdict exposed by `husk check`.

use super::CheckArgs;
use crate::term::color;
use anyhow::Result;

/// Parse a package coordinate, query OSV.dev, print the verdict, and exit
/// non-zero when the package is flagged.
pub(super) async fn run_check(args: CheckArgs) -> Result<()> {
    let target = parse_check_spec(&args.spec)?;
    let result = crate::check::check(target, args.cooldown_hours).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_check_result(&result);
    }
    std::process::exit(result.exit_code());
}

/// Turn the 1-3 positional args into a [`crate::check::CheckTarget`].
/// One arg is a bare name (npm inferred); two are `ecosystem name`; three are
/// `ecosystem name version`. The name may carry an `@version` suffix, so
/// `husk check lodash@4.17.21` means `husk check npm lodash 4.17.21`.
fn parse_check_spec(spec: &[String]) -> Result<crate::check::CheckTarget> {
    match spec {
        [name] => {
            let (name, version) = split_name_version(name)?;
            Ok(crate::check::CheckTarget::new(
                None,
                name,
                version.as_deref(),
            ))
        }
        [ecosystem, name] => {
            let (name, version) = split_name_version(name)?;
            Ok(crate::check::CheckTarget::new(
                Some(ecosystem),
                name,
                version.as_deref(),
            ))
        }
        [ecosystem, name, version] => {
            // The version is explicit here, so the name is taken verbatim. A
            // suffix on top of it is ambiguous rather than redundant: refuse it
            // instead of picking one of the two versions.
            if let (bare, Some(suffix)) = split_name_version(name)? {
                anyhow::bail!(
                    "`{name}` already carries version `{suffix}`, but version `{version}` was \
also given. Pass the version once: `husk check {ecosystem} {name}` or `husk check \
{ecosystem} {bare} {version}`."
                );
            }
            Ok(crate::check::CheckTarget::new(
                Some(ecosystem),
                name,
                Some(version.as_str()),
            ))
        }
        _ => {
            anyhow::bail!("usage: husk check <ecosystem> <name> [version]  (or: husk check <name>)")
        }
    }
}

/// Split a `name@version` argument. The split is on the LAST `@` so scoped npm
/// names survive (`@scope/pkg@1.2.3`), and a leading `@` is never a separator
/// so a bare scope (`@scope/pkg`) stays one name. A trailing `@` with nothing
/// after it is a typo, not a versionless lookup: versionless lookups only
/// consider malware advisories, so silently accepting it would report a
/// package "clean" that was never checked for vulnerabilities.
fn split_name_version(raw: &str) -> Result<(&str, Option<String>)> {
    let Some((name, version)) = raw.rsplit_once('@') else {
        return Ok((raw, None));
    };
    if name.is_empty() {
        return Ok((raw, None));
    }
    if version.trim().is_empty() {
        anyhow::bail!(
            "`{raw}` ends with `@` but no version. Pass a version (`{name}@1.2.3`) or drop the \
`@` to check the name alone."
        );
    }
    Ok((name, Some(version.trim().to_string())))
}

fn print_check_result(result: &crate::check::CheckResult) {
    use crate::check::CheckOutcome;
    let target = &result.target;
    let version = target.version.as_deref().unwrap_or("*");
    match &result.outcome {
        CheckOutcome::Clean => {
            println!(
                "{} {} {} {}@{}: no matching advisories at {}",
                color("ok", "32;1"),
                color("clean", "32;1"),
                target.ecosystem,
                target.name,
                version,
                result.source,
            );
            if target.version.is_none() {
                println!(
                    "   (checked for malicious-package advisories; pass a version to also check vulnerabilities)"
                );
            }
        }
        CheckOutcome::Unknown { reason } => {
            println!(
                "{} {} {} {}@{}: {}",
                color("?", "33;1"),
                color("unknown", "33;1"),
                target.ecosystem,
                target.name,
                version,
                reason,
            );
        }
        CheckOutcome::Flagged { reasons } => {
            for reason in reasons {
                println!(
                    "{} {} {} {}@{}",
                    color("!!", "31;1"),
                    color(reason.kind.label(), "31;1"),
                    target.ecosystem,
                    target.name,
                    version
                );
                let published = match reason.published_at {
                    Some(at) => format!("   published {}", at.format("%Y-%m-%d %H:%M UTC")),
                    None => String::new(),
                };
                println!(
                    "   advisory {} via {}{}{}",
                    reason.advisory,
                    result.source,
                    published,
                    if reason.within_cooldown {
                        " (within cooldown)"
                    } else {
                        ""
                    }
                );
                if !reason.summary.trim().is_empty() {
                    println!("   {}", reason.summary);
                }
                println!("   {}", reason.recommendation);
            }
            print_flagged_check_nudge();
        }
    }
}

fn print_flagged_check_nudge() {
    let logged_in = crate::cloud::auth::env_token().is_some()
        || crate::cloud::Credentials::load().ok().flatten().is_some();
    if logged_in {
        eprintln!("   run `husk status` to see whether this is already installed on your machines");
    } else {
        eprintln!("   tip: retroactive cloud alerts are coming soon");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn parse(args: &[&str]) -> crate::check::CheckTarget {
        parse_check_spec(&spec(args)).expect("spec should parse")
    }

    #[test]
    fn bare_name_infers_npm_and_no_version() {
        let target = parse(&["lodash"]);
        assert_eq!(target.ecosystem, "npm");
        assert_eq!(target.name, "lodash");
        assert_eq!(target.version, None);
    }

    #[test]
    fn name_at_version_is_the_same_as_the_spaced_form() {
        assert_eq!(
            parse(&["lodash@4.17.21"]),
            parse(&["npm", "lodash", "4.17.21"])
        );
        assert_eq!(
            parse(&["pypi", "requests@2.19.1"]),
            parse(&["pypi", "requests", "2.19.1"])
        );
    }

    #[test]
    fn scoped_name_splits_on_the_last_at() {
        let target = parse(&["@scope/pkg@1.2.3"]);
        assert_eq!(target.name, "@scope/pkg");
        assert_eq!(target.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn scoped_name_without_a_version_is_not_split() {
        let target = parse(&["@scope/pkg"]);
        assert_eq!(target.name, "@scope/pkg");
        assert_eq!(target.version, None);
    }

    #[test]
    fn explicit_three_arg_form_keeps_the_name_verbatim() {
        let target = parse(&["npm", "@scope/pkg", "1.2.3"]);
        assert_eq!(target.name, "@scope/pkg");
        assert_eq!(target.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn a_suffix_plus_an_explicit_version_is_an_error() {
        let err = parse_check_spec(&spec(&["npm", "lodash@4.17.21", "4.17.20"]))
            .expect_err("two versions should conflict");
        assert!(err.to_string().contains("Pass the version once"));
    }

    #[test]
    fn a_trailing_at_with_no_version_is_an_error() {
        for args in [
            &["lodash@"][..],
            &["npm", "lodash@"][..],
            &["npm", "lodash@", "1.0.0"][..],
        ] {
            let err = parse_check_spec(&spec(args)).expect_err("empty version should fail");
            assert!(err.to_string().contains("no version"));
        }
    }
}
