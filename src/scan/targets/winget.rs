//! winget: the Windows Package Manager OS-level application inventory.
//!
//! winget is an OS-level application installer, not a language package manager,
//! so there is no OSV/advisory ecosystem for its coordinates (inventory-only).
//! Ecosystem id: `"winget"`.
//!
//! Lockfile: the output of `winget export`. There is NO fixed filename or
//! location; `winget export` requires an explicit `-o/--output` path, so the
//! file can be named anything (`winget-packages.json`, `packages.json`,
//! `apps.json`, …) and is commonly committed to a dotfiles/setup repo. We
//! therefore detect by FILE EXTENSION only (cheap, no reads) and confirm the
//! winget shape by CONTENT in `emit` (a cheap fingerprint prefilter on the
//! file head, then the authoritative [`is_winget_export`] check).
//!
//! Export format (schema v1.0 and v2.0 share the extraction path):
//!
//! ```json
//! {
//!   "$schema": "https://aka.ms/winget-packages.schema.2.0.json",
//!   "Sources": [
//!     { "Packages": [ { "PackageIdentifier": "Microsoft.PowerToys", "Version": "0.81.0" } ],
//!       "SourceDetails": { "Name": "winget", ... } }
//!   ],
//!   "WinGetVersion": "1.8.1911"
//! }
//! ```
//!
//! A file is treated as a winget export iff EITHER (a) the top-level `$schema`
//! string contains the substring `winget-packages.schema`, OR (b) the top-level
//! `Sources` key is an array whose elements are objects carrying both
//! `SourceDetails` (object) and `Packages` (array). PascalCase keys
//! (`PackageIdentifier`, `Version`, `Sources`, `SourceDetails`) are the
//! fingerprint that distinguishes winget exports from other JSON.
//!
//! Coordinate = (`PackageIdentifier`, `Version`) exactly as written; casing is
//! preserved for display. `Version` is OPTIONAL and free-form (opaque, never
//! coerced to semver); a missing/empty `Version` or the sentinel `Unknown` means
//! "latest available" → recorded unpinned (empty version string). The enclosing
//! `SourceDetails.Name` (`winget` vs `msstore`) is captured because msstore IDs
//! are opaque Microsoft Store product IDs in a separate namespace; we qualify
//! non-`winget` sources by prefixing the source name so they never collide with
//! community-repo (winget-pkgs) identifiers. `winget configure` DSC YAML files
//! are a different (YAML) format and out of scope.

use super::ScanTarget;
use super::support::{Emitter, LineFinder, read_text};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct WingetTarget;

impl ScanTarget for WingetTarget {
    fn ecosystem_id(&self) -> &'static str {
        "winget"
    }

    /// Cheap dispatch: any `*.json` file. winget exports have no stable name, so
    /// the authoritative winget-shape confirmation happens (by content) in
    /// `emit`; non-winget JSON simply yields no coordinates.
    fn detects(&self, path: &Path) -> bool {
        super::file_name(path)
            .and_then(|n| n.rsplit_once('.'))
            .map(|(_, ext)| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        // Cheap prefilter before the full JSON parse: since `detects` claims
        // every *.json on the machine, don't serde-parse files that cannot be
        // a winget export. Real exports open with `$schema` and/or `Sources`
        // right at the top, so a head that mentions neither fingerprint is
        // conclusive. `is_winget_export` stays the authority for the rest.
        let head = json_head(&contents);
        if !head.contains("Sources") && !head.contains("winget-packages.schema") {
            return;
        }
        // Any random JSON lands here, so malformed input is "nothing to
        // report", not a scan failure.
        let Ok(root) = serde_json::from_str::<JsonValue>(&contents) else {
            return;
        };
        if !is_winget_export(&root) {
            return;
        }

        let mut lines = LineFinder::new(&contents);
        for coord in extract_coordinates(&root) {
            let line = lines.find(&coord.identifier);
            out.pkg(&coord.name, &coord.version, line);
        }
    }
}

/// The first ~4 KiB of `contents`, cut on a char boundary: the prefilter
/// window in which a real winget export always mentions `Sources` or the
/// winget `$schema` URL.
fn json_head(contents: &str) -> &str {
    let mut end = contents.len().min(4096);
    while !contents.is_char_boundary(end) {
        end -= 1;
    }
    &contents[..end]
}

/// A resolved winget inventory coordinate.
#[derive(Debug)]
struct Coord {
    /// The coordinate name as emitted (PackageIdentifier, qualified with the
    /// source name for non-`winget` sources, e.g. `msstore:9WZDNCRFJ3PZ`).
    name: String,
    /// The raw PackageIdentifier as written (used to locate the source line).
    identifier: String,
    /// Version verbatim, or empty for unpinned (missing/empty/`Unknown`).
    version: String,
}

/// True iff `root` looks like a `winget export` document. Either a `$schema`
/// referencing the winget packages schema, or a `Sources` array of
/// `{ SourceDetails, Packages }` objects.
fn is_winget_export(root: &JsonValue) -> bool {
    let Some(obj) = root.as_object() else {
        return false;
    };
    if let Some(schema) = obj.get("$schema").and_then(JsonValue::as_str)
        && schema.contains("winget-packages.schema")
    {
        return true;
    }
    let Some(sources) = obj.get("Sources").and_then(JsonValue::as_array) else {
        return false;
    };
    // Require at least one source carrying both SourceDetails (object) and
    // Packages (array) to avoid claiming an unrelated `{ "Sources": [...] }`.
    sources.iter().any(|src| {
        src.get("SourceDetails")
            .map(JsonValue::is_object)
            .unwrap_or(false)
            && src
                .get("Packages")
                .map(JsonValue::is_array)
                .unwrap_or(false)
    })
}

/// Walk `Sources[].Packages[]`, emitting one [`Coord`] per package that has a
/// `PackageIdentifier`.
fn extract_coordinates(root: &JsonValue) -> Vec<Coord> {
    let mut out = Vec::new();
    let Some(sources) = root.get("Sources").and_then(JsonValue::as_array) else {
        return out;
    };

    for source in sources {
        let source_name = source
            .get("SourceDetails")
            .and_then(|d| d.get("Name"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");

        let Some(packages) = source.get("Packages").and_then(JsonValue::as_array) else {
            continue;
        };

        for pkg in packages {
            let Some(identifier) = pkg
                .get("PackageIdentifier")
                .and_then(JsonValue::as_str)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };

            out.push(Coord {
                name: qualified_name(source_name, identifier),
                identifier: identifier.to_string(),
                version: normalize_version(pkg.get("Version").and_then(JsonValue::as_str)),
            });
        }
    }
    out
}

/// Qualify the identifier with its source unless it comes from the community
/// `winget` source (or an unknown source). msstore IDs are opaque Store product
/// IDs in a different namespace, so we prefix them (`msstore:9WZDNCRFJ3PZ`) to
/// avoid cross-namespace collisions with winget-pkgs identifiers.
fn qualified_name(source_name: &str, identifier: &str) -> String {
    match source_name {
        "" | "winget" => identifier.to_string(),
        other => format!("{other}:{identifier}"),
    }
}

/// Normalize an export `Version` to the coordinate version: verbatim if pinned,
/// or empty for the unpinned cases (missing, empty, or the `Unknown`/`Latest`
/// sentinels winget emits when it cannot determine an installed version).
fn normalize_version(version: Option<&str>) -> String {
    match version.map(str::trim) {
        Some(v)
            if !v.is_empty()
                && !v.eq_ignore_ascii_case("Unknown")
                && !v.eq_ignore_ascii_case("Latest") =>
        {
            v.to_string()
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
  "$schema": "https://aka.ms/winget-packages.schema.2.0.json",
  "CreationDate": "2026-06-19T10:15:00.000-00:00",
  "Sources": [
    {
      "Packages": [
        { "PackageIdentifier": "Microsoft.PowerToys", "Version": "0.81.0" },
        { "PackageIdentifier": "Python.Python.3.12", "Version": "3.12.4", "Scope": "user" },
        { "PackageIdentifier": "Mozilla.Firefox" }
      ],
      "SourceDetails": { "Name": "winget", "Type": "Microsoft.PreIndexed.Package" }
    },
    {
      "Packages": [
        { "PackageIdentifier": "9WZDNCRFJ3PZ", "Version": "Unknown" }
      ],
      "SourceDetails": { "Name": "msstore", "Type": "Microsoft.Rest" }
    }
  ],
  "WinGetVersion": "1.8.1911"
}"#;

    #[test]
    fn detects_export_by_schema_and_by_shape() {
        let by_schema: JsonValue = serde_json::from_str(
            r#"{ "$schema": "https://aka.ms/winget-packages.schema.1.0.json" }"#,
        )
        .unwrap();
        assert!(is_winget_export(&by_schema));

        let by_shape: JsonValue =
            serde_json::from_str(r#"{ "Sources": [ { "Packages": [], "SourceDetails": {} } ] }"#)
                .unwrap();
        assert!(is_winget_export(&by_shape));
    }

    #[test]
    fn rejects_unrelated_json() {
        // A bare Sources array without SourceDetails/Packages is not winget.
        let bare: JsonValue = serde_json::from_str(r#"{ "Sources": ["a", "b"] }"#).unwrap();
        assert!(!is_winget_export(&bare));
        let other: JsonValue =
            serde_json::from_str(r#"{ "name": "x", "version": "1.0.0" }"#).unwrap();
        assert!(!is_winget_export(&other));
    }

    #[test]
    fn normalize_version_handles_unpinned_sentinels() {
        assert_eq!(normalize_version(Some("0.81.0")), "0.81.0");
        assert_eq!(normalize_version(Some("  3.12.4 ")), "3.12.4");
        assert_eq!(normalize_version(Some("")), "");
        assert_eq!(normalize_version(Some("Unknown")), "");
        assert_eq!(normalize_version(Some("latest")), "");
        assert_eq!(normalize_version(None), "");
    }

    #[test]
    fn qualifies_non_winget_sources_only() {
        assert_eq!(
            qualified_name("winget", "Microsoft.PowerToys"),
            "Microsoft.PowerToys"
        );
        assert_eq!(
            qualified_name("", "Microsoft.PowerToys"),
            "Microsoft.PowerToys"
        );
        assert_eq!(
            qualified_name("msstore", "9WZDNCRFJ3PZ"),
            "msstore:9WZDNCRFJ3PZ"
        );
    }

    #[test]
    fn extracts_pinned_and_unpinned_across_sources() {
        let root: JsonValue = serde_json::from_str(SAMPLE).unwrap();
        let coords = extract_coordinates(&root);

        let powertoys = coords
            .iter()
            .find(|c| c.name == "Microsoft.PowerToys")
            .unwrap();
        assert_eq!(powertoys.version, "0.81.0");

        // Dotted winget ID is NOT a PyPI package; kept verbatim, unqualified.
        let python = coords
            .iter()
            .find(|c| c.name == "Python.Python.3.12")
            .unwrap();
        assert_eq!(python.version, "3.12.4");

        // Missing Version -> unpinned.
        let firefox = coords.iter().find(|c| c.name == "Mozilla.Firefox").unwrap();
        assert_eq!(firefox.version, "");

        // msstore opaque Store ID is qualified and its `Unknown` version unpinned.
        let store = coords
            .iter()
            .find(|c| c.name == "msstore:9WZDNCRFJ3PZ")
            .unwrap();
        assert_eq!(store.version, "");
    }

    #[test]
    fn skips_packages_missing_identifier() {
        let root: JsonValue = serde_json::from_str(
            r#"{ "Sources": [ { "SourceDetails": { "Name": "winget" },
                 "Packages": [ { "Version": "1.0" }, { "PackageIdentifier": "A.B", "Version": "2.0" } ] } ] }"#,
        )
        .unwrap();
        let coords = extract_coordinates(&root);
        assert_eq!(coords.len(), 1);
        assert_eq!(coords[0].name, "A.B");
    }
}
