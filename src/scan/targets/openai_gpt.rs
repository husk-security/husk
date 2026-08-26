//! OpenAI GPTs / ChatGPT plugins (`ai-plugin.json` → inventory-only, no OSV
//! ecosystem).
//!
//! The legacy plugin manifest is canonically served at
//! `<domain>/.well-known/ai-plugin.json` but is often staged at the repo root
//! / `public` / `static` before deploy, so we match the basename anywhere and
//! never require the `.well-known/` parent. The companion `openapi.*` /
//! `swagger.*` files are never detected: they collide with nearly every
//! REST-API repo. The ecosystem is **versionless**: `schema_version` is a
//! schema tag (in practice the constant `"v1"`), not a release version, and
//! the OpenAPI sidecar's `info.version` belongs to the API, not the plugin.
//! The successors (custom GPTs / GPT Actions) have no portable on-disk
//! manifest, so `ai-plugin.json` is the only stable local artifact.
//!
//! Security note: `description_for_model` is injected verbatim into the agent
//! prompt (a prime prompt-injection vector); husk's prompt-injection/secrets
//! checks cover that, not this target.

use super::support::Emitter;
use serde_json::Value as JsonValue;

/// Parse an `ai-plugin.json` manifest.
///
/// Emit rule: `name = name_for_model`, else `name_for_human`;
/// `version = schema_version`, else the literal `"v1"`. If the JSON is not an
/// object, or has NONE of `{name_for_model, name_for_human, api}`, it does not
/// look like a plugin manifest; skip rather than emit a phantom coordinate
/// from an unrelated file that merely shares the basename.
pub(super) fn ai_plugin(contents: &str, out: &mut Emitter<'_>) {
    // serde_json rejects a leading UTF-8 BOM; strip it.
    let trimmed = contents.strip_prefix('\u{feff}').unwrap_or(contents);

    let Ok(json) = serde_json::from_str::<JsonValue>(trimmed) else {
        out.warn("ai-plugin.json is not valid JSON");
        return;
    };
    let Some(obj) = json.as_object() else {
        return;
    };

    let str_field = |key: &str| -> Option<&str> {
        obj.get(key)
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };

    let name_for_model = str_field("name_for_model");
    let name_for_human = str_field("name_for_human");
    let has_api = obj.get("api").is_some_and(JsonValue::is_object);

    if name_for_model.is_none() && name_for_human.is_none() && !has_api {
        return;
    }

    let Some(name) = name_for_model.or(name_for_human) else {
        return;
    };

    // schema_version is an opaque schema tag, virtually always "v1". Do NOT
    // coerce to semver or strip the 'v': the value IS "v1".
    let version = str_field("schema_version").unwrap_or("v1");

    out.pkg(name, version, None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("openai-gpt", contents, ai_plugin)
    }

    #[test]
    fn prefers_name_for_model_and_reads_schema_version() {
        let contents = r#"{
            "schema_version": "v1",
            "name_for_human": "Weather Lookup",
            "name_for_model": "weather",
            "description_for_model": "Retrieve current weather and forecasts.",
            "auth": { "type": "none" },
            "api": { "type": "openapi", "url": "https://weather.example.com/openapi.yaml" }
        }"#;
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, "openai-gpt");
        assert_eq!(pkgs[0].name, "weather");
        assert_eq!(pkgs[0].version, "v1");
    }

    #[test]
    fn falls_back_to_name_for_human_and_default_version() {
        let contents = r#"{
            "name_for_human": "Kayak",
            "api": { "type": "openapi", "url": "https://kayak.example.com/openapi.json" }
        }"#;
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Kayak");
        assert_eq!(pkgs[0].version, "v1");
    }

    #[test]
    fn schema_version_is_opaque_not_coerced() {
        let contents = r#"{ "name_for_model": "x", "schema_version": "v2-beta" }"#;
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "v2-beta");
    }

    #[test]
    fn skips_non_manifest_json_with_no_plugin_fields() {
        let contents = r#"{ "hello": "world", "info": { "title": "Some API" } }"#;
        assert!(parse(contents).is_empty());
        assert!(parse("{}").is_empty());
        // api present but no usable name => nothing to key on.
        let api_only = r#"{ "api": { "type": "openapi", "url": "https://x/openapi.json" } }"#;
        assert!(parse(api_only).is_empty());
    }

    #[test]
    fn malformed_input_yields_empty_not_panic() {
        assert!(parse("[1, 2, 3]").is_empty());
        assert!(parse(r#""just a string""#).is_empty());
        assert!(parse("{ not json,, }").is_empty());
    }

    #[test]
    fn tolerates_utf8_bom() {
        let contents = "\u{feff}{ \"name_for_model\": \"bommy\", \"schema_version\": \"v1\" }";
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bommy");
    }
}
