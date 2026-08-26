use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

mod common;
use common::fixture_root;

struct McpServer {
    child: Child,
    reader: BufReader<ChildStdout>,
}

impl McpServer {
    /// Hermetic child command: its scan cache and durable state live under
    /// the test's temp dir, never in the developer's real ~/.cache / ~/.husk
    /// (HUSK_* overrides work on every OS, unlike XDG_CACHE_HOME).
    fn command(state_dir: &std::path::Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_husk"));
        command
            .arg("mcp")
            .env("HUSK_CACHE_DIR", state_dir.join("cache"))
            .env("HUSK_HOME", state_dir.join("home"))
            // No test may reach a real backend; anything that tries (e.g.
            // husk_feedback) must fail fast against a closed local port.
            .env("HUSK_BACKEND_URL", "http://127.0.0.1:9");
        command
    }

    fn spawn(state_dir: &std::path::Path) -> Self {
        Self::from_command(Self::command(state_dir))
    }

    fn from_command(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn husk mcp");
        let reader = BufReader::new(child.stdout.take().expect("child stdout"));
        Self { child, reader }
    }

    fn request(&mut self, message: Value) -> Value {
        let stdin = self.child.stdin.as_mut().expect("child stdin");
        let mut line = serde_json::to_string(&message).expect("encode request");
        line.push('\n');
        stdin.write_all(line.as_bytes()).expect("write request");
        stdin.flush().expect("flush request");

        let mut response = String::new();
        self.reader.read_line(&mut response).expect("read response");
        serde_json::from_str(&response).expect("parse response")
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tool_text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text content")
}

#[test]
fn mcp_server_handshake_scan_and_findings() {
    let state_dir = tempfile::tempdir().expect("temp state dir");
    let mut server = McpServer::spawn(state_dir.path());

    let initialize = server.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "husk-test", "version": "0" },
        },
    }));
    assert_eq!(initialize["result"]["serverInfo"]["name"], "husk");
    assert_eq!(initialize["result"]["protocolVersion"], "2025-03-26");

    let tools = server.request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    }));
    let names = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_string())
        .collect::<Vec<_>>();
    for expected in [
        "husk_status",
        "husk_findings",
        "husk_packages",
        "husk_guide",
        "husk_scan",
        "husk_policy",
        "husk_ledger",
        "husk_feedback",
    ] {
        assert!(names.contains(&expected.to_string()), "missing {expected}");
    }

    // husk_feedback validates locally before any network call; a missing
    // message is a tool error naming the requirement.
    let feedback = server.request(json!({
        "jsonrpc": "2.0",
        "id": 23,
        "method": "tools/call",
        "params": { "name": "husk_feedback", "arguments": {} },
    }));
    assert_eq!(feedback["result"]["isError"], true);
    let feedback_json: Value = serde_json::from_str(tool_text(&feedback)).expect("feedback json");
    assert!(
        feedback_json["error"]
            .as_str()
            .expect("error text")
            .contains("`message` is required"),
        "{feedback_json}"
    );

    // A valid message reaches the (unroutable) backend and reports it clearly,
    // proving validation passed and the send used the resolved backend URL.
    let unreachable = server.request(json!({
        "jsonrpc": "2.0",
        "id": 24,
        "method": "tools/call",
        "params": { "name": "husk_feedback", "arguments": { "message": "great scanner" } },
    }));
    assert_eq!(unreachable["result"]["isError"], true);
    let unreachable_json: Value =
        serde_json::from_str(tool_text(&unreachable)).expect("feedback json");
    assert!(
        unreachable_json["error"]
            .as_str()
            .expect("error text")
            .contains("could not reach the Husk backend"),
        "{unreachable_json}"
    );

    // husk_ledger returns the (here empty) trust ledger with an intact chain.
    let ledger = server.request(json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "tools/call",
        "params": { "name": "husk_ledger", "arguments": {} },
    }));
    assert_eq!(ledger["result"]["isError"], false);
    let ledger_json: Value = serde_json::from_str(tool_text(&ledger)).expect("ledger json");
    assert_eq!(ledger_json["chain_intact"], true);
    assert!(ledger_json["entries"].is_array());

    // husk_policy returns the committed project policy for a path.
    let project = tempfile::tempdir().expect("temp project");
    std::fs::create_dir_all(project.path().join(".husk")).expect("mk .husk");
    std::fs::write(
        project.path().join(".husk/policy.toml"),
        "schema_version = 1\n[packages]\nblock = [\"npm:evil\"]\nallow = []\n[ci]\nfail_on = \"medium\"\n",
    )
    .expect("write policy");
    let policy = server.request(json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "husk_policy",
            "arguments": { "path": project.path() },
        },
    }));
    assert_eq!(policy["result"]["isError"], false);
    let policy_json: Value = serde_json::from_str(tool_text(&policy)).expect("policy json");
    assert_eq!(policy_json["block"][0], "npm:evil");
    assert_eq!(policy_json["ci_fail_on"], "medium");

    // No policy on a bare path: the tool returns a null policy, not an error.
    let none = server.request(json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "husk_policy",
            "arguments": { "path": tempfile::tempdir().unwrap().path() },
        },
    }));
    assert_eq!(none["result"]["isError"], false);
    let none_json: Value = serde_json::from_str(tool_text(&none)).expect("none json");
    assert!(none_json["policy"].is_null());

    // Empty cache: status is a tool-level error telling the agent to scan.
    let status = server.request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "husk_status", "arguments": {} },
    }));
    assert_eq!(status["result"]["isError"], true);
    assert!(tool_text(&status).contains("no cached husk scan"));

    let scan = server.request(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "husk_scan",
            "arguments": {
                "paths": [fixture_root()],
                "offline": true,
                "include_home_inventory": false,
            },
        },
    }));
    assert_eq!(scan["result"]["isError"], false);
    let scan_report: Value = serde_json::from_str(tool_text(&scan)).expect("scan report json");
    assert!(scan_report["stats"]["packages"].as_u64().expect("packages") >= 4);
    assert!(scan_report["stats"]["findings"].as_u64().expect("findings") > 0);

    let findings = server.request(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "husk_findings",
            "arguments": { "min_severity": "high", "limit": 5 },
        },
    }));
    assert_eq!(findings["result"]["isError"], false);
    let listing: Value = serde_json::from_str(tool_text(&findings)).expect("findings json");
    let returned = listing["findings"].as_array().expect("findings array");
    assert!(returned.len() <= 5);
    for finding in returned {
        let severity = finding["severity"].as_str().expect("severity");
        assert!(matches!(severity, "critical" | "high"), "got {severity}");
    }

    // A typo'd min_severity is an InvalidParams error, never a silent
    // widen-to-info that returns every finding.
    let bad_severity = server.request(json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "husk_findings",
            "arguments": { "min_severity": "hgih" },
        },
    }));
    assert_eq!(bad_severity["result"]["isError"], true);
    assert!(tool_text(&bad_severity).contains("unknown min_severity"));

    let unknown = server.request(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": { "name": "husk_bogus", "arguments": {} },
    }));
    assert!(
        unknown["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("unknown tool")
    );
}

// Telemetry counter keys are a closed set: a dispatched tool bumps its own
// counter (plus its `.err` counter when the dispatch returns an error
// result), while a made-up tool name lands in `mcp.tool.unknown` and the
// client-chosen string never becomes a counter key.
#[test]
fn mcp_tool_telemetry_never_records_unknown_tool_names() {
    let state_dir = tempfile::tempdir().expect("temp state dir");
    let home = state_dir.path().join("home");
    std::fs::create_dir_all(&home).expect("create home dir");
    husk::cloud::telemetry::Telemetry::at(&home)
        .enable()
        .expect("enable telemetry");

    // The opt-in above must hold regardless of the harness environment:
    // CI runners set `CI=true` and a developer may set `DO_NOT_TRACK`.
    let mut command = McpServer::command(state_dir.path());
    command
        .env("HUSK_TELEMETRY", "1")
        .env_remove("DO_NOT_TRACK")
        .env_remove("HUSK_TELEMETRY_DISABLED");
    let mut server = McpServer::from_command(command);

    let known = server.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "husk_status", "arguments": {} },
    }));
    // Empty cache makes the tool fail; the dispatch still counts.
    assert_eq!(known["result"]["isError"], true);

    let unknown = server.request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "husk_bogus", "arguments": {} },
    }));
    assert!(
        unknown["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("unknown tool")
    );

    let current =
        std::fs::read_to_string(home.join("telemetry/current.json")).expect("read current.json");
    let current: Value = serde_json::from_str(&current).expect("parse current.json");
    let counters = current["counters"].as_object().expect("counters object");
    assert_eq!(counters["mcp.tool.husk_status"], 1);
    assert_eq!(
        counters["mcp.tool.husk_status.err"], 1,
        "an error result must also bump the tool's .err counter"
    );
    assert_eq!(counters["mcp.tool.unknown"], 1);
    assert!(
        !counters.keys().any(|key| key.contains("husk_bogus")),
        "client-chosen tool name leaked into counters: {counters:?}"
    );
}
