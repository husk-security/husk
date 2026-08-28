//! The localhost web UI server (behind the default `web` Cargo feature): a
//! thin Axum server exposing the JSON API (`/api/live`, `/api/guide`, …) over
//! the shared live-scan state and serving the embedded `web/dist` Vite+React
//! app. Binds to loopback by default (`--host` can widen it deliberately); no
//! HTML is rendered in Rust.

use crate::model::{LiveScan, LiveScanLock, ScanOptions, SharedLiveScan};
use anyhow::Result;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// The built Vite front-end (`web/dist/`), baked into the binary at compile time
/// with `rust-embed`. `husk web` serves these directly, so the shipped product
/// stays a single self-contained binary: no Node, no network, no external
/// assets at runtime. `web/dist/` is gitignored build output: rebuild it with
/// `npm --prefix web run build` (`build.rs` fails fast when it's missing).
#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct WebAssets;

#[derive(Clone)]
struct AppState {
    /// The project scan: the folder this session targets.
    live: SharedLiveScan,
    /// The machine-posture scan; independent of the project slot, so a
    /// machine rescan never disturbs the project view being read.
    machine: SharedLiveScan,
    options: Option<ScanOptions>,
    /// Telemetry consent state for the one-time web consent card; the same
    /// on-disk state the CLI prompt and TUI pane read and write.
    telemetry: crate::cloud::telemetry::Telemetry,
}

pub struct WebHandle {
    pub addr: SocketAddr,
    /// The server task's handle; await it to block until the server has fully
    /// shut down. Dropping it merely detaches the task (the server keeps
    /// running), so the owner must keep the whole `WebHandle` alive for as long
    /// as the server should serve: dropping `WebHandle` drops `shutdown`, which
    /// signals a graceful shutdown.
    pub task: JoinHandle<()>,
    /// Graceful-shutdown trigger. Sending `true` (via [`WebHandle::trigger_shutdown`])
    /// (or dropping the sender with the whole handle) asks Axum to stop
    /// accepting connections and drain in-flight ones, then the `task` future
    /// resolves.
    shutdown: watch::Sender<bool>,
}

impl WebHandle {
    /// Ask the server to shut down gracefully: stop accepting new connections,
    /// drain in-flight requests, then resolve `task`. Idempotent, and safe to
    /// call even if the server has already stopped.
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// The uniform `/api/*` failure shape: a real HTTP status code and an
/// `{ "error": "…" }` body, so the TS client needs exactly one convention.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    /// An upstream (Husk cloud backend) call failed or was unreachable.
    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    /// The request is valid but the server's state cannot serve it right now,
    /// and waiting is the fix.
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

pub async fn start_live_with_options(
    live: SharedLiveScan,
    machine: SharedLiveScan,
    addr: SocketAddr,
    options: Option<ScanOptions>,
    dev: bool,
) -> Result<WebHandle> {
    let state = AppState {
        live,
        machine,
        options,
        telemetry: crate::cloud::telemetry::Telemetry::from_default_dir()?,
    };
    start_with_state(state, addr, dev).await
}

async fn start_with_state(state: AppState, addr: SocketAddr, dev: bool) -> Result<WebHandle> {
    let api = Router::new()
        .route("/api/guide", get(api_guide))
        .route("/api/guide/task", post(api_guide_task))
        .route("/api/finding/mute", post(api_finding_mute))
        .route("/api/finding/unmute", post(api_finding_unmute))
        .route("/api/remediation/apply", post(api_remediation_apply))
        .route("/api/remediation/tools", get(api_remediation_tools))
        .route("/api/live", get(api_live))
        .route("/api/machine", get(api_machine))
        .route("/api/projects", get(api_projects))
        .route("/api/projects/track", post(api_projects_track))
        .route("/api/machine/rescan", post(api_machine_rescan))
        .route("/api/history", get(api_history))
        .route("/api/dirs", get(api_dirs))
        .route("/api/source", get(api_source))
        .route("/api/rescan", post(api_rescan))
        .route("/api/account", get(api_account))
        .route("/api/agents", get(api_agents))
        .route("/api/feedback", post(api_feedback))
        .route("/api/policy", get(api_policy))
        .route(
            "/api/telemetry/consent",
            get(api_telemetry_consent).post(api_telemetry_consent_answer),
        );
    let api = if crate::cloud::LOGIN_AVAILABLE {
        api.route("/api/login/start", post(api_login_start))
            .route("/api/login/poll", post(api_login_poll))
    } else {
        api.route("/api/login/start", post(api_login_unavailable))
            .route("/api/login/poll", post(api_login_unavailable))
    };
    // Normally everything else is the embedded front-end build. `--dev` serves
    // the API only, so you run the Vite dev server (with hot reload) yourself.
    let mut app = if dev {
        api
    } else {
        api.fallback(static_handler)
    }
    .with_state(state);

    // DNS-rebinding guard for the default loopback bind: a malicious page at
    // `evil.example` resolving to 127.0.0.1 still sends `Host: evil.example`.
    // A deliberate `--host` widening skips it: LAN hostnames can't be
    // enumerated here, and widening is an explicit user choice.
    if addr.ip().is_loopback() {
        app = app.layer(axum::middleware::from_fn(require_loopback));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;

    // Graceful-shutdown channel: the server future waits on `shutdown_rx`, and
    // the returned `WebHandle` keeps the sender. A single Ctrl-C in `husk web`
    // flips it to `true` (or dropping the handle closes the channel), which lets
    // Axum drain in-flight requests and return promptly.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let shutdown = async move {
            let mut rx = shutdown_rx;
            // Wait until told to stop, or until the sender is dropped.
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        };
        if let Err(err) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            eprintln!("husk web server stopped: {err}");
        }
    });
    Ok(WebHandle {
        addr: actual,
        task,
        shutdown: shutdown_tx,
    })
}

#[derive(Deserialize)]
struct ApplyRemediationBody {
    /// The proposals to apply, as one batch. Plural by design: a developer with
    /// thirty vulnerable packages selects them once, and the whole selection
    /// runs under a single lock, into a single backup snapshot, so
    /// `husk fix --rollback` undoes the click rather than its last step.
    ids: Vec<String>,
    /// Explicit opt-in for the one known overridable package-manager guard.
    #[serde(default)]
    allow_system_packages: bool,
}

#[derive(Serialize)]
struct ApplyRemediationResult {
    /// Nothing failed and nothing is still waiting on the user.
    ok: bool,
    /// Proposals that changed something. A proposal whose change was already in
    /// place counts as `skipped`, never here: the caller uses this to decide
    /// whether anything happened at all.
    applied: usize,
    /// Already satisfied, so nothing was changed for them.
    skipped: usize,
    /// Blocked or otherwise beyond what husk may do on its own.
    needs_user: usize,
    failed: usize,
    message: String,
    results: Vec<crate::remediation::ActionResult>,
}

#[derive(serde::Serialize)]
struct ToolAvailability {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    advice: Option<String>,
}

/// Live PATH check for the package managers a one-click remediation shells out
/// to. Proposals carry a scan-time snapshot of the same fact, but a user who
/// installs npm because husk told them to should see the one-click light up
/// without re-running a full scan, so this is polled independently.
async fn api_remediation_tools() -> Json<std::collections::BTreeMap<&'static str, ToolAvailability>>
{
    Json(
        crate::remediation::plan::PROGRAMS
            .iter()
            .copied()
            .map(|program| {
                let available = crate::remediation::program_on_path(program);
                (
                    program,
                    ToolAvailability {
                        available,
                        advice: (!available)
                            .then(|| crate::remediation::install_advice_for(program).to_string()),
                    },
                )
            })
            .collect(),
    )
}

/// Apply a selection of server-planned proposals as one batch. The request
/// carries only opaque proposal ids: paths, commands, and values always come
/// from the latest scan, never from browser input. Proposals run in report
/// order (worst severity first), so two updates against the same manifest can
/// never race each other.
///
/// A scan in flight rejects the whole request. The plan on screen during a
/// rescan was computed against the tree that scan is walking right now:
/// applying it would edit files behind the scan, so the report that lands
/// seconds later would be part pre-fix and part post-fix, and each proposal's
/// own re-parse verification would race the same walk. Waiting for the scan is
/// both cheap and the thing that produces the correct next plan.
async fn api_remediation_apply(
    State(state): State<AppState>,
    Json(body): Json<ApplyRemediationBody>,
) -> Result<Json<ApplyRemediationResult>, ApiError> {
    if body.ids.is_empty() {
        return Err(ApiError::bad_request("no remediation proposal ids given"));
    }
    let wanted: std::collections::HashSet<&str> = body.ids.iter().map(String::as_str).collect();
    // Running-check and lookup share one read, so the proposals about to run
    // are the ones a settled report offered. Proposals live in whichever
    // report planned them: the project slot's or the machine slot's.
    let lookup = |slot: &SharedLiveScan| {
        slot.with_read(|live| {
            (
                live.running,
                live.report.generated_at,
                live.report
                    .remediations
                    .iter()
                    .filter(|proposal| wanted.contains(proposal.id.as_str()))
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
    };
    let (running, generated_at, mut proposals) = {
        let project = lookup(&state.live);
        // A running project slot always answers: its proposals are being
        // rebuilt, so an id that fails to resolve there must refuse as
        // "scan running", never fall through as unknown.
        if project.0 || project.2.len() == wanted.len() {
            project
        } else {
            lookup(&state.machine)
        }
    };
    if running {
        return Err(ApiError::conflict(
            "a scan is running; wait for it to finish, then apply the fix",
        ));
    }
    if proposals.len() != wanted.len() {
        return Err(ApiError::bad_request(
            "unknown remediation proposal id; re-read GET /api/live for the current plan",
        ));
    }
    if proposals
        .iter()
        .any(|proposal| proposal.class == crate::remediation::ExecutionClass::Manual)
    {
        return Err(ApiError::bad_request(
            "this remediation requires manual steps and cannot be applied by husk",
        ));
    }
    if body.allow_system_packages {
        proposals = proposals
            .into_iter()
            .map(crate::remediation::with_break_system_packages)
            .collect();
    }
    let run_dependencies = proposals.iter().any(|proposal| {
        matches!(
            proposal.action,
            crate::remediation::RemediationOperation::DependencyUpdate { .. }
        )
    });
    // Findings keyed by proposal id, so a ledger entry names what it fixed.
    let targets: std::collections::HashMap<String, String> = proposals
        .iter()
        .map(|proposal| {
            (
                proposal.id.clone(),
                proposal
                    .finding_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| proposal.id.clone()),
            )
        })
        .collect();
    let outcome = tokio::task::spawn_blocking(move || {
        // One plan, one `apply` call: one lock, one snapshot directory, one
        // rollback point for the whole click.
        let plan = crate::remediation::RemediationPlan {
            generated_at,
            proposals,
        };
        let mut options = crate::remediation::ApplyOptions::new(false);
        options.deps = run_dependencies;
        crate::remediation::apply(&plan, &options)
    })
    .await
    .map_err(|error| ApiError::internal(format!("remediation task failed: {error}")))?
    .map_err(|error| ApiError::internal(format!("remediation failed: {error:#}")))?;
    if outcome.results.is_empty() {
        return Err(ApiError::internal(
            "remediation executor returned no result",
        ));
    }
    // The ledger records what husk changed, so a proposal that found its change
    // already in place leaves no entry.
    for result in outcome
        .results
        .iter()
        .filter(|result| result.status == crate::remediation::ActionStatus::Applied)
    {
        let target = targets.get(&result.id).unwrap_or(&result.id);
        let _ = crate::ledger::append(
            "remediation.apply",
            target,
            Some(result.detail.as_str()),
            None,
        );
    }
    let tally = crate::remediation::ApplyTally::of(&outcome.results);
    Ok(Json(ApplyRemediationResult {
        ok: tally.ok(),
        applied: tally.applied,
        skipped: tally.skipped,
        needs_user: tally.needs_user,
        failed: tally.failed,
        message: crate::remediation::apply_summary(&outcome.results),
        results: outcome.results,
    }))
}

/// Reject any request whose `Host` isn't loopback, and any state-changing
/// request with a non-loopback `Origin`: the standard localhost-API guards
/// against DNS rebinding and cross-site requests driving `/api/rescan`,
/// `/api/remediation/apply`, or `/api/finding/mute` from a malicious webpage.
/// An absent `Origin` passes (curl, same-origin GETs, non-browser clients).
async fn require_loopback(req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(host_is_loopback)
        // HTTP/2 carries the authority in the URI instead of a Host header.
        .or_else(|| req.uri().authority().map(|a| host_is_loopback(a.as_str())))
        .unwrap_or(false);
    if !host_ok {
        return (
            StatusCode::FORBIDDEN,
            "husk web only answers to localhost (rejected non-loopback Host)",
        )
            .into_response();
    }
    let state_changing = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if state_changing && let Some(origin) = req.headers().get(ORIGIN) {
        let origin_ok = origin.to_str().ok().is_some_and(origin_is_loopback);
        if !origin_ok {
            return (
                StatusCode::FORBIDDEN,
                "cross-origin request rejected (non-loopback Origin)",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// `localhost` / `127.0.0.1` / `[::1]` (any loopback IP, optional port);
/// anything else on a loopback-bound server is a rebinding/proxy suspect.
fn host_is_loopback(host: &str) -> bool {
    let host = host.trim();
    let bare = if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6 (`[::1]:7770`).
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else if let Some((name, port)) = host.rsplit_once(':') {
        // `name:port`, but a bare unbracketed IPv6 address also contains
        // colons and has no port to strip.
        if name.contains(':') || port.is_empty() || port.bytes().any(|b| !b.is_ascii_digit()) {
            host
        } else {
            name
        }
    } else {
        host
    };
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// An `Origin` header value (`scheme://host[:port]`) with a loopback host.
/// The literal `null` origin (sandboxed iframes, some redirects) is rejected.
fn origin_is_loopback(origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(host_is_loopback)
}

/// Serve a file from the embedded `web/dist`. Anything that isn't a bundled
/// asset falls back to `index.html` (so a deep link still loads the app).
async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    match WebAssets::get(path).filter(|_| !path.is_empty()) {
        // Content-hashed assets (e.g. assets/index-*.js) are immutable: the name
        // changes on every build, so cache them forever.
        Some(file) => (
            [
                (CONTENT_TYPE, file.metadata.mimetype()),
                (CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            file.data,
        )
            .into_response(),
        // A missing bundle file must 404 rather than fall back: answering a
        // stale `assets/index-<hash>.js` with the HTML shell makes the browser
        // reject the module for its MIME type and paint a blank page, with
        // nothing in the server log to say why.
        None if path.starts_with("assets/") => {
            (StatusCode::NOT_FOUND, "asset not in this husk build").into_response()
        }
        // index.html (the SPA shell, served for `/` and any deep link) must never
        // be cached, or the browser keeps pointing at a stale hashed bundle.
        None => match WebAssets::get("index.html") {
            Some(file) => (
                [
                    (CONTENT_TYPE, file.metadata.mimetype()),
                    (CACHE_CONTROL, "no-cache"),
                ],
                file.data,
            )
                .into_response(),
            None => (StatusCode::NOT_FOUND, "husk web build missing").into_response(),
        },
    }
}

/// Account-connection status surfaced to the web UI. The backend URL is
/// resolved like every `husk` cloud command (`HUSK_BACKEND_URL` > config file >
/// default); the account block comes from `cloud::auth::whoami`, which reads
/// `~/.husk/credentials.json` (or `HUSK_TOKEN`). Logged out, backend
/// unreachable, and signed in are three distinct states the UI renders.
#[derive(Serialize)]
struct AccountStatus {
    /// `true` only when the backend confirmed a usable session.
    connected: bool,
    /// Resolved backend base URL (so the UI can show where it would connect).
    backend_url: String,
    /// Signed-in account, present only when `connected`.
    account: Option<AccountInfo>,
    /// Human-readable note for the not-connected / error states.
    detail: Option<String>,
}

/// The subset of the backend account the web UI displays. Mirrors
/// `cloud::auth::Account` (which is `Deserialize`-only) into a `Serialize` shape.
#[derive(Serialize)]
struct AccountInfo {
    email: String,
    email_verified: bool,
    display_name: Option<String>,
    tier: String,
}

async fn api_account() -> Result<Json<AccountStatus>, ApiError> {
    let config = crate::cloud::HuskCloudConfig::load().unwrap_or_default();
    let backend_url = crate::cloud::effective_backend_url(&config);

    let client = crate::cloud::http_client()
        .map_err(|err| ApiError::internal(format!("could not build HTTP client: {err}")))?;

    Ok(
        match crate::cloud::auth::whoami(&backend_url, &client).await {
            Ok(Some(account)) => Json(AccountStatus {
                connected: true,
                backend_url,
                account: Some(AccountInfo {
                    email: account.email,
                    email_verified: account.email_verified,
                    display_name: account.display_name.filter(|name| !name.trim().is_empty()),
                    tier: account.tier,
                }),
                detail: None,
            }),
            Ok(None) => Json(AccountStatus {
                connected: false,
                backend_url,
                account: None,
                detail: Some("not connected".to_string()),
            }),
            Err(err) => Json(AccountStatus {
                connected: false,
                backend_url,
                account: None,
                // Rejected credentials / unreachable backend is still a 200
                // AccountStatus the UI renders, not an HTTP error.
                detail: Some(format!("{err:#}")),
            }),
        },
    )
}

/// Body for `POST /api/feedback`: free-text feedback typed into the web UI's
/// Send-feedback dialog, with an optional reply email.
#[derive(Deserialize)]
struct FeedbackBody {
    message: String,
    #[serde(default)]
    contact: Option<String>,
}

#[derive(Serialize)]
struct FeedbackResult {
    sent: bool,
}

/// Forward feedback to the Husk backend server-side, so the browser never
/// talks cross-origin and the backend URL resolution (`HUSK_BACKEND_URL` >
/// config file > default) stays in one place (`cloud::feedback`). Validation
/// failures are 400s the dialog shows inline; an unreachable or rejecting
/// backend is a 502 with a clear message.
async fn api_feedback(Json(body): Json<FeedbackBody>) -> Result<Json<FeedbackResult>, ApiError> {
    let message = crate::cloud::feedback::clean_message(&body.message)
        .map_err(|err| ApiError::bad_request(format!("{err:#}")))?;
    let contact = crate::cloud::feedback::clean_contact(body.contact.as_deref());
    // `{err}` (not `{err:#}`): the outermost context is the user-facing line
    // ("could not reach the Husk backend at ..."); the transport error chain
    // underneath is noise in a dialog.
    crate::cloud::feedback::send(&message, contact.as_deref(), "web")
        .await
        .map_err(|err| ApiError::bad_gateway(err.to_string()))?;
    Ok(Json(FeedbackResult { sent: true }))
}

/// Telemetry consent state surfaced to the web UI's one-time consent card.
/// Reads and writes the same on-disk state (`~/.husk/config.json` plus the
/// telemetry meta file) as the CLI prompt and the TUI pane, so no surface ever
/// re-asks once any surface has asked.
#[derive(Serialize)]
struct TelemetryConsentView {
    /// `unset` | `enabled` | `disabled`.
    state: &'static str,
    /// Whether the one-time consent card is due now: no decision recorded
    /// yet (or a yes to an older consent message version) and no environment
    /// kill switch (`CI`, `DO_NOT_TRACK`, `HUSK_TELEMETRY_DISABLED`) active.
    ask_due: bool,
}

fn consent_view(telemetry: &crate::cloud::telemetry::Telemetry) -> TelemetryConsentView {
    let state = match telemetry.consent() {
        crate::cloud::TelemetryConsent::Unset => "unset",
        crate::cloud::TelemetryConsent::Enabled => "enabled",
        crate::cloud::TelemetryConsent::Disabled => "disabled",
    };
    TelemetryConsentView {
        state,
        // A browser session is interactive by construction, so the TTY inputs
        // of the shared decision are fixed true here.
        ask_due: crate::cloud::telemetry::consent_due_now(telemetry, true, true),
    }
}

async fn api_telemetry_consent(State(state): State<AppState>) -> Json<TelemetryConsentView> {
    Json(consent_view(&state.telemetry))
}

/// Body for `POST /api/telemetry/consent`: the explicit answer from the card.
/// `enable: false` covers both "No thanks" and dismissing the card; either
/// way the asked state persists and the card never returns.
#[derive(Deserialize)]
struct TelemetryConsentBody {
    enable: bool,
}

async fn api_telemetry_consent_answer(
    State(state): State<AppState>,
    Json(body): Json<TelemetryConsentBody>,
) -> Result<Json<TelemetryConsentView>, ApiError> {
    let outcome = if body.enable {
        state.telemetry.enable()
    } else {
        state.telemetry.disable()
    };
    outcome.map_err(|err| ApiError::internal(format!("could not record the decision: {err:#}")))?;
    Ok(Json(consent_view(&state.telemetry)))
}

/// Which coding agents already have husk's MCP server registered locally. Drives
/// the "Configured / Not configured" chips on the AI-agent-setup page. Pure local
/// filesystem reads (via `agent::is_installed`); no network, no scan data.
async fn api_agents() -> Json<std::collections::BTreeMap<String, bool>> {
    // `claude-code` is the plugin path (detected separately); the rest are
    // `husk mcp install` targets.
    Json(
        std::iter::once("claude-code")
            .chain(crate::agent::INSTALL_AGENTS.iter().copied())
            .map(|id| (id.to_string(), crate::agent::is_installed(id)))
            .collect(),
    )
}

/// Start an in-UI device-flow login. Returns the user code to show, the URL to
/// open for approval, and the opaque `device_code` the UI polls with. No
/// credentials are written here; that happens on approval in `api_login_poll`.
#[derive(Serialize)]
struct LoginStart {
    user_code: String,
    verification_uri_complete: String,
    device_code: String,
    interval: u64,
    expires_in: u64,
}

async fn api_login_unavailable() -> ApiError {
    ApiError::service_unavailable("Account sign-in is coming soon.")
}

async fn api_login_start() -> Result<Json<LoginStart>, ApiError> {
    let s = crate::cloud::auth::web_device_start()
        .await
        .map_err(|err| ApiError::bad_gateway(format!("{err:#}")))?;
    Ok(Json(LoginStart {
        user_code: s.user_code,
        verification_uri_complete: s.verification_uri_complete,
        device_code: s.device_code,
        interval: s.interval.max(1),
        expires_in: s.expires_in,
    }))
}

/// Poll a started login once. On approval, credentials are stored locally
/// (`~/.husk/credentials.json`, same as the CLI) and `status` is `approved`.
#[derive(serde::Deserialize)]
struct LoginPollBody {
    device_code: String,
}

#[derive(Serialize)]
struct LoginPoll {
    /// `pending` | `slow_down` | `approved` | `denied` | `expired`.
    /// `slow_down` asks the client to back off its poll interval (RFC 8628).
    status: &'static str,
}

async fn api_login_poll(Json(body): Json<LoginPollBody>) -> Result<Json<LoginPoll>, ApiError> {
    use crate::cloud::auth::WebPollStatus;
    let status = match crate::cloud::auth::web_device_poll(&body.device_code)
        .await
        .map_err(|err| ApiError::bad_gateway(format!("{err:#}")))?
    {
        WebPollStatus::Pending => "pending",
        WebPollStatus::SlowDown => "slow_down",
        WebPollStatus::Approved => "approved",
        WebPollStatus::Denied => "denied",
        WebPollStatus::Expired => "expired",
    };
    Ok(Json(LoginPoll { status }))
}

/// The committed project policy (`.husk/policy.toml`, discovered from the scan
/// roots) and the personal append-only trust ledger (`~/.husk/ledger.jsonl`)
/// surfaced to the web UI. Both are strictly local, read-only here, and exactly
/// what the CLI's `husk policy` / `husk ledger` show, so the web and terminal
/// report the same state.
#[derive(Serialize)]
struct PolicyStatus {
    /// `None` when no `.husk/policy.toml` exists for the scanned project(s).
    policy: Option<PolicyView>,
    ledger: LedgerView,
}

#[derive(Serialize)]
struct PolicyView {
    /// The directory holding `policy.toml` (e.g. `<project>/.husk`).
    dir: String,
    blocked: Vec<String>,
    allowed: Vec<String>,
    /// The muted findings (`[[suppress]]` entries): id + optional reason. The UI
    /// uses these both to render the muted state and to list/unmute them.
    suppressed: Vec<SuppressedView>,
    /// CI fail threshold (`high` by default).
    ci_fail_on: String,
}

#[derive(Serialize)]
struct SuppressedView {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct LedgerView {
    /// Total recorded trust decisions.
    count: usize,
    /// `true` when the hash chain verifies; `false` if any entry was edited
    /// or corrupted.
    intact: bool,
    /// The most recent decisions (newest first), capped for display.
    recent: Vec<crate::ledger::LedgerEntry>,
}

async fn api_policy(State(state): State<AppState>) -> Json<PolicyStatus> {
    let roots = state.live.with_read(|live| live.report.roots.clone());

    let policy = crate::policy::Policy::discover(&roots)
        .ok()
        .flatten()
        .map(|p| PolicyView {
            dir: p.dir.display().to_string(),
            blocked: p.config.packages.block.clone(),
            allowed: p.config.packages.allow.clone(),
            suppressed: p
                .config
                .suppress
                .iter()
                .map(|s| SuppressedView {
                    id: s.id.clone(),
                    reason: s.reason.clone(),
                })
                .collect(),
            ci_fail_on: p
                .config
                .ci
                .fail_on
                .clone()
                .unwrap_or_else(|| "high".to_string()),
        });

    let entries = crate::ledger::load().unwrap_or_default();
    let intact = crate::ledger::verify(&entries).is_none();
    let recent: Vec<crate::ledger::LedgerEntry> = entries.iter().rev().take(20).cloned().collect();

    Json(PolicyStatus {
        policy,
        ledger: LedgerView {
            count: entries.len(),
            intact,
            recent,
        },
    })
}

/// The security guide merged with your personal state (the catalog is truth;
/// progress joins scan verification with read/complete/dismiss decisions).
async fn api_guide(State(state): State<AppState>) -> Json<crate::guide::GuideReport> {
    let report = state.live.with_read(|live| live.report.clone());
    let machine = finished_report(&state.machine);
    Json(crate::guide::assess(
        &report,
        machine.as_ref(),
        &crate::guide::load_state(),
    ))
}

/// The slot's report if a scan has completed there; `None` while it is idle
/// or has only ever streamed partial results.
fn finished_report(slot: &SharedLiveScan) -> Option<crate::model::ScanReport> {
    slot.with_read(|live| {
        (live.finished_at.is_some() && !live.running).then(|| live.report.clone())
    })
}

/// Body for `POST /api/guide/task`: mark a to-do done, dismiss it (won't do),
/// or clear the override. `reason` is optional.
#[derive(serde::Deserialize)]
struct GuideTaskAction {
    id: String,
    action: String,
    #[serde(default)]
    reason: Option<String>,
}

/// Persist a per-task override to the XDG data file and return the fresh guide.
/// An unknown `action` or task `id` is a 400, never a silent no-op: a typo'd
/// or stale id must not be persisted as dead state.
async fn api_guide_task(
    State(state): State<AppState>,
    Json(body): Json<GuideTaskAction>,
) -> Result<Json<crate::guide::GuideReport>, ApiError> {
    let action: crate::guide::GuideAction = body
        .action
        .parse()
        .map_err(|err| ApiError::bad_request(format!("{err:#}")))?;
    if !crate::guide::is_known_task(&body.id) {
        return Err(ApiError::bad_request(format!(
            "no guide task with id `{}`; see GET /api/guide for valid ids",
            body.id
        )));
    }
    let reason = body
        .reason
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());
    let user = crate::guide::apply(&body.id, action, reason)
        .map_err(|err| ApiError::internal(format!("{err:#}")))?;
    let report = state.live.with_read(|live| live.report.clone());
    let machine = finished_report(&state.machine);
    Ok(Json(crate::guide::assess(&report, machine.as_ref(), &user)))
}

/// Body for `POST /api/finding/mute`: silence one or more finding ids by writing
/// `[[suppress]]` entries into the project policy + recording them on the ledger.
/// Accepts a single `id` or a batch `ids` (a whole grouped category at once), so
/// the UI never has to await a per-id loop.
#[derive(serde::Deserialize)]
struct MuteBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct MuteResult {
    /// Human-readable outcome (e.g. "Muted 2. Rescan to apply").
    message: String,
    /// How many new suppressions were written (idempotent: already-muted = 0).
    muted: usize,
    /// The policy dir the suppressions landed in.
    policy_dir: String,
}

/// Mute (suppress) one or more findings: append `[[suppress]]` entries to the
/// committed `.husk/policy.toml` (discovered from the scan roots, or created in
/// the first scanned directory) and record each decision on the trust ledger.
/// Takes effect on the next scan; strictly local, comment-preserving,
/// idempotent.
async fn api_finding_mute(
    State(state): State<AppState>,
    Json(body): Json<MuteBody>,
) -> Result<Json<MuteResult>, ApiError> {
    let mut ids: Vec<String> = body
        .id
        .into_iter()
        .chain(body.ids)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(ApiError::bad_request("missing finding id"));
    }
    let reason = body
        .reason
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());

    let roots = state.live.with_read(|live| live.report.roots.clone());
    let outcome = crate::policy::mute_findings(&roots, &ids, reason.as_deref())
        .map_err(|err| ApiError::internal(format!("{err:#}")))?;

    let dir = outcome.policy_dir.display().to_string();
    Ok(Json(MuteResult {
        message: if outcome.muted > 0 {
            format!("Muted {}. Rescan to apply (policy: {dir})", outcome.muted)
        } else {
            "Already muted in policy".to_string()
        },
        muted: outcome.muted,
        policy_dir: dir,
    }))
}

/// Unmute (un-suppress) one or more findings: remove their `[[suppress]]`
/// entries from the discovered project policy and record each on the ledger.
/// The inverse of [`api_finding_mute`]; takes effect on the next scan.
async fn api_finding_unmute(
    State(state): State<AppState>,
    Json(body): Json<MuteBody>,
) -> Result<Json<MuteResult>, ApiError> {
    let mut ids: Vec<String> = body
        .id
        .into_iter()
        .chain(body.ids)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(ApiError::bad_request("missing finding id"));
    }

    let roots = state.live.with_read(|live| live.report.roots.clone());

    // Unmute only touches an existing policy; nothing to revoke otherwise.
    if !roots
        .iter()
        .any(|root| crate::policy::discover_file(root).is_some())
    {
        return Err(ApiError::bad_request("no project policy to unmute from"));
    }
    let outcome = crate::policy::unmute_findings(&roots, &ids)
        .map_err(|err| ApiError::internal(format!("{err:#}")))?;

    let dir = outcome.policy_dir.display().to_string();
    Ok(Json(MuteResult {
        message: if outcome.muted > 0 {
            format!("Unmuted {}. Rescan to apply (policy: {dir})", outcome.muted)
        } else {
            "Not muted in policy".to_string()
        },
        muted: outcome.muted,
        policy_dir: dir,
    }))
}

async fn api_live(State(state): State<AppState>) -> Json<LiveScan> {
    Json(state.live.snapshot())
}

/// Every project Husk knows about, each carrying the freshest scan result that
/// covered it, whether that came from scanning the project or the machine.
/// Read from the stored reports rather than the live session, so the list is
/// complete the moment the page opens.
async fn api_projects() -> Result<Json<Vec<crate::projects::ProjectView>>, ApiError> {
    crate::projects::index()
        .map(Json)
        .map_err(|err| ApiError::internal(err.to_string()))
}

#[derive(serde::Deserialize)]
struct TrackBody {
    root: String,
    tracked: bool,
}

/// Track or untrack one project root, then return the refreshed list so the UI
/// re-renders from server truth instead of guessing the new order.
async fn api_projects_track(
    Json(body): Json<TrackBody>,
) -> Result<Json<Vec<crate::projects::ProjectView>>, ApiError> {
    let root = body.root.trim();
    if root.is_empty() {
        return Err(ApiError::bad_request("missing project root"));
    }
    crate::projects::set_tracked(std::path::Path::new(root), body.tracked)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    api_projects().await
}

async fn api_machine(State(state): State<AppState>) -> Json<LiveScan> {
    Json(state.machine.snapshot())
}

/// Start (or join) a machine-posture scan in the machine slot. Roots are
/// always the home directory; the only caller-controlled knob is when it
/// runs. Online/offline follows the session's launch options.
async fn api_machine_rescan(State(state): State<AppState>) -> Json<LiveScan> {
    let Some(home) = dirs::home_dir() else {
        return Json(state.machine.snapshot());
    };
    let mut options = ScanOptions::machine(home);
    if let Some(launch) = &state.options {
        options.online = launch.online;
    }
    let (snapshot, start) = state.machine.with_write(|live| {
        if live.running {
            (live.visible(), false)
        } else {
            live.restart(options.roots.clone());
            (live.visible(), true)
        }
    });
    if start {
        crate::scan::spawn_scan(options, state.machine.clone());
    }
    Json(snapshot)
}

/// Cap on history rows returned per roots group: the trend charts never need
/// more than a year of daily scans, and the file itself is unbounded.
const HISTORY_API_CAP: usize = 365;

/// Scan history across *all* scanned roots (oldest first): one summary row per
/// completed scan, from `~/.husk/history.jsonl`. The Scan-history tab groups
/// rows by `roots_key` itself. Read-only and strictly local.
async fn api_history() -> Json<Vec<crate::history::HistoryEntry>> {
    let entries = tokio::task::spawn_blocking(|| {
        let mut groups: std::collections::HashMap<String, Vec<crate::history::HistoryEntry>> =
            std::collections::HashMap::new();
        for entry in crate::history::load_all() {
            groups
                .entry(entry.roots_key.clone())
                .or_default()
                .push(entry);
        }
        let mut entries: Vec<_> = groups
            .into_values()
            .flat_map(|mut group| {
                // File order is append order, so groups are oldest-first:
                // dropping the front keeps the newest rows.
                if group.len() > HISTORY_API_CAP {
                    group.drain(..group.len() - HISTORY_API_CAP);
                }
                group
            })
            .collect();
        entries.sort_by_key(|entry| entry.at);
        entries
    })
    .await
    .unwrap_or_default();
    Json(entries)
}

#[derive(Deserialize)]
struct SourceQuery {
    /// The file to show. Must be one the current report points at.
    path: String,
    /// The line to centre the window on. Absent → the head of the file.
    line: Option<usize>,
}

/// One file a finding sits in, tokenized for the source panel: the browser
/// half of the TUI's source pane.
///
/// The path is checked against the current reports first. A localhost server
/// that reads whatever path a page asks for is a file-disclosure hole with a
/// URL, so the allowlist is exactly the set of files the UI already shows a
/// location for, computed by the same [`Finding::location`] the TUI opens.
async fn api_source(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<SourceQuery>,
) -> Result<Json<crate::highlight::Excerpt>, ApiError> {
    let path = std::path::PathBuf::from(&query.path);
    // Both reports, because the Scan view renders both: the machine-posture
    // scan is where the home-directory secrets live, and those are the rows a
    // reader most wants to see the line of.
    let flagged = [&state.live, &state.machine].into_iter().any(|scan| {
        scan.with_read(|live| {
            // Resolved findings too: the Solved panel opens the same detail
            // pane, and its file is one husk itself flagged a scan ago.
            let resolved = live.report.delta.iter().flat_map(|d| d.resolved.iter());
            live.report
                .findings
                .iter()
                .chain(resolved)
                .any(|finding| finding.location().is_some_and(|(at, _)| at == path))
        })
    });
    if !flagged {
        return Err(ApiError::bad_request("no finding sits in that file"));
    }
    crate::highlight::excerpt(
        &path,
        query.line.map(|line| line as u32),
        crate::highlight::RADIUS,
    )
    .map(Json)
    .map_err(|err| ApiError::bad_request(format!("{err:#}")))
}

#[derive(Deserialize)]
struct DirsQuery {
    /// Directory to list. Absent → the user's home directory.
    path: Option<String>,
}

#[derive(Serialize)]
struct DirEntry {
    name: String,
    path: String,
}

#[derive(Serialize)]
struct DirsView {
    /// Absolute path being listed.
    path: String,
    /// Parent directory, or `None` at the filesystem root.
    parent: Option<String>,
    /// Immediate subdirectories, name-sorted.
    dirs: Vec<DirEntry>,
}

/// List the immediate subdirectories of `path` so the web UI can browse the
/// local filesystem with mouse clicks. Localhost-only and read-only: it never
/// descends or reads file contents, just one directory level. Hidden dirs
/// (dotfiles) are skipped except well-known config homes are still reachable by
/// typing, keeping the picker uncluttered.
fn list_dirs(start: Option<String>) -> DirsView {
    let path = start
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("/"));
    let mut dirs = Vec::new();
    if let Ok(read) = std::fs::read_dir(&path) {
        for entry in read.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue;
                }
                dirs.push(DirEntry {
                    name,
                    path: entry.path().to_string_lossy().into_owned(),
                });
            }
        }
    }
    dirs.sort_by_key(|a| a.name.to_lowercase());
    DirsView {
        parent: path.parent().map(|p| p.to_string_lossy().into_owned()),
        path: path.to_string_lossy().into_owned(),
        dirs,
    }
}

async fn api_dirs(axum::extract::Query(q): axum::extract::Query<DirsQuery>) -> Json<DirsView> {
    Json(list_dirs(q.path))
}

/// Optional rescan body: `{ "roots": ["/path"] }` re-targets the scan at a
/// specific directory; an empty/absent body reuses the current scan roots.
#[derive(Default, Deserialize)]
struct RescanBody {
    #[serde(default)]
    roots: Vec<String>,
}

/// Re-target the scan if the caller picked a directory; otherwise keep the
/// existing roots. Blank entries are dropped so a stray empty input can't wipe
/// the scan target. Re-targeting also drops the retained report: results for
/// one directory must never be shown as the state of another.
fn resolve_rescan_roots(
    current: Vec<std::path::PathBuf>,
    requested: Vec<String>,
) -> Vec<std::path::PathBuf> {
    let requested: Vec<_> = requested
        .into_iter()
        .filter(|r| !r.trim().is_empty())
        .map(std::path::PathBuf::from)
        .collect();
    let roots = if requested.is_empty() {
        current
    } else {
        requested
    };
    // The report's roots become the scan's identity: the cache key and the
    // history row's `roots_key`. History drops rows whose roots are not
    // absolute, so a relatively-launched server (`husk web tst`) would record
    // scans the Scan-history tab then silently discards. An unresolvable root
    // is left as-is for the scan itself to report.
    if roots.is_empty() {
        return roots;
    }
    crate::scan::normalize_roots(roots.clone()).unwrap_or(roots)
}

async fn api_rescan(
    State(state): State<AppState>,
    body: Option<Json<RescanBody>>,
) -> Json<LiveScan> {
    let Some(mut options) = state.options.clone() else {
        return Json(state.live.snapshot());
    };
    let requested = body.map(|Json(b)| b.roots).unwrap_or_default();
    // Already canonical: "same target" has to be a fact about the directory,
    // not about how the CLI argument or the picker spelled it, or a plain
    // rescan of `.` would look like a re-target and throw the report away.
    options.roots = resolve_rescan_roots(options.roots, requested);

    // Decide-and-restart under one write lock so two concurrent rescan requests
    // can't both observe `running == false` and spawn duplicate scans.
    let (snapshot, start) = state.live.with_write(|live| {
        if live.running {
            (live.visible(), false)
        } else {
            live.restart(options.roots.clone());
            (live.visible(), true)
        }
    });
    if start {
        crate::scan::spawn_scan(options, state.live.clone());
    }
    Json(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The poll must report on every program a recipe can run, or a user whose
    /// only missing tool is the unreported one sees no reason the fix is dark.
    #[tokio::test]
    async fn tool_poll_reports_on_every_runnable_program() {
        let Json(tools) = api_remediation_tools().await;
        let mut expected = crate::remediation::plan::PROGRAMS.to_vec();
        expected.sort_unstable();
        assert_eq!(tools.keys().copied().collect::<Vec<_>>(), expected);
    }

    /// A stale hashed bundle name is the one 404 the SPA fallback must not
    /// swallow: served the HTML shell instead, the browser rejects the module
    /// and paints a blank page.
    #[tokio::test]
    async fn missing_bundle_asset_is_not_answered_with_the_shell() {
        let missing = static_handler("/assets/index-stale.js".parse().unwrap()).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let deep_link = static_handler("/guide".parse().unwrap()).await;
        assert_eq!(deep_link.status(), StatusCode::OK);
    }

    #[test]
    fn rescan_body_defaults_to_empty_roots() {
        let body: RescanBody = serde_json::from_str("{}").unwrap();
        assert!(body.roots.is_empty());
    }

    #[test]
    fn rescan_body_parses_roots() {
        let body: RescanBody = serde_json::from_str(r#"{"roots":["/a","/b"]}"#).unwrap();
        assert_eq!(body.roots, vec!["/a".to_string(), "/b".to_string()]);
    }

    #[test]
    fn empty_request_keeps_current_roots() {
        let current = vec![PathBuf::from("/home/me")];
        assert_eq!(
            resolve_rescan_roots(current.clone(), vec![]),
            current,
            "absent roots reuse the current target"
        );
        assert_eq!(
            resolve_rescan_roots(current.clone(), vec!["  ".to_string()]),
            current,
            "blank-only input must not wipe the scan target"
        );
    }

    #[test]
    fn resolved_roots_are_absolute_so_history_keeps_the_scan() {
        // `src` is relative to the crate root, which is the test process's cwd.
        let resolved = resolve_rescan_roots(vec![PathBuf::from("src")], vec![]);
        assert_eq!(
            resolved,
            vec![PathBuf::from("src").canonicalize().expect("canonicalize")],
            "a relative root must be resolved before it becomes the scan identity"
        );
    }

    #[test]
    fn requested_roots_override_and_drop_blanks() {
        let resolved = resolve_rescan_roots(
            vec![PathBuf::from("/home/me")],
            vec!["/proj".to_string(), "".to_string(), " ".to_string()],
        );
        assert_eq!(resolved, vec![PathBuf::from("/proj")]);
    }

    #[test]
    fn host_check_accepts_loopback_and_rejects_everything_else() {
        for ok in [
            "localhost",
            "LOCALHOST",
            "localhost:7770",
            "127.0.0.1",
            "127.0.0.1:7770",
            "127.4.5.6",
            "[::1]",
            "[::1]:7770",
            "::1",
        ] {
            assert!(host_is_loopback(ok), "{ok} should pass");
        }
        for bad in [
            "evil.example",
            "evil.example:7770",
            "192.168.1.10:7770",
            "localhost.evil.example",
            "[2001:db8::1]:7770",
            "",
        ] {
            assert!(!host_is_loopback(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn origin_check_requires_a_loopback_web_origin() {
        assert!(origin_is_loopback("http://localhost:5173"));
        assert!(origin_is_loopback("http://127.0.0.1:7770"));
        assert!(origin_is_loopback("https://localhost"));
        assert!(!origin_is_loopback("http://evil.example"));
        assert!(!origin_is_loopback("https://evil.example:7770"));
        assert!(!origin_is_loopback("null"));
        assert!(!origin_is_loopback("file://x"));
    }

    /// Send one raw HTTP/1.1 request to the live server and return the
    /// response head + body as a string. Raw sockets so the test controls the
    /// exact `Host`/`Origin` headers a rebinding page would send.
    async fn raw_request(addr: std::net::SocketAddr, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Serve against a throwaway telemetry state directory, so consent tests
    /// never read or write the developer's real `~/.husk`.
    async fn serve_in(
        live: LiveScan,
        options: Option<ScanOptions>,
        state_dir: &std::path::Path,
    ) -> WebHandle {
        let state = AppState {
            live: std::sync::Arc::new(std::sync::RwLock::new(live)),
            machine: std::sync::Arc::new(std::sync::RwLock::new(LiveScan::idle(Vec::new()))),
            options,
            telemetry: crate::cloud::telemetry::Telemetry::at(state_dir),
        };
        start_with_state(state, "127.0.0.1:0".parse().unwrap(), false)
            .await
            .expect("start server")
    }

    async fn serve(live: LiveScan, options: Option<ScanOptions>) -> WebHandle {
        serve_in(
            live,
            options,
            &std::env::temp_dir().join("husk-web-test-state"),
        )
        .await
    }

    /// [`serve`] with a machine-posture report alongside the project one.
    async fn serve_with_machine(live: LiveScan, machine: LiveScan) -> WebHandle {
        let state = AppState {
            live: std::sync::Arc::new(std::sync::RwLock::new(live)),
            machine: std::sync::Arc::new(std::sync::RwLock::new(machine)),
            options: None,
            telemetry: crate::cloud::telemetry::Telemetry::at(
                std::env::temp_dir().join("husk-web-test-state"),
            ),
        };
        start_with_state(state, "127.0.0.1:0".parse().unwrap(), false)
            .await
            .expect("start server")
    }

    async fn test_server() -> WebHandle {
        serve(
            LiveScan::finished(crate::model::ScanReport::empty(vec![])),
            None,
        )
        .await
    }

    /// A finished scan of `/proj` with one finding, then a rescan of the same
    /// target in flight: the state a user is in when they click during a scan.
    fn rescanning(finding_id: &str) -> LiveScan {
        let mut report = crate::model::ScanReport::empty(vec![PathBuf::from("/proj")]);
        report.findings = vec![crate::model::Finding::new(
            finding_id,
            finding_id,
            crate::model::Severity::High,
            crate::rule::Category::Secret,
            "test",
            None,
            None,
            "s",
            None,
            "r",
        )];
        let mut live = LiveScan::finished(report);
        live.restart(vec![PathBuf::from("/proj")]);
        live
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        raw_request(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        )
        .await
    }

    /// The source panel may read only what the report already points at.
    /// Without this the localhost API is a file reader any page in the browser
    /// can aim at the user's home directory.
    #[tokio::test]
    async fn the_source_api_serves_flagged_files_and_refuses_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let flagged = dir.path().join("app.json");
        std::fs::write(&flagged, "{\n  \"token\": \"redacted\"\n}\n").expect("write");
        let secret = dir.path().join("id_rsa");
        std::fs::write(&secret, "PRIVATE").expect("write");

        let mut report = crate::model::ScanReport::empty(vec![dir.path().to_path_buf()]);
        report.findings = vec![crate::model::Finding::new(
            "secret-in-json",
            "Secret in app.json",
            crate::model::Severity::High,
            crate::rule::Category::Secret,
            "test",
            Some(flagged.clone()),
            Some(2),
            "s",
            None,
            "r",
        )];
        // A resolved finding's file stays readable: the Solved panel opens the
        // same detail pane, source view and all.
        let fixed = dir.path().join("was-leaking.env");
        std::fs::write(&fixed, "TOKEN=rotated\n").expect("write");
        report.delta = Some(crate::model::ScanDelta {
            previous_at: chrono::Utc::now(),
            previous_score: 50,
            score: 60,
            new_count: 0,
            unchanged_count: 1,
            resolved_count: 1,
            resolved: vec![crate::model::Finding::new(
                "rotated-token",
                "Token was exposed",
                crate::model::Severity::High,
                crate::rule::Category::Secret,
                "test",
                Some(fixed.clone()),
                Some(1),
                "s",
                None,
                "r",
            )],
            new: Vec::new(),
        });
        // The home-directory secrets sit in the machine report, not the project
        // one, and they are the rows a reader most wants the line of.
        let machine_flagged = dir.path().join(".npmrc");
        std::fs::write(&machine_flagged, "//registry:_authToken=redacted\n").expect("write");
        let mut machine = crate::model::ScanReport::empty(vec![dir.path().to_path_buf()]);
        machine.findings = vec![crate::model::Finding::new(
            "npm-token",
            "npm publish token exposed",
            crate::model::Severity::Critical,
            crate::rule::Category::Secret,
            "test",
            Some(machine_flagged.clone()),
            Some(1),
            "s",
            None,
            "r",
        )];
        let server =
            serve_with_machine(LiveScan::finished(report), LiveScan::finished(machine)).await;

        let shown = get(
            server.addr,
            &format!("/api/source?path={}&line=2", flagged.display()),
        )
        .await;
        assert!(shown.starts_with("HTTP/1.1 200"), "{shown}");
        assert!(shown.contains("\"focus\":2"), "{shown}");
        assert!(
            shown.contains("\"key\""),
            "the key token must survive: {shown}"
        );

        let from_machine = get(
            server.addr,
            &format!("/api/source?path={}&line=1", machine_flagged.display()),
        )
        .await;
        assert!(
            from_machine.starts_with("HTTP/1.1 200"),
            "a machine-scan finding's file must be readable: {from_machine}"
        );

        let solved = get(
            server.addr,
            &format!("/api/source?path={}&line=1", fixed.display()),
        )
        .await;
        assert!(
            solved.starts_with("HTTP/1.1 200"),
            "a resolved finding's file must stay readable: {solved}"
        );

        let refused = get(
            server.addr,
            &format!("/api/source?path={}", secret.display()),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
        assert!(
            refused.contains("no finding sits in that file"),
            "{refused}"
        );
    }

    async fn post(addr: std::net::SocketAddr, path: &str, body: &str) -> String {
        raw_request(
            addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await
    }

    /// A mid-scan rescan reply must carry the report the user is looking at,
    /// never an empty one: the browser caches the reply as the current state.
    #[tokio::test]
    async fn a_rescan_reply_carries_the_previous_report() {
        let server = serve(
            rescanning("kept-visible"),
            Some(ScanOptions::new(vec![PathBuf::from("/proj")])),
        )
        .await;

        let response = post(server.addr, "/api/rescan", "{}").await;

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"running\":true"), "{response}");
        assert!(
            response.contains("kept-visible"),
            "the previous findings must survive the rescan: {response}"
        );
    }

    /// Applying a fix while a scan is walking the tree is refused with the
    /// scan-running reason, not misreported as an unknown proposal id.
    #[tokio::test]
    async fn applying_a_fix_during_a_scan_is_refused_with_the_reason() {
        let scanning = serve(rescanning("kept-visible"), None).await;

        let response = post(
            scanning.addr,
            "/api/remediation/apply",
            r#"{"ids":["dependency-update:npm:left-pad"]}"#,
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 409"), "{response}");
        assert!(response.contains("a scan is running"), "{response}");
        assert!(
            !response.contains("unknown remediation proposal id"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn applying_an_unknown_proposal_id_still_fails_when_no_scan_runs() {
        let settled = test_server().await;

        let response = post(
            settled.addr,
            "/api/remediation/apply",
            r#"{"ids":["dependency-update:npm:left-pad"]}"#,
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(
            response.contains("unknown remediation proposal id"),
            "{response}"
        );
    }

    /// Feedback validation fails before any network resolution, so a bad
    /// message is a local 400 with the reason, never a hung or forwarded call.
    /// (The forwarding half is covered by `cloud::feedback`'s stub-server
    /// tests; this route only adds validation + the "web" context.)
    #[tokio::test]
    async fn feedback_rejects_a_blank_or_oversized_message_locally() {
        let server = test_server().await;

        let blank = post(server.addr, "/api/feedback", r#"{"message":"  "}"#).await;
        assert!(blank.starts_with("HTTP/1.1 400"), "{blank}");
        assert!(blank.contains("feedback message is empty"), "{blank}");

        let long = format!(r#"{{"message":"{}"}}"#, "x".repeat(5000));
        let oversized = post(server.addr, "/api/feedback", &long).await;
        assert!(oversized.starts_with("HTTP/1.1 400"), "{oversized}");
        assert!(oversized.contains("too long"), "{oversized}");
    }

    #[tokio::test]
    async fn login_routes_are_unavailable_until_sign_in_launches() {
        let server = test_server().await;

        for path in ["/api/login/start", "/api/login/poll"] {
            let response = raw_request(
                server.addr,
                &format!(
                    "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 503"), "{path}: {response}");
            assert!(response.contains("Account sign-in is coming soon."));
        }
    }

    #[tokio::test]
    async fn rebinding_style_host_is_rejected_and_localhost_passes() {
        let server = test_server().await;

        // DNS rebinding: the request reaches loopback but carries the
        // attacker page's hostname.
        let rebound = raw_request(
            server.addr,
            "GET /api/live HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(rebound.starts_with("HTTP/1.1 403"), "{rebound}");

        // Normal local requests pass: API and the embedded SPA shell.
        for host in ["127.0.0.1", "localhost:9", "[::1]"] {
            let ok = raw_request(
                server.addr,
                &format!("GET /api/live HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(ok.starts_with("HTTP/1.1 200"), "Host {host}: {ok}");
        }
        let spa = raw_request(
            server.addr,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(spa.starts_with("HTTP/1.1 200"), "{spa}");
        assert!(spa.contains("text/html"), "{spa}");
    }

    #[tokio::test]
    async fn state_changing_routes_require_a_local_origin() {
        let server = test_server().await;

        // A cross-site POST (browser always attaches the page's Origin).
        let cross = raw_request(
            server.addr,
            "POST /api/rescan HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://evil.example\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        assert!(cross.starts_with("HTTP/1.1 403"), "{cross}");

        // The SPA's own same-origin POST passes the guard.
        let local = raw_request(
            server.addr,
            "POST /api/rescan HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        assert!(!local.starts_with("HTTP/1.1 403"), "{local}");

        // No Origin (curl, scripts) also passes the guard.
        let headerless = raw_request(
            server.addr,
            "POST /api/rescan HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        assert!(!headerless.starts_with("HTTP/1.1 403"), "{headerless}");
    }

    /// The consent endpoints round-trip against the shared on-disk state:
    /// answering (either way) persists the decision, and once a decision is
    /// recorded the card is never due again. Asserts only on env-independent
    /// facts, so the test passes identically on a workstation and under CI's
    /// `CI=true` kill switch.
    #[tokio::test]
    async fn consent_endpoints_persist_the_answer_and_stop_asking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = serve_in(
            LiveScan::finished(crate::model::ScanReport::empty(vec![])),
            None,
            dir.path(),
        )
        .await;

        let fresh = raw_request(
            server.addr,
            "GET /api/telemetry/consent HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(fresh.starts_with("HTTP/1.1 200"), "{fresh}");
        assert!(fresh.contains("\"state\":\"unset\""), "{fresh}");

        let enabled = post(server.addr, "/api/telemetry/consent", r#"{"enable":true}"#).await;
        assert!(enabled.starts_with("HTTP/1.1 200"), "{enabled}");
        assert!(enabled.contains("\"state\":\"enabled\""), "{enabled}");
        assert!(enabled.contains("\"ask_due\":false"), "{enabled}");
        let telemetry = crate::cloud::telemetry::Telemetry::at(dir.path());
        assert_eq!(telemetry.consent(), crate::cloud::TelemetryConsent::Enabled);

        let declined = post(server.addr, "/api/telemetry/consent", r#"{"enable":false}"#).await;
        assert!(declined.starts_with("HTTP/1.1 200"), "{declined}");
        assert!(declined.contains("\"state\":\"disabled\""), "{declined}");
        assert!(declined.contains("\"ask_due\":false"), "{declined}");
        assert_eq!(
            telemetry.consent(),
            crate::cloud::TelemetryConsent::Disabled
        );
    }

    /// A malformed answer body is rejected and records nothing: dismissal is
    /// an explicit `enable:false`, never a parse accident.
    #[tokio::test]
    async fn consent_answer_rejects_a_malformed_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = serve_in(
            LiveScan::finished(crate::model::ScanReport::empty(vec![])),
            None,
            dir.path(),
        )
        .await;

        let response = post(server.addr, "/api/telemetry/consent", r#"{"on":"yes"}"#).await;
        assert!(
            response.starts_with("HTTP/1.1 4"),
            "malformed body must 4xx: {response}"
        );
        let telemetry = crate::cloud::telemetry::Telemetry::at(dir.path());
        assert_eq!(telemetry.consent(), crate::cloud::TelemetryConsent::Unset);
    }

    #[test]
    fn list_dirs_lists_subdirs_and_parent() {
        let tmp = std::env::temp_dir().join(format!("husk-dirs-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::create_dir_all(tmp.join(".hidden")).unwrap();
        std::fs::write(tmp.join("file.txt"), "x").unwrap();

        let view = list_dirs(Some(tmp.to_string_lossy().into_owned()));
        let names: Vec<_> = view.dirs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["sub"], "files and dotfiles are excluded");
        assert!(view.parent.is_some(), "non-root dir exposes a parent");

        // A bad path falls back to home (never panics / never empty path).
        assert!(!list_dirs(Some("/no/such/dir".into())).path.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
