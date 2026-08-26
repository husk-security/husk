//! `husk login` against the Husk identity provider (Zitadel).
//!
//! Prefers the Authorization Code + PKCE flow on a loopback redirect
//! ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)) when a browser is
//! available, falling back to the device authorization grant
//! ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) on headless machines
//! or when `HUSK_LOGIN_DEVICE=1` forces it. Both flows run through the
//! `oauth2` crate; the one hand-rolled token request is the web UI's
//! single-shot device poll ([`web_device_poll`]).
//!
//! Tokens live in `~/.husk/credentials.json` (owner-only permissions) and are
//! rotated via the refresh-token grant shortly before expiry. `HUSK_TOKEN`
//! always wins over stored credentials and is never persisted.

use super::{Credentials, api_url, env_truthy};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, DeviceAuthorizationUrl, PkceCodeChallenge,
    RedirectUrl, RefreshToken, Scope, StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::io::{Read, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Environment variable holding an explicit bearer token. Highest
/// precedence; never written to disk.
pub const TOKEN_ENV: &str = "HUSK_TOKEN";

/// Environment variable overriding the Zitadel issuer (instance URL).
pub const OIDC_ISSUER_ENV: &str = "HUSK_OIDC_ISSUER";
/// Environment variable overriding the Zitadel CLI client id.
pub const OIDC_CLIENT_ID_ENV: &str = "HUSK_OIDC_CLIENT_ID";
/// Environment variable that forces the device flow even when a browser is
/// available (set to a truthy value to skip the loopback-PKCE path).
pub const LOGIN_DEVICE_ENV: &str = "HUSK_LOGIN_DEVICE";

/// Default Zitadel issuer (instance URL) for the device flow.
pub const DEFAULT_OIDC_ISSUER: &str = "https://auth.husk-security.dev";

/// Refresh the access token when it expires within this many minutes.
const REFRESH_WINDOW_MINUTES: i64 = 5;
const GRANT_TYPE_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// OAuth scopes requested for the CLI: identity claims + a refresh token.
const SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];
/// How long the loopback listener waits for the browser redirect before
/// giving up and falling back to the device flow.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// How an interactive `husk login` ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginOutcome {
    /// The user approved the code; credentials are stored.
    LoggedIn,
    /// The user denied the request at the verification page.
    Denied,
    /// The one-time code expired before it was approved.
    Expired,
}

/// Result of [`refresh_if_needed`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// No usable stored credentials; the machine is logged out.
    NotLoggedIn,
    /// Valid credentials, freshly rotated when they were close to expiry.
    Active(Credentials),
}

/// The signed-in account as reported by the backend's `/api/v1/account`.
/// Only the fields the CLI/web surfaces display are modeled; the rest of the
/// response is ignored.
#[derive(Clone, Debug, Deserialize)]
pub struct Account {
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    pub tier: String,
}

/// The configured Zitadel issuer, for display in the login prompt.
pub fn oidc_issuer_display() -> String {
    oidc_issuer()
}

/// The Zitadel instance URL (issuer): `HUSK_OIDC_ISSUER` or the default.
fn oidc_issuer() -> String {
    std::env::var(OIDC_ISSUER_ENV)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_OIDC_ISSUER.to_string())
}

/// The Zitadel public client id for the CLI (`HUSK_OIDC_CLIENT_ID`). There is
/// no built-in default: the project's client id is provisioned with the
/// deployed Zitadel instance, so login requires it to be configured.
fn oidc_client_id() -> Result<String> {
    std::env::var(OIDC_CLIENT_ID_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .context(
            "no Husk OIDC client id configured; set HUSK_OIDC_CLIENT_ID to this machine's \
             Zitadel CLI client id (see the deployed instance)",
        )
}

/// The fully-configured OAuth client for the device flow (auth + token +
/// device-authorization endpoints set; introspection/revocation unset).
type OauthClient = oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    oauth2::basic::BasicTokenResponse,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
    oauth2::EndpointSet,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

fn oauth_client() -> Result<OauthClient> {
    let issuer = oidc_issuer();
    let client_id = oidc_client_id()?;
    Ok(BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new(format!("{issuer}/oauth/v2/authorize")).context("invalid OIDC issuer")?,
        )
        .set_token_uri(
            TokenUrl::new(format!("{issuer}/oauth/v2/token")).context("invalid OIDC issuer")?,
        )
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(format!("{issuer}/oauth/v2/device_authorization"))
                .context("invalid OIDC issuer")?,
        ))
}

/// An HTTP client for OAuth calls that never follows redirects (defense in
/// depth, per the oauth2 crate's guidance).
fn oauth_http_client() -> Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("husk/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build OAuth HTTP client")
}

/// Run the interactive login and store credentials in `~/.husk` on success.
///
/// Prefers the loopback-PKCE browser flow when a browser is available, and
/// otherwise (or on any browser-path failure) falls back to the device flow.
pub async fn login() -> Result<LoginOutcome> {
    let state_dir = &crate::paths::husk_home()?;
    // Both flows need the OIDC client id; resolve it up front so a missing
    // `HUSK_OIDC_CLIENT_ID` fails once, before any device-flow fallback notice.
    oidc_client_id()?;
    if browser_login_preferred() {
        match login_loopback(state_dir).await {
            Ok(Some(outcome)) => return Ok(outcome),
            Ok(None) => {
                eprintln!("Browser login timed out; falling back to a device code.");
            }
            Err(err) => {
                eprintln!("Browser login unavailable ({err:#}); falling back to a device code.");
            }
        }
    }
    login_device(state_dir).await
}

/// Whether `husk login` should attempt the loopback-PKCE browser flow before
/// the device flow. True when a desktop browser is plausibly reachable and the
/// user has not forced the device flow via [`LOGIN_DEVICE_ENV`].
fn browser_login_preferred() -> bool {
    if env_truthy(LOGIN_DEVICE_ENV) {
        return false;
    }
    browser_available()
}

/// Heuristic for whether a system browser can be opened. macOS always has one;
/// on Linux/BSD it requires a graphical session (`DISPLAY` or
/// `WAYLAND_DISPLAY`).
fn browser_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    env_present("DISPLAY") || env_present("WAYLAND_DISPLAY")
}

fn env_present(name: &str) -> bool {
    std::env::var_os(name)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

fn scopes() -> impl Iterator<Item = Scope> {
    SCOPES.iter().map(|scope| Scope::new((*scope).to_string()))
}

/// Run the Authorization Code + PKCE flow on a loopback redirect and store
/// credentials on success.
///
/// Returns `Ok(None)` when the browser redirect never arrives (timeout), so
/// the caller can fall back to the device flow. The Zitadel CLI client must
/// register the loopback redirect (`http://127.0.0.1/callback`, any port; the
/// RFC 8252 native-app pattern) for this to succeed.
async fn login_loopback(state_dir: &Path) -> Result<Option<LoginOutcome>> {
    // Bind an ephemeral loopback port up front so the exact redirect URI is
    // known before building the authorization URL.
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("bind loopback callback listener")?;
    let port = listener
        .local_addr()
        .context("read loopback listener address")?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let client = oauth_client()?
        .set_redirect_uri(RedirectUrl::new(redirect).context("invalid loopback redirect")?);

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes())
        .set_pkce_challenge(challenge)
        .url();

    println!("Opening your browser to sign in...");
    println!("If it doesn't open automatically, visit:\n{auth_url}");
    open_browser(auth_url.as_str());
    println!("Waiting for the browser to complete sign-in...");

    // Block on the redirect off the async runtime; the listener is moved into
    // the blocking task and dropped there so the port is released on return.
    let callback =
        tokio::task::spawn_blocking(move || wait_for_callback(&listener, LOOPBACK_TIMEOUT))
            .await
            .context("loopback listener task panicked")??;
    let Some(callback) = callback else {
        return Ok(None);
    };
    let (code, state) = match callback {
        Callback::Code { code, state } => (code, state),
        Callback::Error(error) => {
            return match error.as_str() {
                "access_denied" => Ok(Some(LoginOutcome::Denied)),
                other => bail!("authorization failed at the sign-in page: {other}"),
            };
        }
    };
    if state != *csrf.secret() {
        bail!("login failed: authorization state mismatch (possible CSRF); please try again");
    }

    let http = oauth_http_client()?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .context("could not exchange the authorization code for a token")?;
    let path = credentials_from_token(&token).store_in(state_dir)?;
    println!("Logged in. Credentials saved to {}.", path.display());
    Ok(Some(LoginOutcome::LoggedIn))
}

/// The outcome of a single loopback redirect request.
enum Callback {
    /// The IdP redirected back with an authorization code and CSRF state.
    Code { code: String, state: String },
    /// The IdP redirected back with an OAuth `error` (e.g. `access_denied`).
    Error(String),
}

/// Accept one loopback connection (until `timeout`), parse the OAuth redirect,
/// send a small confirmation page to the browser, and return what it carried.
/// `Ok(None)` means the deadline passed with no redirect.
fn wait_for_callback(listener: &TcpListener, timeout: Duration) -> Result<Option<Callback>> {
    listener
        .set_nonblocking(true)
        .context("configure loopback listener")?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // On BSD-derived platforms (macOS) an accepted socket inherits
                // the listener's non-blocking flag (Linux clears it; POSIX
                // leaves it unspecified), so the redirect must be read in
                // blocking mode or the browser's bytes may not have arrived
                // yet. Blocking mode also makes the read timeout below apply.
                stream
                    .set_nonblocking(false)
                    .context("switch loopback connection to blocking mode")?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .context("set read timeout on loopback connection")?;
                let target = read_request_target(&mut stream)?;
                let callback = parse_callback(&target);
                let _ = write_callback_response(&mut stream, callback.is_some());
                if let Some(callback) = callback {
                    return Ok(Some(callback));
                }
                // A favicon or unrelated probe: keep waiting for the real redirect.
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(err).context("accept loopback connection"),
        }
    }
}

/// Read an HTTP request from `stream` and return its request target (the path
/// plus query string from the request line).
fn read_request_target(stream: &mut std::net::TcpStream) -> Result<String> {
    let mut buf = [0u8; 2048];
    let mut filled = 0;
    loop {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if buf[..filled].contains(&b'\n') || filled == buf.len() {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err).context("read loopback request"),
        }
    }
    let text = String::from_utf8_lossy(&buf[..filled]);
    let first_line = text.lines().next().unwrap_or_default();
    // "GET /callback?code=...&state=... HTTP/1.1"
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    Ok(parts.next().unwrap_or_default().to_string())
}

/// Parse an OAuth redirect target (`/callback?...`) into a [`Callback`], or
/// `None` if it is not the callback path / carries neither `code` nor `error`.
fn parse_callback(target: &str) -> Option<Callback> {
    let query = target.split_once('?').map(|(_, q)| q)?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string());
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => error = Some(value),
            _ => {}
        }
    }
    if let Some(error) = error {
        return Some(Callback::Error(error));
    }
    let code = code?;
    Some(Callback::Code {
        code,
        state: state.unwrap_or_default(),
    })
}

/// Send the browser a tiny HTML page so the user knows to return to the
/// terminal. Best-effort: a write failure does not fail the login.
fn write_callback_response(stream: &mut std::net::TcpStream, ok: bool) -> std::io::Result<()> {
    let (title, message) = if ok {
        (
            "Husk: signed in",
            "You're signed in. You can close this tab and return to the terminal.",
        )
    } else {
        (
            "Husk",
            "Waiting for sign-in to complete. You can close this tab.",
        )
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body style=\"font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;\
         text-align:center;color:#111\"><h1 style=\"font-size:1.25rem\">{title}</h1>\
         <p>{message}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// [`login`]'s device-authorization-grant path (RFC 8628). Used for headless
/// machines and as the fallback when the browser flow is unavailable.
async fn login_device(state_dir: &Path) -> Result<LoginOutcome> {
    let client = oauth_client()?;
    let http = oauth_http_client()?;

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scopes(scopes())
        .request_async(&http)
        .await
        .context("could not start the device-flow login")?;

    let code = format_user_code(details.user_code().secret());
    let uri = verification_uri(&details);
    println!("First, copy your one-time code: {code}");
    println!("Then approve this machine at: {uri}");
    open_browser(&uri);
    println!("Waiting for approval...");

    match client
        .exchange_device_access_token(&details)
        .request_async(&http, tokio::time::sleep, None)
        .await
    {
        Ok(token) => {
            let path = credentials_from_token(&token).store_in(state_dir)?;
            println!("Logged in. Credentials saved to {}.", path.display());
            Ok(LoginOutcome::LoggedIn)
        }
        Err(oauth2::RequestTokenError::ServerResponse(response)) => {
            use oauth2::DeviceCodeErrorResponseType as E;
            match response.error() {
                E::AccessDenied => Ok(LoginOutcome::Denied),
                E::ExpiredToken => Ok(LoginOutcome::Expired),
                other => bail!("device authorization failed: {other:?}"),
            }
        }
        Err(err) => Err(anyhow::Error::new(err).context("device-flow login failed")),
    }
}

/// Rotate the stored token pair when the access token expires within five
/// minutes. An `invalid_grant` from the refresh endpoint means the token was
/// revoked or expired server-side: local credentials are deleted and the
/// machine is logged out.
pub async fn refresh_if_needed() -> Result<SessionState> {
    let state_dir = &crate::paths::husk_home()?;
    let Some(credentials) = Credentials::load_from(state_dir)? else {
        return Ok(SessionState::NotLoggedIn);
    };
    if !credentials.expires_within(chrono::Duration::minutes(REFRESH_WINDOW_MINUTES)) {
        return Ok(SessionState::Active(credentials));
    }
    // Credentials without a refresh token (legacy static bearers) cannot be
    // rotated: use them until they expire, then the machine is logged out.
    if credentials.refresh_token.is_empty() {
        if credentials.expires_at > Utc::now() {
            return Ok(SessionState::Active(credentials));
        }
        Credentials::delete_in(state_dir)?;
        return Ok(SessionState::NotLoggedIn);
    }

    let client = oauth_client()?;
    let http = oauth_http_client()?;
    match client
        .exchange_refresh_token(&RefreshToken::new(credentials.refresh_token.clone()))
        .add_scopes(scopes())
        .request_async(&http)
        .await
    {
        Ok(token) => {
            // Zitadel may not return a new refresh token; keep the old one.
            let mut refreshed = credentials_from_token(&token);
            if refreshed.refresh_token.is_empty() {
                refreshed.refresh_token = credentials.refresh_token.clone();
            }
            refreshed.store_in(state_dir)?;
            Ok(SessionState::Active(refreshed))
        }
        Err(oauth2::RequestTokenError::ServerResponse(_)) => {
            // The refresh token was rejected (revoked/expired): log out.
            Credentials::delete_in(state_dir)?;
            Ok(SessionState::NotLoggedIn)
        }
        Err(err) => {
            // Offline / transport error: keep using the current token while valid.
            if credentials.expires_at > Utc::now() {
                Ok(SessionState::Active(credentials))
            } else {
                Err(anyhow::Error::new(err).context("could not refresh the husk session"))
            }
        }
    }
}

/// Log out: delete the local credentials. Returns `true` when credentials
/// existed. (Zitadel-issued device tokens are short-lived and expire on their
/// own; the refresh token is simply discarded.)
pub async fn logout() -> Result<bool> {
    let state_dir = &crate::paths::husk_home()?;
    let existed = Credentials::exists_in(state_dir)?;
    Credentials::delete_in(state_dir)?;
    Ok(existed)
}

/// Fetch the signed-in account from the backend. Returns `None` when this
/// machine has no usable credentials or the backend rejects them.
pub async fn whoami(base_url: &str, client: &Client) -> Result<Option<Account>> {
    let Some(token) = access_token().await? else {
        return Ok(None);
    };
    let response = client
        .get(api_url(base_url, "/api/v1/account"))
        .bearer_auth(&token)
        .send()
        .await
        .context("could not reach the husk backend")?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("account lookup failed: HTTP {}", response.status());
    }
    let account = response
        .json::<Account>()
        .await
        .context("invalid account response")?;
    Ok(Some(account))
}

/// The bearer token for authenticated backend calls: `HUSK_TOKEN` wins,
/// otherwise the stored credentials (refreshed when close to expiry).
/// `None` means this machine is logged out.
pub async fn access_token() -> Result<Option<String>> {
    if let Some(token) = env_token() {
        return Ok(Some(token));
    }
    match refresh_if_needed().await? {
        SessionState::Active(credentials) => Ok(Some(credentials.access_token)),
        SessionState::NotLoggedIn => Ok(None),
    }
}

/// The `HUSK_TOKEN` environment override, when set and non-blank.
pub fn env_token() -> Option<String> {
    std::env::var(TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Normalize a device-flow user code for display as `XXXX-XXXX`. Inputs that
/// are not eight alphanumeric characters are passed through trimmed.
pub fn format_user_code(code: &str) -> String {
    let canonical = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>();
    if canonical.len() == 8 {
        format!("{}-{}", &canonical[..4], &canonical[4..])
    } else {
        code.trim().to_string()
    }
}

/// The page the user opens to approve a device login: the complete URI (with
/// the code pre-filled) when the IdP provides it, else the bare one.
fn verification_uri(details: &StandardDeviceAuthorizationResponse) -> String {
    details
        .verification_uri_complete()
        .map(|uri| uri.secret().clone())
        .unwrap_or_else(|| details.verification_uri().to_string())
}

/// What the web UI needs to start a device-flow login: the code to show, the
/// URL to open, and the opaque `device_code` it polls with.
pub struct WebDeviceStart {
    pub user_code: String,
    pub verification_uri_complete: String,
    pub device_code: String,
    pub interval: u64,
    pub expires_in: u64,
}

/// The status of one web login poll. `Approved` means credentials were just
/// stored locally; the others are transient/terminal device-flow states.
pub enum WebPollStatus {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Approved,
}

/// Begin a device-authorization login for the web UI (mirrors the start of
/// [`login`], but returns the grant instead of driving the terminal).
pub async fn web_device_start() -> Result<WebDeviceStart> {
    let client = oauth_client()?;
    let http = oauth_http_client()?;
    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scopes(scopes())
        .request_async(&http)
        .await
        .context("could not start the device-flow login")?;
    Ok(WebDeviceStart {
        user_code: format_user_code(details.user_code().secret()),
        verification_uri_complete: verification_uri(&details),
        device_code: details.device_code().secret().clone(),
        interval: details.interval().as_secs(),
        expires_in: details.expires_in().as_secs(),
    })
}

/// Poll a web device-login once. On approval, store credentials in the default
/// state dir (the same `~/.husk/credentials.json` the CLI writes) and report
/// `Approved`; otherwise report the current device-flow status.
///
/// This is the one deliberately hand-rolled token request in this module: the
/// `oauth2` crate's `exchange_device_access_token` drives its own sleep loop
/// until the grant resolves, but the web UI needs exactly one poll per HTTP
/// request, so the RFC 8628 `device_code` grant is posted directly.
pub async fn web_device_poll(device_code: &str) -> Result<WebPollStatus> {
    let state_dir = &crate::paths::husk_home()?;
    let issuer = oidc_issuer();
    let client_id = oidc_client_id()?;
    let http = oauth_http_client()?;
    let response = http
        .post(format!("{issuer}/oauth/v2/token"))
        .form(&[
            ("grant_type", GRANT_TYPE_DEVICE_CODE),
            ("device_code", device_code),
            ("client_id", client_id.as_str()),
        ])
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        // Transient network hiccup: the UI keeps polling until the deadline.
        Err(_) => return Ok(WebPollStatus::Pending),
    };
    let status = response.status();
    if status.is_success() {
        let token: RawToken = response.json().await.context("invalid token response")?;
        credentials(token.access_token, token.refresh_token, token.expires_in)
            .store_in(state_dir)?;
        return Ok(WebPollStatus::Approved);
    }
    if status.is_server_error() {
        return Ok(WebPollStatus::Pending);
    }
    let error = response
        .json::<OauthError>()
        .await
        .map(|body| body.error)
        .unwrap_or_default();
    match error.as_str() {
        "authorization_pending" => Ok(WebPollStatus::Pending),
        "slow_down" => Ok(WebPollStatus::SlowDown),
        "access_denied" => Ok(WebPollStatus::Denied),
        "expired_token" => Ok(WebPollStatus::Expired),
        "" => bail!("device authorization failed: HTTP {status}"),
        other => bail!("device authorization failed: {other}"),
    }
}

/// A minimal OAuth token-endpoint response, used by the web single-poll path.
#[derive(Debug, Deserialize)]
struct RawToken {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct OauthError {
    #[serde(default)]
    error: String,
}

fn credentials_from_token(token: &oauth2::basic::BasicTokenResponse) -> Credentials {
    let expires_in = token
        .expires_in()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0);
    credentials(
        token.access_token().secret().clone(),
        token
            .refresh_token()
            .map(|t| t.secret().clone())
            .unwrap_or_default(),
        expires_in,
    )
}

/// The one place a token response's fields become stored [`Credentials`]:
/// `expires_in` (token-endpoint lifetime, seconds) becomes an absolute
/// `expires_at`. Shared by the oauth2-crate flows and the web single-poll
/// path so the conversion cannot drift.
fn credentials(access_token: String, refresh_token: String, expires_in: i64) -> Credentials {
    Credentials {
        access_token,
        refresh_token,
        expires_at: Utc::now() + chrono::Duration::seconds(expires_in.max(0)),
    }
}

/// Try to open the approval page in the system browser; failure is fine,
/// the URL is already printed.
fn open_browser(url: &str) {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(url);
        command
    } else {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    let _ = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_callback_extracts_code_and_state() {
        let Some(Callback::Code { code, state }) =
            parse_callback("/callback?code=abc123&state=xyz789")
        else {
            panic!("expected a code callback");
        };
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn parse_callback_url_decodes_values() {
        let Some(Callback::Code { code, state }) =
            parse_callback("/callback?state=a%2Fb%2Bc&code=tok%20en")
        else {
            panic!("expected a code callback");
        };
        assert_eq!(code, "tok en");
        assert_eq!(state, "a/b+c");
    }

    #[test]
    fn parse_callback_surfaces_oauth_error() {
        let Some(Callback::Error(error)) =
            parse_callback("/callback?error=access_denied&error_description=nope")
        else {
            panic!("expected an error callback");
        };
        assert_eq!(error, "access_denied");
    }

    #[test]
    fn parse_callback_ignores_non_callback_requests() {
        assert!(parse_callback("/favicon.ico").is_none());
        assert!(parse_callback("/callback").is_none());
        assert!(parse_callback("/callback?foo=bar").is_none());
    }

    #[test]
    fn wait_for_callback_reads_a_slowly_arriving_redirect() {
        // On BSD platforms accepted sockets inherit the listener's
        // non-blocking flag; delivering the request in two delayed chunks
        // asserts the accepted stream reads in blocking mode until the
        // request line is complete.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");

        let writer = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect to listener");
            stream
                .write_all(b"GET /callback?code=abc123")
                .expect("write first chunk");
            stream.flush().expect("flush first chunk");
            std::thread::sleep(Duration::from_millis(200));
            stream
                .write_all(b"&state=xyz789 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .expect("write second chunk");
            // Keep the connection open long enough to receive the response.
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
        });

        let callback = wait_for_callback(&listener, Duration::from_secs(10))
            .expect("callback read succeeds")
            .expect("redirect arrives before the deadline");
        writer.join().expect("writer thread");

        let Callback::Code { code, state } = callback else {
            panic!("expected a code callback");
        };
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }
}
