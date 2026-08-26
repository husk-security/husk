//! Send free-text product feedback to the Husk backend.
//!
//! One anonymous POST shared by the CLI (`husk feedback`), the local web UI,
//! and the MCP tool. The backend stores only what is sent here: the message,
//! an optional reply email, which surface it came from, and the husk version.
//! No account, no identifier, no file contents.

use anyhow::{Context, Result, bail};
use serde_json::json;

/// Longest accepted message, in characters after trimming. Mirrors the
/// backend's own limit so an over-long message fails before the network.
pub const MAX_MESSAGE_CHARS: usize = 4096;

/// Backend intake route (`husk_platform`: `backend/src/feedback.rs`).
const FEEDBACK_PATH: &str = "/api/v1/feedback";

/// Normalize and bound a raw message: CRLF becomes LF, surrounding whitespace
/// is trimmed, and the result must be non-empty and within
/// [`MAX_MESSAGE_CHARS`]. The backend rejects control characters beyond
/// newline/tab, so surfacing that rule here keeps the error local and clear.
pub fn clean_message(raw: &str) -> Result<String> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let message = normalized.trim();
    if message.is_empty() {
        bail!("feedback message is empty");
    }
    if message.chars().count() > MAX_MESSAGE_CHARS {
        bail!("feedback message is too long (max {MAX_MESSAGE_CHARS} characters)");
    }
    if let Some(c) = message
        .chars()
        .find(|c| c.is_control() && *c != '\n' && *c != '\t')
    {
        bail!("feedback message contains a control character ({c:?}); remove it and try again");
    }
    Ok(message.to_string())
}

/// A trimmed, non-empty contact value, or `None` when blank/absent.
pub fn clean_contact(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The exact JSON body the backend intake accepts.
fn payload(message: &str, contact: Option<&str>, context: &str) -> serde_json::Value {
    let mut body = json!({
        "message": message,
        "context": context,
        "husk_version": env!("CARGO_PKG_VERSION"),
    });
    if let Some(contact) = contact {
        body["contact"] = json!(contact);
    }
    body
}

/// Send one feedback submission to the resolved backend
/// (`HUSK_BACKEND_URL` beats the config file, which beats the default).
/// `context` names the surface it came from: `web`, `mcp`, or `cli`.
pub async fn send(message: &str, contact: Option<&str>, context: &str) -> Result<()> {
    let config = super::HuskCloudConfig::load().unwrap_or_default();
    let backend_url = super::effective_backend_url(&config);
    let client = super::http_client()?;
    send_to(&backend_url, &client, message, contact, context).await
}

/// [`send`] against an explicit backend URL (the resolution-free half, so
/// tests can point it at a local stub).
pub async fn send_to(
    backend_url: &str,
    client: &reqwest::Client,
    message: &str,
    contact: Option<&str>,
    context: &str,
) -> Result<()> {
    let url = super::api_url(backend_url, FEEDBACK_PATH);
    let response = client
        .post(&url)
        .json(&payload(message, contact, context))
        .send()
        .await
        .with_context(|| format!("could not reach the Husk backend at {backend_url}"))?;
    let status = response.status();
    if !status.is_success() {
        // The backend's validation errors carry {"error": {"message": ...}} or
        // {"message": ...}; surface whichever is present without echoing the
        // whole body.
        let detail = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| {
                body.pointer("/error/message")
                    .or_else(|| body.get("message"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        if detail.is_empty() {
            bail!("the Husk backend rejected the feedback ({status})");
        }
        bail!("the Husk backend rejected the feedback ({status}): {detail}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_message_normalizes_and_bounds() {
        assert_eq!(
            clean_message("  a line\r\nand\tanother\r  ").unwrap(),
            "a line\nand\tanother"
        );
        assert!(clean_message("").is_err());
        assert!(clean_message("   \n  ").is_err());
        assert!(clean_message(&"x".repeat(MAX_MESSAGE_CHARS)).is_ok());
        assert!(clean_message(&"x".repeat(MAX_MESSAGE_CHARS + 1)).is_err());
        assert!(clean_message("null\u{0}byte").is_err());
    }

    #[test]
    fn clean_contact_drops_blank_values() {
        assert_eq!(clean_contact(None), None);
        assert_eq!(clean_contact(Some("   ")), None);
        assert_eq!(
            clean_contact(Some(" dev@example.com ")).as_deref(),
            Some("dev@example.com")
        );
    }

    #[test]
    fn payload_carries_the_surface_and_version_and_optional_contact() {
        let body = payload("hi", None, "cli");
        assert_eq!(body["message"], "hi");
        assert_eq!(body["context"], "cli");
        assert_eq!(body["husk_version"], env!("CARGO_PKG_VERSION"));
        assert!(body.get("contact").is_none());

        let body = payload("hi", Some("dev@example.com"), "web");
        assert_eq!(body["contact"], "dev@example.com");
    }

    /// One-shot HTTP stub: accepts a single connection, answers with the given
    /// status line + body, and reports the request head it saw.
    async fn stub_backend(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut seen = vec![0u8; 8192];
            let n = socket.read(&mut seen).await.expect("read request");
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            String::from_utf8_lossy(&seen[..n]).into_owned()
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn send_to_posts_the_intake_route_and_accepts_a_202() {
        let (url, request) = stub_backend(
            "HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\ncontent-length: 17\r\nconnection: close\r\n\r\n{\"received\":true}",
        )
        .await;
        let client = crate::cloud::http_client().expect("client");
        send_to(&url, &client, "great tool", Some("dev@example.com"), "cli")
            .await
            .expect("send");
        let seen = request.await.expect("stub task");
        assert!(seen.starts_with("POST /api/v1/feedback HTTP/1.1"), "{seen}");
        assert!(seen.contains("\"context\":\"cli\""), "{seen}");
        assert!(seen.contains("\"contact\":\"dev@example.com\""), "{seen}");
    }

    #[tokio::test]
    async fn send_to_surfaces_a_backend_rejection() {
        let (url, _request) = stub_backend(
            "HTTP/1.1 422 Unprocessable Entity\r\ncontent-type: application/json\r\ncontent-length: 51\r\nconnection: close\r\n\r\n{\"code\":\"validation\",\"message\":\"invalid feedback\"}\n",
        )
        .await;
        let client = crate::cloud::http_client().expect("client");
        let err = send_to(&url, &client, "hi", None, "web")
            .await
            .expect_err("rejection");
        let text = format!("{err:#}");
        assert!(text.contains("rejected the feedback"), "{text}");
        assert!(text.contains("invalid feedback"), "{text}");
    }

    #[tokio::test]
    async fn send_to_reports_an_unreachable_backend() {
        let client = crate::cloud::http_client().expect("client");
        let err = send_to("http://127.0.0.1:9", &client, "hi", None, "mcp")
            .await
            .expect_err("unreachable");
        assert!(
            format!("{err:#}").contains("could not reach the Husk backend"),
            "{err:#}"
        );
    }
}
