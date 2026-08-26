//! The optional cloud/account command bodies: `husk login`, `logout`,
//! `account`, `sync`, `alerts`, and `telemetry`, plus the shared backend
//! context (base URL + HTTP client) and the best-effort open-alerts summary
//! that `husk status` surfaces. Everything here is opt-in; husk works fully
//! offline with no account.

use super::{AlertsArgs, FeedbackArgs, TelemetryAction, TelemetryArgs};
use crate::cloud;
use crate::cloud::sync::AlertStateFilter;
use crate::term::{color, severity_ansi};
use anyhow::Result;

/// Backend base URL (env > `~/.husk/config.json` > default) plus the shared
/// short-timeout HTTP client used by every cloud command.
fn backend_context() -> Result<(String, reqwest::Client)> {
    let config = cloud::HuskCloudConfig::load().unwrap_or_default();
    Ok((cloud::effective_backend_url(&config), cloud::http_client()?))
}

pub(super) async fn run_login() -> Result<()> {
    if !cloud::LOGIN_AVAILABLE {
        println!("Account sign-in is coming soon.");
        return Ok(());
    }

    let (base_url, client) = backend_context()?;

    println!("Logging in via {}", cloud::auth::oidc_issuer_display());
    match cloud::auth::login().await? {
        cloud::auth::LoginOutcome::LoggedIn => {
            if let Ok(Some(account)) = cloud::auth::whoami(&base_url, &client).await {
                announce_login(&account);
            }
            Ok(())
        }
        cloud::auth::LoginOutcome::Denied => {
            anyhow::bail!("the login request was denied at the verification page")
        }
        cloud::auth::LoginOutcome::Expired => {
            anyhow::bail!("the one-time code expired before approval; run `husk login` again")
        }
    }
}

fn announce_login(account: &cloud::auth::Account) {
    println!("Signed in as {} ({} tier).", account.email, account.tier);
}

pub(super) async fn run_logout() -> Result<()> {
    let env_token_active = cloud::auth::env_token().is_some();
    match (cloud::auth::logout().await?, env_token_active) {
        (true, true) => println!(
            "Stored credentials deleted. HUSK_TOKEN is still active; unset it to end that session."
        ),
        (true, false) => println!("Logged out. Stored credentials deleted."),
        (false, true) => {
            println!("No stored credentials. HUSK_TOKEN is active; unset it to end that session.")
        }
        (false, false) => println!("No stored credentials; nothing to do."),
    }
    Ok(())
}

pub(super) async fn run_account() -> Result<()> {
    let (base_url, client) = backend_context()?;
    println!("backend:   {base_url}");

    match cloud::auth::whoami(&base_url, &client).await {
        Ok(Some(account)) => {
            let verified = if account.email_verified {
                ""
            } else {
                ", email unverified"
            };
            println!(
                "account:   {} ({} tier{verified})",
                account.email, account.tier
            );
            if let Some(name) = account.display_name {
                println!("name:      {name}");
            }
        }
        Ok(None) => println!("account:   not logged in (account sign-in is coming soon)"),
        Err(err) => println!("account:   unavailable ({err:#})"),
    }

    let machine_id = crate::paths::husk_home()
        .ok()
        .and_then(|home| cloud::sync::read_cached_machine_id(&home));
    match machine_id {
        Some(id) => println!("machine:   linked as {id}"),
        None => println!("machine:   not linked"),
    }

    let telemetry = cloud::telemetry::Telemetry::from_default_dir()?;
    let state = match telemetry.consent() {
        cloud::TelemetryConsent::Unset => "off (default)",
        cloud::TelemetryConsent::Disabled => "off",
        cloud::TelemetryConsent::Enabled if cloud::telemetry::env_allows_telemetry() => "on",
        cloud::TelemetryConsent::Enabled => "on, but suppressed by environment",
    };
    println!("telemetry: {state}");
    Ok(())
}

pub(super) async fn run_sync() -> Result<()> {
    let (base_url, client) = backend_context()?;
    let Some(token) = cloud::auth::access_token().await? else {
        anyhow::bail!("not logged in; account sign-in is coming soon");
    };

    // Retroactive alerts cover what the last scan actually saw, so upload the
    // cached report's full inventory, not a fresh cwd-only discovery, which
    // would silently under-cover the machine.
    let Some(report) = crate::cache::load_any_latest_report()? else {
        anyhow::bail!(
            "no cached scan to sync; run `husk scan --home` first so the upload covers this machine"
        );
    };
    let packages = report.packages;
    let roots = report
        .roots
        .iter()
        .map(|root| root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Syncing the last scan's inventory ({roots}, scanned {})",
        report.generated_at.format("%Y-%m-%d %H:%M UTC")
    );
    println!(
        "Uploading {} package version(s) to {base_url}",
        packages.len()
    );

    let report = cloud::sync::sync_inventory(&base_url, &client, &token, &packages).await?;
    println!(
        "Synced {} package(s) for machine {}.",
        report.uploaded, report.machine_id
    );
    if report.new_alerts > 0 {
        println!(
            "{} new alert(s) from intel matching. Run `husk alerts` to view them.",
            report.new_alerts
        );
    } else {
        println!("No new alerts.");
    }
    Ok(())
}

/// Best-effort summary of open retroactive alerts for `husk status`.
///
/// Silent when not logged in or when the backend is unreachable: a status
/// command must work fully offline, so any error here is swallowed and only a
/// successful fetch prints anything.
pub(super) async fn surface_open_alerts() {
    // Don't even build a client unless the user has linked an account.
    if cloud::auth::env_token().is_none() && !matches!(cloud::Credentials::load(), Ok(Some(_))) {
        return;
    }
    let Ok((base_url, client)) = backend_context() else {
        return;
    };
    let Ok(Some(token)) = cloud::auth::access_token().await else {
        return;
    };
    let Ok(alerts) =
        cloud::sync::fetch_alerts(&base_url, &client, &token, AlertStateFilter::Open).await
    else {
        return;
    };

    println!();
    if alerts.is_empty() {
        println!("{} no open retroactive alerts", color("alerts", "32;1"));
        return;
    }
    println!(
        "{} {} open retroactive alert(s). Run `husk alerts` for detail",
        color("alerts", "31;1"),
        alerts.len()
    );
    for alert in alerts.iter().take(5) {
        let severity = alert.severity_level();
        println!(
            "  {} {} {}@{} ({})",
            color(format!("{:8}", severity.label()), severity_ansi(severity)),
            alert.verdict,
            alert.name,
            alert.version,
            alert.ecosystem
        );
    }
    if alerts.len() > 5 {
        println!("  ... {} more", alerts.len() - 5);
    }
}

pub(super) async fn run_alerts(args: AlertsArgs) -> Result<()> {
    let (base_url, client) = backend_context()?;
    let Some(token) = cloud::auth::access_token().await? else {
        anyhow::bail!("not logged in; account sign-in is coming soon");
    };

    let filter = if args.all {
        AlertStateFilter::All
    } else {
        AlertStateFilter::Open
    };
    let alerts = cloud::sync::fetch_alerts(&base_url, &client, &token, filter).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&alerts)?);
        return Ok(());
    }
    if alerts.is_empty() {
        if args.all {
            println!("No alerts.");
        } else {
            println!("No open alerts.");
        }
        return Ok(());
    }

    println!("{} {} alert(s):", alerts.len(), filter);
    for alert in &alerts {
        let severity = alert.severity_level();
        let machine = if alert.machine_name.is_empty() {
            alert.machine_id.as_str()
        } else {
            alert.machine_name.as_str()
        };
        println!(
            "  {} {:9} {:12} {} {}@{}",
            color(format!("{:8}", severity.label()), severity_ansi(severity)),
            alert.state,
            alert.verdict,
            alert.ecosystem,
            alert.name,
            alert.version
        );
        println!(
            "           machine {machine}  first seen {}",
            alert.first_seen_at.format("%Y-%m-%d %H:%M UTC")
        );
        if !alert.summary.trim().is_empty() {
            println!("           {}", alert.summary);
        }
    }
    Ok(())
}

/// One line naming the resolved report-upload endpoint, and where the base
/// URL came from when it is not the built-in default, so a dev build pointed
/// at another backend is visible at a glance.
fn print_telemetry_endpoint() {
    let config = cloud::HuskCloudConfig::load().unwrap_or_default();
    let base_url = cloud::effective_backend_url(&config);
    let source =
        if std::env::var(cloud::BACKEND_URL_ENV).is_ok_and(|value| !value.trim().is_empty()) {
            " (from HUSK_BACKEND_URL)"
        } else if config
            .backend_url
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            " (from config backend_url)"
        } else {
            ""
        };
    println!(
        "endpoint: {}{source}",
        cloud::telemetry::reports_url(&base_url)
    );
}

/// `husk feedback [MESSAGE] [--contact EMAIL]`: send free-text feedback to
/// the husk developers. No account needed; only the message, the optional
/// reply email, and the husk version are sent.
pub(super) async fn run_feedback(args: FeedbackArgs) -> Result<()> {
    let raw = match args.message {
        Some(message) => message,
        None => {
            use std::io::{IsTerminal, Read};
            let mut stdin = std::io::stdin();
            if stdin.is_terminal() {
                eprintln!("Reading feedback from stdin. Finish with Ctrl-D.");
            }
            let mut buffer = String::new();
            stdin.read_to_string(&mut buffer)?;
            buffer
        }
    };
    let message = cloud::feedback::clean_message(&raw)?;
    let contact = cloud::feedback::clean_contact(args.contact.as_deref());

    cloud::feedback::send(&message, contact.as_deref(), "cli").await?;
    println!("Feedback sent. Thanks!");
    Ok(())
}

pub(super) fn run_telemetry(args: TelemetryArgs) -> Result<()> {
    let telemetry = cloud::telemetry::Telemetry::from_default_dir()?;
    match args
        .action
        .unwrap_or(TelemetryAction::Status(super::TelemetryStatusArgs {
            payload: false,
        })) {
        TelemetryAction::On => {
            telemetry.enable()?;
            println!(
                "Telemetry is on: one anonymous summary per completed day, bucketed \
counters only, no identifier."
            );
            println!("Inspect exactly what would be sent with `husk telemetry status --payload`.");
            if !cloud::telemetry::env_allows_telemetry() {
                println!(
                    "Note: DO_NOT_TRACK, HUSK_TELEMETRY_DISABLED, or CI currently suppresses it."
                );
            }
        }
        TelemetryAction::Off => {
            telemetry.disable()?;
            println!("Telemetry is off. All local telemetry state was deleted.");
        }
        TelemetryAction::Status(status) => {
            if status.payload {
                print!("{}", telemetry.payload()?);
                return Ok(());
            }
            print_telemetry_endpoint();
            match telemetry.consent() {
                cloud::TelemetryConsent::Enabled => {
                    println!("telemetry: on");
                    if !cloud::telemetry::env_allows_telemetry() {
                        println!(
                            "suppressed by environment (DO_NOT_TRACK, HUSK_TELEMETRY_DISABLED, or CI)"
                        );
                    }
                    if let Some(day) = telemetry.install_day() {
                        println!("install day: {day}");
                    }
                    println!("pending reports: {}", telemetry.pending_count());
                }
                consent => {
                    let state = if consent.is_unset() { " (default)" } else { "" };
                    println!("telemetry: off{state}");
                    println!("Nothing is ever recorded or sent. Opt in with `husk telemetry on`.");
                }
            }
        }
    }
    Ok(())
}
