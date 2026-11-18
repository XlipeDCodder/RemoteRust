//! Consent (blueprint v2 §7.3): screen requests go to the Agent's window
//! (see [`crate::ui`]) or, in console mode, to a prompt in the terminal.
//!
//! On the console, a Viewer that asks for control can be given it (`y`),
//! held to viewing only (`v`) or denied (anything else). Only the local
//! user can answer: answers are read from this process's own standard
//! input, and anything typed *before* a request appears is discarded, so a
//! stray "y" cannot accept a later request. Typing `stop` at any other time
//! is the console's kill switch.

use std::io::BufRead as _;
use std::sync::Arc;

use rr_net::{CONSENT_TIMEOUT, Grant, SessionRequest};
use rr_platform::capture;
use rr_proto::{BoundedString, MonitorInfo, Permissions};
use tokio::sync::mpsc;

use crate::hub::{Hub, Via};
use crate::media;

/// What to type in the terminal to stop sharing.
const STOP_COMMAND: &str = "stop";

/// Hands session requests to the window, or asks on the console when
/// there is none, one at a time until the channel closes. Between
/// requests, `stop` on the console ends every session.
pub async fn run(mut requests: mpsc::Receiver<SessionRequest>, hub: Arc<Hub>) {
    let mut lines = spawn_stdin_reader();
    // Standard input is still open.
    let mut console_open = true;
    loop {
        let mut request = tokio::select! {
            request = requests.recv() => match request {
                Some(request) => request,
                None => return,
            },
            line = lines.recv(), if console_open => {
                match line {
                    Some(line) if clean(&line).eq_ignore_ascii_case(STOP_COMMAND) => {
                        hub.kill(Via::Console);
                        println!("  Stopped sharing.");
                    }
                    Some(_) => {}
                    None => console_open = false,
                }
                continue;
            }
        };
        if !hub.console() {
            hub.offer(request, CONSENT_TIMEOUT);
            continue;
        }
        // Discard input typed before the prompt.
        while lines.try_recv().is_ok() {}
        println!();
        println!(
            "\"{}\" (fingerprint {}) asks to {} this screen.",
            request.viewer_name(),
            request.fingerprint(),
            describe(request.permissions())
        );
        let wants_control = request.permissions().contains(Permissions::CONTROL);
        if wants_control {
            println!(
                "  Type y to allow viewing and control, v to allow viewing only, anything else \
                 to deny (denied automatically in {} s): ",
                CONSENT_TIMEOUT.as_secs()
            );
        } else {
            println!(
                "  Accept? Type y and Enter (denied automatically in {} s): ",
                CONSENT_TIMEOUT.as_secs()
            );
        }
        let answer = tokio::select! {
            line = lines.recv() => line,
            () = request.withdrawn() => {
                println!("  The request expired or the viewer left.");
                continue;
            }
        };
        let Some(answer) = answer else {
            println!("  No console input available: denied.");
            request.deny();
            continue;
        };
        let Some(permissions) = granted(&answer, request.permissions()) else {
            println!("  Denied.");
            request.deny();
            continue;
        };
        accept(request, permissions, Arc::clone(&hub)).await;
    }
}

/// What an answer grants, given what was asked; `None` denies.
fn granted(answer: &str, requested: Permissions) -> Option<Permissions> {
    match clean(answer).to_ascii_lowercase().as_str() {
        "y" | "yes" => grant(requested, true),
        "v" | "view" => grant(requested, false),
        _ => None,
    }
}

/// A console line without surrounding blanks or a byte-order mark (which
/// some programs write before the first line they pipe in).
fn clean(line: &str) -> &str {
    line.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// What accepting grants: viewing, and control if it was asked for and
/// `control` allows it. Only viewing and control exist so far, so nothing
/// else is ever granted; `None` if viewing was not asked for.
pub fn grant(requested: Permissions, control: bool) -> Option<Permissions> {
    let allowed = if control {
        Permissions::VIEW.union(Permissions::CONTROL)
    } else {
        Permissions::VIEW
    };
    Some(requested.intersection(allowed)).filter(|granted| granted.contains(Permissions::VIEW))
}

/// Accepts with `permissions` on the primary monitor and starts the media
/// pipeline (and, with control, input).
pub async fn accept(request: SessionRequest, permissions: Permissions, hub: Arc<Hub>) {
    let fingerprint = request.fingerprint().to_string();
    let monitors = match tokio::task::spawn_blocking(capture::monitors).await {
        Ok(Ok(monitors)) if !monitors.is_empty() => monitors,
        Ok(Ok(_)) => {
            tracing::error!("no monitor to capture");
            request.deny();
            return;
        }
        Ok(Err(err)) => {
            tracing::error!(error = %err, "cannot list monitors");
            request.deny();
            return;
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot list monitors");
            request.deny();
            return;
        }
    };
    let monitor = monitors
        .iter()
        .find(|monitor| monitor.primary)
        .or_else(|| monitors.first())
        .map_or(0, |monitor| monitor.id);
    let grant = Grant {
        permissions,
        monitors: monitors.iter().map(monitor_info).collect(),
        monitor,
        encoder: rr_media::OpenH264Encoder::NAME.to_owned(),
    };
    match request.accept(grant).await {
        Ok(session) => {
            let control = session.permissions().contains(Permissions::CONTROL);
            let stop = hub.hotkey().map_or_else(
                || format!("type {STOP_COMMAND} and Enter to stop sharing"),
                |hotkey| format!("{hotkey}, or {STOP_COMMAND} and Enter, stops sharing"),
            );
            if control {
                println!("  Accepted: sharing this screen with remote control ({stop}).");
            } else {
                println!("  Accepted: sharing this screen, view only ({stop}).");
            }
            if capture::picks_in_dialog() {
                if control {
                    println!("  Pick the screen to share and allow control in the system dialog.");
                } else {
                    println!("  Pick the screen to share in the system dialog.");
                }
            }
            tokio::spawn(media::run_session(session, monitor, hub, fingerprint));
        }
        Err(err) => println!("  Could not start the session: {err}"),
    }
}

fn monitor_info(monitor: &capture::Monitor) -> MonitorInfo {
    MonitorInfo {
        id: monitor.id,
        name: BoundedString::truncating(&monitor.name),
        width: u16::try_from(monitor.width).unwrap_or(u16::MAX),
        height: u16::try_from(monitor.height).unwrap_or(u16::MAX),
        primary: monitor.primary,
    }
}

fn describe(permissions: Permissions) -> String {
    if permissions.contains(Permissions::CONTROL) {
        format!("see and control ({permissions})")
    } else {
        format!("see ({permissions})")
    }
}

/// Forwards console lines; the channel closes when standard input does.
fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    let spawned = std::thread::Builder::new()
        .name("rr-stdin".to_owned())
        .spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
    if let Err(err) = spawned {
        tracing::error!(error = %err, "cannot read the console; every request will be denied");
    }
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: Permissions = Permissions::VIEW.union(Permissions::CONTROL);

    #[test]
    fn answers_grant_what_was_asked_or_less() {
        assert_eq!(granted("y", BOTH), Some(BOTH));
        assert_eq!(granted(" YES ", BOTH), Some(BOTH));
        assert_eq!(granted("v", BOTH), Some(Permissions::VIEW));
        assert_eq!(granted("y", Permissions::VIEW), Some(Permissions::VIEW));
        assert_eq!(granted("n", BOTH), None);
        assert_eq!(granted("", BOTH), None);
        assert_eq!(granted("yy", BOTH), None);
        assert_eq!(granted("\u{feff}y\r", BOTH), Some(BOTH));
        // Control alone, without viewing, is never granted.
        assert_eq!(granted("y", Permissions::CONTROL), None);
    }

    #[test]
    fn the_dialog_grants_control_only_when_asked_and_allowed() {
        assert_eq!(grant(BOTH, true), Some(BOTH));
        assert_eq!(grant(BOTH, false), Some(Permissions::VIEW));
        assert_eq!(grant(Permissions::VIEW, true), Some(Permissions::VIEW));
        assert_eq!(grant(Permissions::CONTROL, true), None);
    }
}
