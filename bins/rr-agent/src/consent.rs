//! Consent prompt in the Agent's terminal (blueprint v2 §7.3). M2 asks on
//! the console; the graphical dialog, session indicator and kill switch
//! arrive together in M4.
//!
//! Only the local user can answer: answers are read from this process's
//! own standard input, and anything typed *before* a request appears is
//! discarded, so a stray "y" cannot accept a later request.

use std::io::BufRead as _;

use rr_net::{CONSENT_TIMEOUT, Grant, SessionRequest};
use rr_platform::capture;
use rr_proto::{BoundedString, MonitorInfo, Permissions};
use tokio::sync::mpsc;

use crate::media;

/// Answers session requests one at a time until the channel closes.
pub async fn run(mut requests: mpsc::Receiver<SessionRequest>) {
    let mut lines = spawn_stdin_reader();
    while let Some(mut request) = requests.recv().await {
        // Discard input typed before the prompt.
        while lines.try_recv().is_ok() {}
        println!();
        println!(
            "\"{}\" (fingerprint {}) asks to {} this screen.",
            request.viewer_name(),
            request.fingerprint(),
            describe(request.permissions())
        );
        println!(
            "  Accept? Type y and Enter (denied automatically in {} s): ",
            CONSENT_TIMEOUT.as_secs()
        );
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
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("  Denied.");
            request.deny();
            continue;
        }
        accept(request).await;
    }
}

/// Accepts with view-only access to the primary monitor and starts the
/// media pipeline.
async fn accept(request: SessionRequest) {
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
        // M2 streams the screen only; input control arrives in M3.
        permissions: Permissions::VIEW,
        monitors: monitors.iter().map(monitor_info).collect(),
        monitor,
        encoder: rr_media::OpenH264Encoder::NAME.to_owned(),
    };
    match request.accept(grant).await {
        Ok(session) => {
            println!("  Accepted: sharing this screen (Ctrl+C stops the Agent).");
            tokio::spawn(media::run_session(session, monitor));
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
