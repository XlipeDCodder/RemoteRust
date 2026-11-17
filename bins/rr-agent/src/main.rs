//! RustRemote Agent: runs on the machine being accessed (blueprint v2 §4.1).
//!
//! Unprivileged process: network endpoint, protocol parsing, capture,
//! encoding, input injection (attended mode), tray icon and consent dialog.
//!
//! M3 build: listeners, pairing, the consent prompt (in the terminal),
//! screen sharing (software H.264), remote keyboard and mouse, and the
//! pointer sent apart from the video. The graphical consent dialog,
//! indicator and kill switch arrive in M4.
#![forbid(unsafe_code)]

mod consent;
mod cursor;
mod input;
mod media;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use rr_config::{Config, TrustStore};
use rr_net::{
    Agent, AgentOptions, CONSENT_TIMEOUT, CodePolicy, DeviceIdentity, PairingCodes, SessionCode,
    plan_listeners,
};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Parser)]
#[command(
    name = "rr-agent",
    version,
    about = "RustRemote Agent: lets paired Viewers reach this machine."
)]
struct Cli {
    /// Keep configuration, identity and paired devices in this folder
    /// instead of the per-user default (for example to run a second
    /// device on one machine).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Listen for Viewers (the default when no command is given).
    Run(RunArgs),
    /// Show network interfaces, their class and where the Agent would listen.
    Interfaces,
    /// Show this device's key and fingerprint (creates them on first use).
    Identity,
    /// List the Viewers paired with this Agent.
    Viewers,
    /// Unpair a Viewer, by name or key prefix (8+ hex characters).
    Forget {
        /// Viewer name or key prefix.
        viewer: String,
    },
}

#[derive(Debug, Default, Args)]
struct RunArgs {
    /// UDP port to listen on (overrides `agent.listen_port`).
    #[arg(long)]
    port: Option<u16>,
    /// Refuse pairing: only already paired Viewers can connect, and unknown
    /// keys are rejected during the TLS handshake.
    #[arg(long)]
    no_pairing: bool,
    /// Also listen on 127.0.0.1, to test with a Viewer on this machine.
    #[arg(long)]
    listen_loopback: bool,
}

struct Paths {
    config: PathBuf,
    identity: PathBuf,
    trust: PathBuf,
}

impl Paths {
    /// Default per-user locations, or everything inside `data_dir`.
    fn resolve(data_dir: Option<PathBuf>) -> anyhow::Result<Self> {
        if let Some(dir) = data_dir {
            return Ok(Self {
                config: dir.join(rr_config::CONFIG_FILE_NAME),
                identity: dir.join(rr_net::identity::IDENTITY_FILE_NAME),
                trust: dir.join(rr_config::TRUST_FILE_NAME),
            });
        }
        let missing = "cannot determine the per-user data directory";
        Ok(Self {
            config: rr_config::default_config_path().context(missing)?,
            identity: rr_net::default_identity_path().context(missing)?,
            trust: rr_config::default_trust_path().context(missing)?,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rr_telemetry::init()?;
    let cli = Cli::parse();
    let paths = Paths::resolve(cli.data_dir)?;
    let config = rr_config::load_or_default(&paths.config)
        .with_context(|| format!("cannot load {}", paths.config.display()))?;

    match cli.command {
        None => run(&paths, config, RunArgs::default()).await,
        Some(Command::Run(args)) => run(&paths, config, args).await,
        Some(Command::Interfaces) => {
            show_interfaces(&config);
            Ok(())
        }
        Some(Command::Identity) => show_identity(&paths, &config),
        Some(Command::Viewers) => list_viewers(&paths),
        Some(Command::Forget { viewer }) => forget(&paths, &viewer),
    }
}

async fn run(paths: &Paths, mut config: Config, args: RunArgs) -> anyhow::Result<()> {
    if let Some(port) = args.port {
        config.agent.listen_port = port;
    }
    if args.no_pairing {
        config.agent.attended.pairing_enabled = false;
    }
    config.validate()?;

    let identity = load_identity(paths)?;
    let trust = load_trust(paths)?;
    let device_name = device_name(&config);
    println!("RustRemote Agent \"{device_name}\"");
    println!("  fingerprint: {}", identity.fingerprint());
    println!("  paired viewers: {}", trust.viewers.len());

    let pairing = if config.agent.attended.pairing_enabled {
        let codes = PairingCodes::new(CodePolicy::from_config(&config.agent.attended))?;
        tokio::spawn(Arc::clone(&codes).run_expiry());
        tokio::spawn(show_codes(
            codes.subscribe(),
            config.agent.attended.code_ttl_secs,
        ));
        Some(codes)
    } else {
        println!("  pairing: disabled");
        None
    };

    // Physical pixels for capture, input and pointer coordinates.
    if let Err(err) = rr_platform::capture::set_dpi_aware() {
        tracing::debug!(error = %err, "DPI awareness not changed");
    }
    let (sessions, requests) = mpsc::channel(1);
    tokio::spawn(consent::run(requests));

    let agent = Agent::new(
        identity,
        AgentOptions {
            device_name,
            pairing,
            trust_path: Some(paths.trust.clone()),
            sessions: Some(sessions),
            consent_timeout: CONSENT_TIMEOUT,
        },
        trust.viewers.iter().map(|viewer| viewer.key),
    )?;

    let extra = if args.listen_loopback {
        vec![rr_net::listen::loopback_target(config.agent.listen_port)]
    } else {
        Vec::new()
    };
    let (stop, stopped) = watch::channel(false);
    let listeners = tokio::spawn(rr_net::run_listeners(
        agent,
        config.agent.clone(),
        extra,
        stopped,
    ));

    tokio::signal::ctrl_c()
        .await
        .context("cannot wait for Ctrl+C")?;
    println!("Stopping...");
    stop.send_replace(true);
    listeners.await.context("listener task failed")?;
    Ok(())
}

/// Prints the session code whenever it changes. The code goes to stdout for
/// the local user only and is never logged.
async fn show_codes(mut codes: watch::Receiver<SessionCode>, ttl_secs: u16) {
    loop {
        let code = codes.borrow_and_update().clone();
        let text = code.expose();
        let (head, tail) = text.split_at_checked(3).unwrap_or((text, ""));
        let minutes = ttl_secs.div_ceil(60);
        println!("  session code: {head} {tail}  (single use, valid for {minutes} min)");
        if codes.changed().await.is_err() {
            return;
        }
    }
}

fn show_interfaces(config: &Config) {
    let interfaces = rr_net::discover();
    println!("Interfaces:");
    for iface in &interfaces {
        let class = iface.class.map_or("ignored", |class| class.as_str());
        let state = if iface.up { "up" } else { "down" };
        let addrs: Vec<String> = iface.addrs.iter().map(ToString::to_string).collect();
        println!(
            "  {:<28} {:<12} {:<5} {}",
            iface.label,
            class,
            state,
            addrs.join(", ")
        );
        if let Some(description) = &iface.description {
            println!("  {:<28} {description}", "");
        }
    }

    let plan = plan_listeners(&interfaces, &config.agent);
    println!("\nWould listen on:");
    if plan.targets.is_empty() {
        println!("  (nothing: no interface matches the policy in the configuration)");
    }
    for target in &plan.targets {
        let allowed: Vec<String> = target.allowed.iter().map(ToString::to_string).collect();
        println!(
            "  {:<28} {:<12} from {}",
            target.addr,
            target.class.as_str(),
            allowed.join(", ")
        );
    }
    for skipped in &plan.skipped {
        println!("  not {}: {}", skipped.what, skipped.reason);
    }
}

fn show_identity(paths: &Paths, config: &Config) -> anyhow::Result<()> {
    let identity = load_identity(paths)?;
    println!("name:        {}", device_name(config));
    println!("fingerprint: {}", identity.fingerprint());
    println!("public key:  {}", identity.public_key());
    println!("stored in:   {}", paths.identity.display());
    Ok(())
}

fn list_viewers(paths: &Paths) -> anyhow::Result<()> {
    let trust = load_trust(paths)?;
    if trust.viewers.is_empty() {
        println!("No paired viewers.");
    }
    for viewer in &trust.viewers {
        println!(
            "{:<24} {}  key {}",
            viewer.name,
            rr_net::Fingerprint::of(&viewer.key),
            viewer.key
        );
    }
    Ok(())
}

fn forget(paths: &Paths, query: &str) -> anyhow::Result<()> {
    let mut trust = load_trust(paths)?;
    let key = match trust.find_viewers(query).as_slice() {
        [] => bail!("no paired viewer matches {query:?}"),
        [viewer] => viewer.key,
        many => bail!(
            "{} viewers match {query:?}; use a longer key prefix",
            many.len()
        ),
    };
    trust.remove_viewer(&key);
    rr_config::save_trust(&paths.trust, &trust)?;
    println!("Forgot viewer {key}. Restart the Agent for this to take effect.");
    Ok(())
}

fn load_identity(paths: &Paths) -> anyhow::Result<DeviceIdentity> {
    DeviceIdentity::load_or_create(&paths.identity).with_context(|| {
        format!(
            "cannot load the device identity {}",
            paths.identity.display()
        )
    })
}

fn load_trust(paths: &Paths) -> anyhow::Result<TrustStore> {
    rr_config::load_trust_or_default(&paths.trust)
        .with_context(|| format!("cannot load {}", paths.trust.display()))
}

fn device_name(config: &Config) -> String {
    config.effective_device_name(rr_platform::host::hostname().as_deref())
}
