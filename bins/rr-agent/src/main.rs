//! RustRemote Agent: runs on the machine being accessed (blueprint v2 §4.1).
//!
//! Unprivileged process: network endpoint, protocol parsing, capture,
//! encoding, input injection (attended mode), tray icon and consent dialog.
//!
//! M4 build: listeners, pairing, screen sharing (software H.264), remote
//! keyboard and mouse, the pointer sent apart from the video, and the
//! transparency features: the consent dialog, the Agent window and tray
//! icon, the session border, the kill switch, the secure-desktop pause,
//! failed-attempt budgets and the audit log. `run --console` keeps the
//! terminal prompt (scripts, SSH sessions).
#![forbid(unsafe_code)]

mod consent;
mod cursor;
mod hub;
mod input;
mod media;
mod ui;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use rr_config::{Config, TrustStore};
use rr_net::{
    Agent, AgentOptions, CONSENT_TIMEOUT, CodePolicy, DeviceIdentity, LimitPolicy, PairingCodes,
    SessionCode, plan_listeners,
};
use rr_platform::input::InputError;
use rr_platform::killswitch::{Hotkey, KillSwitch};
use serde_json::json;
use tokio::sync::{mpsc, watch};

use crate::hub::{Hub, Via};

/// Network events waiting for the audit log and the window.
const EVENT_QUEUE: usize = 256;
/// Longest wait for the listeners to close when stopping.
const STOP_TIMEOUT: Duration = Duration::from_secs(3);

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
    /// No window or tray icon: requests are answered and the session code
    /// shown in the terminal (scripts, SSH sessions).
    #[arg(long)]
    console: bool,
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

    /// Where the audit log goes: next to the paired devices.
    fn audit_dir(&self) -> Option<&Path> {
        self.trust.parent()
    }
}

fn main() -> anyhow::Result<()> {
    rr_telemetry::init()?;
    let cli = Cli::parse();
    let paths = Paths::resolve(cli.data_dir)?;
    let config = rr_config::load_or_default(&paths.config)
        .with_context(|| format!("cannot load {}", paths.config.display()))?;

    match cli.command {
        None => run(&paths, config, RunArgs::default()),
        Some(Command::Run(args)) => run(&paths, config, args),
        Some(Command::Interfaces) => {
            show_interfaces(&config);
            Ok(())
        }
        Some(Command::Identity) => show_identity(&paths, &config),
        Some(Command::Viewers) => list_viewers(&paths),
        Some(Command::Forget { viewer }) => forget(&paths, &viewer),
    }
}

fn run(paths: &Paths, mut config: Config, args: RunArgs) -> anyhow::Result<()> {
    if let Some(port) = args.port {
        config.agent.listen_port = port;
    }
    if args.no_pairing {
        config.agent.attended.pairing_enabled = false;
    }
    config.validate()?;
    let hotkey: Hotkey = config.agent.kill_switch.hotkey.parse().map_err(|err| {
        anyhow!(
            "agent.kill_switch.hotkey {:?} in {}: {err}",
            config.agent.kill_switch.hotkey,
            paths.config.display()
        )
    })?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rr-agent")
        .build()
        .context("cannot start the async runtime")?;
    // The window system lives on this (the main) thread; the network side
    // runs on the runtime's threads.
    let event_loop = if args.console {
        None
    } else {
        match ui::event_loop() {
            Ok(event_loop) => Some(event_loop),
            Err(err) => {
                println!("No window system ({err:#}): using the terminal.");
                None
            }
        }
    };
    let core = runtime.block_on(start(paths, &config, &args, event_loop.is_none()))?;
    let hub = Arc::clone(&core.hub);
    let kill_switch = install_kill_switch(&hub, hotkey);

    if let Some(event_loop) = event_loop {
        runtime.spawn({
            let hub = Arc::clone(&hub);
            async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    hub.request_quit();
                }
            }
        });
        match ui::run(event_loop, Arc::clone(&hub)) {
            Ok(()) => {}
            Err(err) => {
                tracing::error!(error = format!("{err:#}"), "the Agent window failed");
                println!("The Agent window failed ({err:#}); using the terminal (Ctrl+C stops).");
                hub.use_console();
                wait_for_ctrl_c(&runtime, &hub)?;
            }
        }
    } else {
        wait_for_ctrl_c(&runtime, &hub)?;
    }

    println!("Stopping...");
    hub.shut_down();
    hub.audit("agent_stopped", json!({}));
    drop(kill_switch);
    core.stop.send_replace(true);
    // The timer must be created inside the runtime.
    let stopped =
        runtime.block_on(async { tokio::time::timeout(STOP_TIMEOUT, core.listeners).await });
    if stopped.is_err() {
        tracing::warn!("the listeners did not close in time");
    }
    runtime.shutdown_timeout(Duration::from_secs(1));
    hub.close_audit();
    Ok(())
}

/// Blocks until Ctrl+C (or a quit asked for elsewhere).
fn wait_for_ctrl_c(runtime: &tokio::runtime::Runtime, hub: &Hub) -> anyhow::Result<()> {
    if hub.quit_requested() {
        return Ok(());
    }
    runtime
        .block_on(tokio::signal::ctrl_c())
        .context("cannot wait for Ctrl+C")
}

/// What `run` keeps until the Agent stops.
struct Core {
    hub: Arc<Hub>,
    stop: watch::Sender<bool>,
    listeners: tokio::task::JoinHandle<()>,
}

/// Starts the network side: identity, pairing codes, the Agent, the
/// listeners and the tasks feeding the hub.
async fn start(
    paths: &Paths,
    config: &Config,
    args: &RunArgs,
    console: bool,
) -> anyhow::Result<Core> {
    let identity = load_identity(paths)?;
    let trust = load_trust(paths)?;
    let device_name = device_name(config);
    let fingerprint = identity.fingerprint().to_string();
    println!("RustRemote Agent \"{device_name}\"");
    println!("  fingerprint: {fingerprint}");
    println!("  paired viewers: {}", trust.viewers.len());

    let pairing = if config.agent.attended.pairing_enabled {
        let codes = PairingCodes::new(CodePolicy::from_config(&config.agent.attended))?;
        tokio::spawn(Arc::clone(&codes).run_expiry());
        Some(codes)
    } else {
        println!("  pairing: disabled");
        None
    };

    // Physical pixels for capture, input, the border and pointer
    // coordinates.
    if let Err(err) = rr_platform::capture::set_dpi_aware() {
        tracing::debug!(error = %err, "DPI awareness not changed");
    }
    let (sessions, requests) = mpsc::channel(1);
    let (events, mut events_rx) = mpsc::channel(EVENT_QUEUE);
    let agent = Agent::new(
        identity,
        AgentOptions {
            device_name: device_name.clone(),
            pairing: pairing.clone(),
            trust_path: Some(paths.trust.clone()),
            sessions: Some(sessions),
            consent_timeout: CONSENT_TIMEOUT,
            events: Some(events),
            limits: LimitPolicy::default(),
        },
        trust.viewers.iter().map(|viewer| viewer.key),
    )?;

    let hub = Hub::new(
        agent.clone(),
        tokio::runtime::Handle::current(),
        (device_name.clone(), fingerprint.clone()),
        Duration::from_secs(u64::from(config.agent.attended.code_ttl_secs)),
        paths.audit_dir(),
        console,
    );
    tokio::spawn({
        let hub = Arc::clone(&hub);
        async move {
            while let Some(event) = events_rx.recv().await {
                hub.on_event(&event);
            }
        }
    });
    if let Some(codes) = &pairing {
        tokio::spawn(follow_codes(codes.subscribe(), Arc::clone(&hub)));
    }
    tokio::spawn(consent::run(requests, Arc::clone(&hub)));

    let mut extra = Vec::new();
    if args.listen_loopback {
        extra.push(rr_net::listen::loopback_target(config.agent.listen_port));
    }
    let planned = plan_listeners(&rr_net::discover(), &config.agent);
    let listening: Vec<String> = planned
        .targets
        .iter()
        .chain(&extra)
        .map(|target| format!("{} ({})", target.addr, target.class.as_str()))
        .collect();
    hub.audit(
        "agent_started",
        json!({
            "device": device_name,
            "fingerprint": fingerprint,
            "port": config.agent.listen_port,
            "pairing": config.agent.attended.pairing_enabled,
            "listening": listening,
            "paired_viewers": trust.viewers.len(),
        }),
    );
    hub.state().listening = listening;

    let (stop, stopped) = watch::channel(false);
    let listeners = tokio::spawn(rr_net::run_listeners(
        agent,
        config.agent.clone(),
        extra,
        stopped,
    ));
    Ok(Core {
        hub,
        stop,
        listeners,
    })
}

/// Installs the kill-switch hotkey; `None` (explained on the console) where
/// the system has none. The tray and window buttons work everywhere.
fn install_kill_switch(hub: &Arc<Hub>, hotkey: Hotkey) -> Option<KillSwitch> {
    let target = Arc::clone(hub);
    match KillSwitch::install(hotkey, move || target.kill(Via::Hotkey)) {
        Ok(kill_switch) => {
            println!("  kill switch: {hotkey} ends every session at once");
            hub.set_hotkey(hotkey.to_string());
            Some(kill_switch)
        }
        Err(InputError::Unsupported(reason)) => {
            println!(
                "  kill switch: no hotkey here ({reason}); use Stop sharing in the window or tray"
            );
            None
        }
        Err(err) => {
            tracing::warn!(error = %err, "cannot install the kill-switch hotkey");
            println!("  kill switch: the hotkey is unavailable ({err})");
            None
        }
    }
}

/// Hands every new session code to the hub. The code goes to the window
/// or the terminal for the local user only and is never logged.
async fn follow_codes(mut codes: watch::Receiver<SessionCode>, hub: Arc<Hub>) {
    loop {
        let code = codes.borrow_and_update().expose().to_owned();
        hub.set_code(code);
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
    let name = trust
        .viewers
        .iter()
        .find(|viewer| viewer.key == key)
        .map(|viewer| viewer.name.clone())
        .unwrap_or_default();
    trust.remove_viewer(&key);
    rr_config::save_trust(&paths.trust, &trust)?;
    if let Some(dir) = paths.audit_dir() {
        let recorded = rr_telemetry::AuditLog::open(dir).and_then(|mut log| {
            log.record(
                "viewer_forgotten",
                json!({ "viewer": name, "fingerprint": rr_net::Fingerprint::of(&key).to_string() }),
            )
        });
        if let Err(err) = recorded {
            tracing::warn!(error = %err, "cannot write the audit log");
        }
    }
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
