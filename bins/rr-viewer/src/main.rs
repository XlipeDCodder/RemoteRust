//! RustRemote Viewer: the app used to control a remote Agent
//! (blueprint v2 §4.1).
//!
//! Unprivileged process: UI, path selection, decoding, rendering and local
//! input capture.
//!
//! M1 build: pairing, path selection and the control session (ping) only.
#![forbid(unsafe_code)]

use std::io::{BufRead as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use rr_config::{AgentConfig, Config, KnownAgent, MAX_KNOWN_ADDRESSES, TrustStore};
use rr_net::{DeviceIdentity, Fingerprint, RaceError, SessionCode, SessionError, Viewer};

#[derive(Debug, Parser)]
#[command(
    name = "rr-viewer",
    version,
    about = "RustRemote Viewer: pair with and connect to RustRemote Agents."
)]
struct Cli {
    /// Keep configuration, identity and paired devices in this folder
    /// instead of the per-user default (for example to run a second
    /// device on one machine).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Pair with an Agent using the session code it shows.
    Pair {
        /// Agent address: `IP`, `IP:PORT` or a host name (e.g. Tailscale MagicDNS).
        address: String,
        /// Session code. Prefer typing it at the prompt: command lines are
        /// visible to other local users.
        #[arg(long)]
        code: Option<String>,
    },
    /// Connect to a paired Agent over the best available path.
    Connect {
        /// Agent name or key prefix (8+ hex characters).
        agent: String,
        /// Number of pings to send before disconnecting.
        #[arg(long, default_value_t = 5)]
        pings: u32,
    },
    /// List paired Agents and their known addresses.
    List,
    /// Unpair an Agent, by name or key prefix.
    Forget {
        /// Agent name or key prefix.
        agent: String,
    },
    /// Show network interfaces and the VPNs usable from this machine.
    Interfaces,
    /// Show this device's key and fingerprint (creates them on first use).
    Identity,
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
        Command::Pair { address, code } => pair(&paths, &config, &address, code).await,
        Command::Connect { agent, pings } => connect(&paths, &config, &agent, pings).await,
        Command::List => list(&paths),
        Command::Forget { agent } => forget(&paths, &agent),
        Command::Interfaces => {
            show_interfaces();
            Ok(())
        }
        Command::Identity => show_identity(&paths, &config),
    }
}

async fn pair(
    paths: &Paths,
    config: &Config,
    address: &str,
    code: Option<String>,
) -> anyhow::Result<()> {
    let addr = resolve(address).await?;
    let code = match code {
        Some(text) => text,
        None => prompt("Session code shown on the Agent: ")?,
    };
    let code = SessionCode::parse(&code).context("a session code is 6 digits")?;

    let viewer = new_viewer(paths, config)?;
    let mut session = match viewer.pair(addr, &code).await {
        Ok(session) => session,
        Err(SessionError::PairingFailed) => {
            bail!("wrong session code (after 3 wrong codes the Agent shows a new one)")
        }
        Err(err) => return Err(explain(err)).context(format!("cannot pair with {addr}")),
    };

    let known = session.known_agent(unix_now());
    update_trust(paths, |trust| trust.upsert_agent(known.clone()))?;
    println!(
        "Paired with \"{}\"\n  fingerprint: {}\n  check that the Agent shows the same fingerprint.",
        session.agent_name(),
        Fingerprint::of(&session.agent_key())
    );
    match session.ping().await {
        Ok(rtt) => println!("  round trip: {}", millis(rtt)),
        Err(err) => println!("  ping failed: {err}"),
    }
    session.close().await;
    Ok(())
}

async fn connect(paths: &Paths, config: &Config, query: &str, pings: u32) -> anyhow::Result<()> {
    let trust = load_trust(paths)?;
    let agent = find_agent(&trust, query)?.clone();
    let viewer = new_viewer(paths, config)?;
    let stagger = Duration::from_millis(u64::from(config.viewer.race_stagger_ms));

    let mut session = match viewer
        .connect_known(&agent, &config.viewer.network_priority, stagger)
        .await
    {
        Ok(session) => session,
        Err(RaceError::AllFailed(failures)) => {
            eprintln!("Every path to \"{}\" failed:", agent.name);
            for (candidate, err) in failures {
                eprintln!("  {candidate}: {:#}", explain(err));
            }
            bail!("cannot connect to \"{}\"", agent.name);
        }
        Err(err) => return Err(err.into()),
    };

    let used = session.remote_address();
    let class = agent
        .addresses
        .iter()
        .find(|candidate| candidate.addr == used)
        .map_or("?", |candidate| candidate.class.as_str());
    println!(
        "Connected to \"{}\" via {used} ({class})",
        session.agent_name()
    );

    // Refresh the address book with what the Agent announces now, keeping
    // older entries (such as manual addresses) after them.
    let mut refreshed = session.known_agent(agent.paired_at);
    for old in &agent.addresses {
        if !refreshed.addresses.iter().any(|new| new.addr == old.addr) {
            refreshed.addresses.push(*old);
        }
    }
    refreshed.addresses.truncate(MAX_KNOWN_ADDRESSES);
    if let Err(err) = update_trust(paths, |trust| trust.upsert_agent(refreshed.clone())) {
        eprintln!("warning: could not update the address book: {err:#}");
    }

    for n in 0..pings {
        if n > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        match session.ping().await {
            Ok(rtt) => println!(
                "  ping {}: {} (QUIC estimate {})",
                n.saturating_add(1),
                millis(rtt),
                millis(session.quic_rtt())
            ),
            Err(err) => {
                println!("  ping failed: {err}");
                break;
            }
        }
    }
    session.close().await;
    Ok(())
}

fn list(paths: &Paths) -> anyhow::Result<()> {
    let trust = load_trust(paths)?;
    if trust.agents.is_empty() {
        println!("No paired agents. Use `rr-viewer pair <address>`.");
    }
    for agent in &trust.agents {
        println!("{:<24} {}", agent.name, Fingerprint::of(&agent.key));
        for candidate in &agent.addresses {
            println!("    {:<12} {}", candidate.class.as_str(), candidate.addr);
        }
    }
    Ok(())
}

fn forget(paths: &Paths, query: &str) -> anyhow::Result<()> {
    let trust = load_trust(paths)?;
    let key = find_agent(&trust, query)?.key;
    update_trust(paths, |trust| {
        trust.remove_agent(&key);
        Ok(())
    })?;
    println!("Forgot agent {key}.");
    Ok(())
}

fn show_interfaces() {
    let interfaces = rr_net::discover();
    for iface in &interfaces {
        let class = iface.class.map_or("ignored", |class| class.as_str());
        let state = if iface.up { "up" } else { "down" };
        let addrs: Vec<String> = iface.addrs.iter().map(ToString::to_string).collect();
        println!(
            "{:<28} {:<12} {:<5} {}",
            iface.label,
            class,
            state,
            addrs.join(", ")
        );
    }
    let usable: Vec<&str> = rr_net::discovery::active_classes(&interfaces)
        .into_iter()
        .map(|class| class.as_str())
        .collect();
    println!(
        "\nVPN classes usable for connections: {}",
        usable.join(", ")
    );
}

fn show_identity(paths: &Paths, config: &Config) -> anyhow::Result<()> {
    let identity = load_identity(paths)?;
    println!("name:        {}", device_name(config));
    println!("fingerprint: {}", identity.fingerprint());
    println!("public key:  {}", identity.public_key());
    println!("stored in:   {}", paths.identity.display());
    Ok(())
}

/// Adds context to errors whose cause is not obvious to a user.
fn explain(err: SessionError) -> anyhow::Error {
    let hint = if err.is_tls_rejection() {
        Some("the Agent refused this device, or its key is not the pinned one (pair again?)")
    } else if matches!(err, SessionError::Timeout) {
        Some("no answer: is the Agent running, listening on this network and allowing this source?")
    } else {
        None
    };
    let err = anyhow::Error::new(err);
    match hint {
        Some(hint) => err.context(hint),
        None => err,
    }
}

fn find_agent<'a>(trust: &'a TrustStore, query: &str) -> anyhow::Result<&'a KnownAgent> {
    match trust.find_agents(query).as_slice() {
        [] => bail!("no paired agent matches {query:?} (see `rr-viewer list`)"),
        [agent] => Ok(agent),
        many => bail!(
            "{} agents match {query:?}; use a key prefix instead",
            many.len()
        ),
    }
}

/// Accepts `IP`, `IP:PORT`, `[IPv6]:PORT`, `host` or `host:PORT`.
async fn resolve(address: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, AgentConfig::DEFAULT_PORT));
    }
    let with_port = if address.contains(':') {
        address.to_owned()
    } else {
        format!("{address}:{}", AgentConfig::DEFAULT_PORT)
    };
    tokio::net::lookup_host(&with_port)
        .await
        .with_context(|| format!("cannot resolve {address:?}"))?
        .next()
        .with_context(|| format!("{address:?} has no address"))
}

fn prompt(question: &str) -> anyhow::Result<String> {
    print!("{question}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

fn new_viewer(paths: &Paths, config: &Config) -> anyhow::Result<Viewer> {
    Ok(Viewer::new(load_identity(paths)?, &device_name(config)))
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

/// Re-reads the trust file, applies `change` and saves it, so entries the
/// Agent role wrote in the meantime are kept.
fn update_trust(
    paths: &Paths,
    change: impl FnOnce(&mut TrustStore) -> Result<(), rr_config::ConfigError>,
) -> anyhow::Result<()> {
    let mut trust = load_trust(paths)?;
    change(&mut trust)?;
    rr_config::save_trust(&paths.trust, &trust)
        .with_context(|| format!("cannot save {}", paths.trust.display()))
}

fn device_name(config: &Config) -> String {
    config.effective_device_name(rr_platform::host::hostname().as_deref())
}

fn millis(duration: Duration) -> String {
    format!("{:.1} ms", duration.as_secs_f64() * 1000.0)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
