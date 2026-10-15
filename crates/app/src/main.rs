use clap::{Parser, Subcommand};
use rustwalld_dns::config::Config;
use std::{error::Error, path::PathBuf, process::ExitCode};
#[derive(Parser)]
#[command(
    version,
    about = "Local-first DNS policy and security engine",
    args_conflicts_with_subcommands = true
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    check_config: bool,
    #[arg(long)]
    print_default_config: bool,
}
#[derive(Subcommand)]
enum Command {
    /// Initialize local password/2FA administration without starting services.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Preview a Pi-hole/AdGuard migration without publishing or starting services.
    Migrate {
        #[arg(long, value_enum)]
        source: rustwalld_dns::migration::Source,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        base_config: Option<PathBuf>,
    },
    /// Inspect all required policy assertions without starting the appliance.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Snapshot a live SQLite store into a new private file (including WAL).
    Backup {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Check integrity, schema and required assertions without starting DNS.
    VerifyBackup {
        #[arg(long)]
        database: PathBuf,
    },
    /// Restore a verified snapshot to an absent database; stop the service first.
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        database: PathBuf,
    },
}
#[derive(Subcommand)]
enum AuthCommand {
    Init {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, required = true)]
        password_stdin: bool,
        #[arg(long)]
        disable_totp: bool,
    },
}
#[derive(Subcommand)]
enum PolicyCommand {
    /// Compile a configuration and report every required assertion and its trace.
    Test {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: rustwalld_dns::policy_check::Format,
    },
}
fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    if let Some(command) = args.command {
        let report = match command {
            Command::Auth {
                command:
                    AuthCommand::Init {
                        output,
                        username,
                        password_stdin: _,
                        disable_totp,
                    },
            } => {
                use std::io::Read;
                let mut password = zeroize::Zeroizing::new(Vec::new());
                std::io::stdin().take(1027).read_to_end(&mut password)?;
                if password.last() == Some(&b'\n') {
                    password.pop();
                    if password.last() == Some(&b'\r') {
                        password.pop();
                    }
                }
                std::str::from_utf8(&password).map_err(|_| "Password input must be UTF-8")?;
                let provision =
                    rustwalld_dns::auth::initialize(output, username, &password, !disable_totp)?;
                println!(
                    "{}",
                    serde_json::json!({"initialized":true,"totp_provisioning_uri":provision.as_ref().map(|uri|uri.as_str())})
                );
                return Ok(ExitCode::SUCCESS);
            }
            Command::Migrate {
                source,
                input,
                base_config,
            } => {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::fs::File::open(input)?
                    .take(rustwalld_dns::migration::MAX_INPUT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                let base = base_config
                    .map(|path| Config::read(&path))
                    .transpose()?
                    .unwrap_or_default();
                let mut report = rustwalld_dns::migration::preview(source, &bytes, base.policy)?;
                report.validate_listener(base.dns_listen);
                let code = if report.ready {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(code);
            }
            Command::Policy {
                command: PolicyCommand::Test { config, format },
            } => {
                return Ok(match rustwalld_dns::policy_check::run(&config, format) {
                    Ok(true) => ExitCode::SUCCESS,
                    Ok(false) => ExitCode::from(1),
                    Err(error) => {
                        eprintln!("policy check could not run: {:?}", error.to_string());
                        ExitCode::from(2)
                    }
                });
            }
            Command::Backup { database, output } => {
                rustwalld_dns::maintenance::snapshot(&database, &output)?
            }
            Command::VerifyBackup { database } => rustwalld_dns::maintenance::verify(&database)?,
            Command::Restore { backup, database } => {
                rustwalld_dns::maintenance::snapshot(&backup, &database)?
            }
        };
        println!("{}", serde_json::to_string(&report)?);
        return Ok(ExitCode::SUCCESS);
    }
    if args.print_default_config {
        println!("{}", toml::to_string_pretty(&Config::default())?);
        return Ok(ExitCode::SUCCESS);
    }
    let config = match args.config {
        Some(path) => Config::read(&path)?,
        None => Config::default(),
    };
    if args.check_config {
        config.validate().map_err(rustwalld_dns::config::invalid)?;
        // Operator intake: every exception in the file is treated as new.
        config.policy.validate_new_exceptions(&[])?;
        rustwalld_dns_policy::PolicySnapshot::compile(config.policy, 1)?;
        println!("configuration and required assertions passed");
        return Ok(ExitCode::SUCCESS);
    }
    let token = match (
        std::env::var_os("RUSTWALLD_API_TOKEN_FILE"),
        std::env::var("RUSTWALLD_API_TOKEN").ok(),
    ) {
        (Some(_), Some(_)) => {
            return Err("Set only one of RUSTWALLD_API_TOKEN_FILE or RUSTWALLD_API_TOKEN".into());
        }
        (Some(path), None) => {
            rustwalld_dns::auth::master_token(std::path::Path::new(&path))?.to_string()
        }
        (None, Some(token)) => token,
        (None, None) => return Err(
            "Set RUSTWALLD_API_TOKEN_FILE or RUSTWALLD_API_TOKEN to protect management endpoints"
                .into(),
        ),
    };
    // Standalone commands keep stdout exclusively for their report.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    // Separate executors/reactors protect DNS from management scheduling stalls.
    let dns_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("dns-worker")
        .enable_all()
        .build()?;
    let control_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("control-worker")
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let result = control_runtime.block_on(async {
        let stop = tokio_util::sync::CancellationToken::new();
        let run = rustwalld_dns::run(config, token, dns_runtime.handle().clone(), stop.clone());
        tokio::pin!(run);
        tokio::select! {
            result=&mut run=>result,
            signal=shutdown_signal()=>{stop.cancel();run.await?;signal.map_err(Into::into)},
        }
    });
    control_runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    dns_runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result.map(|()| ExitCode::SUCCESS)
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {result=tokio::signal::ctrl_c()=>result,_=terminate.recv()=>Ok(())}
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
