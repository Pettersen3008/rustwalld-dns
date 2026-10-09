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
    let token = std::env::var("RUSTWALLD_API_TOKEN")
        .map_err(|_| "set RUSTWALLD_API_TOKEN (16..1024 bytes) to protect management endpoints")?;
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
