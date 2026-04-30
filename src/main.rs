use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use he_router::{
    HeRouter, HeRouterConfig, RouteRequest, TlsBackend, bind_dry_run, route_get,
    validate_kernel_ready,
};

#[derive(Debug, Parser)]
#[command(name = "he-router")]
#[command(about = "HE routed IPv6 source binding helper")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write an example config.toml.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Validate config, kernel sysctls, and local route.
    Check,
    /// Derive the source IPv6 for an account/token pair.
    Derive {
        #[arg(long)]
        account_id: String,
        #[arg(long)]
        access_token: Option<String>,
    },
    /// Run a local bind dry-run and optional route lookup.
    Smoke {
        #[arg(long)]
        account_id: String,
        #[arg(long)]
        access_token: Option<String>,
        #[arg(long, default_value = "https://chatgpt.com/backend-api/codex/models")]
        upstream_url: String,
        #[arg(long)]
        target_ipv6: Option<Ipv6Addr>,
    },
}

fn main() -> he_router::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { force } => {
            if cli.config.exists() && !force {
                return Err(he_router::HeRouterError::Config(format!(
                    "{} already exists; pass --force to overwrite",
                    cli.config.display()
                )));
            }
            HeRouterConfig::write_example(&cli.config)?;
            println!("wrote {}", cli.config.display());
        }
        Command::Check => {
            let cfg = HeRouterConfig::load_from(&cli.config)?;
            validate_kernel_ready(&cfg)?;
            println!("kernel ready for prefix {}", cfg.ipv6_prefix);
        }
        Command::Derive {
            account_id,
            access_token,
        } => {
            let cfg = HeRouterConfig::load_from(&cli.config)?;
            let router = HeRouter::new(HeRouterConfig {
                require_kernel_ready: false,
                ..cfg
            })?;
            match router.derive_source_ip(&account_id, access_token.as_deref())? {
                Some(ip) => println!("{ip}"),
                None => println!(
                    "no route decision: router disabled or token missing for access-token scope"
                ),
            }
        }
        Command::Smoke {
            account_id,
            access_token,
            upstream_url,
            target_ipv6,
        } => {
            let cfg = HeRouterConfig::load_from(&cli.config)?;
            let router = HeRouter::new(cfg)?;
            let Some(decision) = router.route(RouteRequest {
                account_id: &account_id,
                access_token: access_token.as_deref(),
                upstream_url: &upstream_url,
                timeout: Duration::from_secs(30),
                tls_backend: TlsBackend::Default,
                proxy_url: None,
            })?
            else {
                println!(
                    "no route decision: router disabled or token missing for access-token scope"
                );
                return Ok(());
            };
            println!("binding_key_prefix={}", decision.binding_key_prefix);
            println!("source_ip={}", decision.source_ip);
            println!("upstream_origin={}", decision.upstream_origin);
            let bound = bind_dry_run(decision.source_ip)?;
            println!("bind ok {bound}");
            if let Some(target_ipv6) = target_ipv6 {
                println!("route_get={}", route_get(target_ipv6, decision.source_ip)?);
            }
        }
    }
    Ok(())
}
