use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use he_router::{
    HeRouter, HeRouterConfig, RouteRequest, TlsBackend, bind_dry_run, kernel_prepare_plan, remote,
    route_get, validate_kernel_ready,
};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "he-router")]
#[command(about = "HE routed IPv6 source binding helper")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[arg(long, global = true)]
    json: bool,
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
    /// Print or apply Linux sysctl/route preparation.
    Prepare {
        /// Apply the commands directly. Run as root or through sudo.
        #[arg(long)]
        apply: bool,
        /// Print a systemd oneshot unit instead of shell commands.
        #[arg(long)]
        systemd: bool,
        /// Optional service that should start after the generated systemd unit.
        #[arg(long)]
        before_service: Option<String>,
    },
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
    /// Run the remote QUIC proxy server on a HE-enabled VPS.
    Server {
        #[arg(long, default_value = "[::]:7443")]
        listen: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        auth_token: String,
    },
    /// Send one HTTP request through a remote he-router server using a local client config.
    Client {
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long)]
        url: String,
        #[arg(long = "header")]
        headers: Vec<String>,
        #[arg(long)]
        body: Option<String>,
    },
    /// Write an example remote client config for local auth/tunnel usage.
    InitClientConfig {
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> he_router::Result<()> {
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
            if cli.json {
                print_json(json!({ "written": cli.config.display().to_string() }))?;
            } else {
                println!("wrote {}", cli.config.display());
            }
        }
        Command::Check => {
            let cfg = HeRouterConfig::load_from(&cli.config)?;
            validate_kernel_ready(&cfg)?;
            if cli.json {
                print_json(json!({
                    "ok": true,
                    "enabled": cfg.enabled,
                    "prefix": cfg.ipv6_prefix,
                }))?;
            } else {
                println!("kernel ready for prefix {}", cfg.ipv6_prefix);
            }
        }
        Command::Prepare {
            apply,
            systemd,
            before_service,
        } => {
            if apply && systemd {
                return Err(he_router::HeRouterError::Config(
                    "--apply and --systemd are mutually exclusive".to_string(),
                ));
            }

            let cfg = HeRouterConfig::load_from(&cli.config)?;
            let Some(plan) = kernel_prepare_plan(&cfg)? else {
                if cli.json {
                    print_json(json!({ "enabled": false, "commands": [] }))?;
                } else {
                    println!("he-router is disabled; no kernel preparation needed");
                }
                return Ok(());
            };

            let prefix = plan.prefix().to_string();
            if systemd {
                let unit = plan.systemd_unit(before_service.as_deref());
                if cli.json {
                    print_json(json!({
                        "prefix": prefix,
                        "systemd_unit": unit,
                    }))?;
                } else {
                    print!("{unit}");
                }
                return Ok(());
            }

            if apply {
                plan.apply()?;
                if cli.json {
                    print_json(json!({
                        "applied": true,
                        "prefix": prefix,
                    }))?;
                } else {
                    println!("applied kernel preparation for prefix {prefix}");
                }
                return Ok(());
            }

            let commands = plan.shell_commands();
            if cli.json {
                print_json(json!({
                    "prefix": prefix,
                    "commands": commands,
                }))?;
            } else {
                for command in commands {
                    println!("{command}");
                }
            }
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
                Some(ip) => {
                    if cli.json {
                        print_json(json!({
                            "routed": true,
                            "source_ip": ip.to_string(),
                        }))?;
                    } else {
                        println!("{ip}");
                    }
                }
                None => {
                    let reason = "router disabled or token missing for access-token scope";
                    if cli.json {
                        print_json(json!({
                            "routed": false,
                            "reason": reason,
                        }))?;
                    } else {
                        println!("no route decision: {reason}");
                    }
                }
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
                let reason = "router disabled or token missing for access-token scope";
                if cli.json {
                    print_json(json!({
                        "routed": false,
                        "reason": reason,
                    }))?;
                } else {
                    println!("no route decision: {reason}");
                }
                return Ok(());
            };

            let bound = bind_dry_run(decision.source_ip)?;
            let route = target_ipv6
                .map(|target_ipv6| route_get(target_ipv6, decision.source_ip))
                .transpose()?;
            if cli.json {
                print_json(json!({
                    "routed": true,
                    "binding_key_prefix": decision.binding_key_prefix,
                    "source_ip": decision.source_ip.to_string(),
                    "upstream_origin": decision.upstream_origin,
                    "bind": bound,
                    "route_get": route,
                }))?;
            } else {
                println!("binding_key_prefix={}", decision.binding_key_prefix);
                println!("source_ip={}", decision.source_ip);
                println!("upstream_origin={}", decision.upstream_origin);
                println!("bind ok {bound}");
                if let Some(route) = route {
                    println!("route_get={route}");
                }
            }
        }
        Command::Server {
            listen,
            cert,
            key,
            auth_token,
        } => {
            let options = remote::RemoteServerOptions {
                listen,
                cert_path: cert,
                key_path: key,
                auth_token,
            };
            remote::run_server(&cli.config, options).await?;
        }
        Command::Client {
            method,
            url,
            headers,
            body,
        } => {
            let headers = parse_header_args(headers)?;
            let response = remote::run_client_command(
                &cli.config,
                remote::ClientCommandOptions {
                    method,
                    url,
                    headers,
                    body: body.unwrap_or_default().into_bytes(),
                },
            )
            .await?;
            if cli.json {
                print_json(json!({
                    "status": response.status,
                    "headers": response.headers,
                    "body": String::from_utf8_lossy(&response.body),
                    "source_ip": response.source_ip,
                    "error": response.error,
                }))?;
            } else {
                println!("status={}", response.status);
                if let Some(source_ip) = response.source_ip {
                    println!("source_ip={source_ip}");
                }
                if let Some(error) = response.error {
                    println!("error={error}");
                }
                for header in response.headers {
                    println!("header:{}={}", header.name, header.value);
                }
                if !response.body.is_empty() {
                    println!("{}", String::from_utf8_lossy(&response.body));
                }
            }
        }
        Command::InitClientConfig { force } => {
            if cli.config.exists() && !force {
                return Err(he_router::HeRouterError::Config(format!(
                    "{} already exists; pass --force to overwrite",
                    cli.config.display()
                )));
            }
            remote::RemoteClientConfig::write_example(&cli.config)?;
            if cli.json {
                print_json(json!({ "written": cli.config.display().to_string() }))?;
            } else {
                println!("wrote {}", cli.config.display());
            }
        }
    }
    Ok(())
}

fn print_json(value: serde_json::Value) -> he_router::Result<()> {
    let raw = serde_json::to_string_pretty(&value).map_err(|err| {
        he_router::HeRouterError::Config(format!("failed to serialize JSON output: {err}"))
    })?;
    println!("{raw}");
    Ok(())
}

fn parse_header_args(values: Vec<String>) -> he_router::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for value in values {
        let Some((name, header_value)) = value.split_once(':') else {
            return Err(he_router::HeRouterError::Config(format!(
                "invalid --header {value:?}; expected name:value"
            )));
        };
        headers.push((name.trim().to_string(), header_value.trim().to_string()));
    }
    Ok(headers)
}
