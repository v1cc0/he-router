# he-router

`he-router` is a small Rust 2024 crate for applications that need deterministic
source IPv6 binding from a routed HE-style IPv6 prefix.

It packages the reusable part of TT's native magic access work:

- parse `config.toml`
- validate Linux non-local IPv6 bind prerequisites
- derive a stable source IPv6 from account/token material
- build/cache `reqwest::Client` values with `ClientBuilder::local_address(...)`
- expose a minimal CLI while keeping the library integration-first
- preserve app-specific routing identity by overriding `binding_namespace` or
  constructing `HeRouter::with_salt_material(...)`

## Kernel setup

Run this outside the application, usually from systemd/deploy scripts:

```bash
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo ip -6 route replace local 2001:470:f41e::/48 dev lo table local
```

The application should stay unprivileged.

## Config

```bash
he-router --config config.toml init
cp config.toml.example config.toml
```

## CLI examples

The CLI is behind the `cli` feature so library consumers do not inherit CLI-only
dependencies:

```bash
cargo run --features cli -- --config config.toml prepare
```

```bash
he-router --config config.toml check
he-router --config config.toml prepare
he-router --config config.toml prepare --systemd --before-service tt.service
he-router --config config.toml derive --account-id acct_1 --access-token token
he-router --config config.toml --json derive --account-id acct_1 --access-token token
he-router --config config.toml smoke \
  --account-id acct_1 \
  --access-token token \
  --target-ipv6 2606:4700:4400::ac40:9bd1
```

`prepare` is safe by default: it prints the exact sysctl/route commands instead
of mutating the host. Use `prepare --apply` only from a privileged deployment
step. Use `prepare --systemd` to generate a oneshot unit.

## Library sketch

```rust
use std::time::Duration;
use he_router::{kernel_prepare_plan, HeRouter, HeRouterConfig, RouteRequest, TlsBackend};

let config = HeRouterConfig::load_from("config.toml")?;
let plan = kernel_prepare_plan(&config)?;
let router = HeRouter::new(config)?;
let decision = router.route(RouteRequest {
    account_id: "account-1",
    access_token: Some("oauth-access-token"),
    upstream_url: "https://chatgpt.com/backend-api/codex/responses",
    timeout: Duration::from_secs(60),
    tls_backend: TlsBackend::Default,
    proxy_url: None,
})?;

if let Some(decision) = decision {
    let client = decision.client;
    // build the upstream request with this client; retries should reuse it.
}
# Ok::<(), he_router::HeRouterError>(())
```
