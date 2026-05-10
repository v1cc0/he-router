use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6, TcpListener};
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, HeRouterError>;

pub mod remote;

#[derive(Debug, Error)]
pub enum HeRouterError {
    #[error("config error: {0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML decode error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("TOML encode error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeRouterMode {
    #[default]
    NativeNonlocalBind,
}

impl fmt::Display for HeRouterMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeNonlocalBind => f.write_str("native-nonlocal-bind"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingScope {
    #[default]
    AccessToken,
    Account,
}

impl fmt::Display for BindingScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken => f.write_str("access-token"),
            Self::Account => f.write_str("account"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeRouterConfig {
    pub enabled: bool,
    pub mode: HeRouterMode,
    pub ipv6_prefix: String,
    pub manage_kernel: bool,
    pub require_kernel_ready: bool,
    pub binding_namespace: String,
    pub binding_scope: BindingScope,
    pub binding_salt: String,
    pub binding_ttl_grace_seconds: u64,
    pub max_client_cache_entries: usize,
    pub client_idle_timeout_seconds: u64,
    pub allow_proxy: bool,
    pub log_decisions: bool,
    pub server: EmbeddedServerConfig,
    pub client: EmbeddedClientConfig,
}

impl Default for HeRouterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: HeRouterMode::NativeNonlocalBind,
            ipv6_prefix: String::new(),
            manage_kernel: false,
            require_kernel_ready: true,
            binding_namespace: "he-router".to_string(),
            binding_scope: BindingScope::AccessToken,
            binding_salt: String::new(),
            binding_ttl_grace_seconds: 120,
            max_client_cache_entries: 512,
            client_idle_timeout_seconds: 90,
            allow_proxy: false,
            log_decisions: false,
            server: EmbeddedServerConfig::default(),
            client: EmbeddedClientConfig::default(),
        }
    }
}

impl HeRouterConfig {
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn write_example(path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, include_str!("../config.toml.example"))?;
        Ok(())
    }

    pub fn default_enabled_example() -> Self {
        Self {
            enabled: true,
            ipv6_prefix: "2001:470:f41e::/48".to_string(),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.binding_namespace.trim().is_empty() {
            return Err(HeRouterError::Config(
                "binding_namespace must not be empty".to_string(),
            ));
        }

        if !self.ipv6_prefix.trim().is_empty() {
            self.parsed_prefix()?;
        }

        if !self.enabled {
            return Ok(());
        }

        if self.ipv6_prefix.trim().is_empty() {
            return Err(HeRouterError::Config(
                "ipv6_prefix is required when enabled=true".to_string(),
            ));
        }

        if self.manage_kernel {
            return Err(HeRouterError::Config(
                "manage_kernel=true is not implemented; prepare sysctl/routes externally"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn parsed_prefix(&self) -> Result<Ipv6Prefix> {
        self.ipv6_prefix.parse()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmbeddedServerConfig {
    pub listen_port: String,
    pub cert: String,
    pub key: String,
    #[serde(rename = "auth-token", alias = "auth_token")]
    pub auth_token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmbeddedClientConfig {
    pub server_addr: String,
    pub server_name: String,
    #[serde(rename = "auth-token", alias = "auth_token")]
    pub auth_token: String,
    pub ca_cert_path: String,
    pub bind_addr: String,
    pub request_timeout_seconds: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    network: Ipv6Addr,
    length: u8,
}

impl Ipv6Prefix {
    pub fn new(network: Ipv6Addr, length: u8) -> Result<Self> {
        if length > 128 {
            return Err(HeRouterError::Config(format!(
                "invalid IPv6 prefix length {length}; expected 0..=128"
            )));
        }
        let mask = prefix_mask(length);
        Ok(Self {
            network: Ipv6Addr::from(u128::from(network) & mask),
            length,
        })
    }

    pub fn network(self) -> Ipv6Addr {
        self.network
    }

    pub fn length(self) -> u8 {
        self.length
    }

    pub fn contains(self, ip: Ipv6Addr) -> bool {
        let mask = prefix_mask(self.length);
        (u128::from(ip) & mask) == u128::from(self.network)
    }
}

impl fmt::Debug for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

impl FromStr for Ipv6Prefix {
    type Err = HeRouterError;

    fn from_str(value: &str) -> Result<Self> {
        let value = value.trim();
        let Some((addr, length)) = value.split_once('/') else {
            return Err(HeRouterError::Config(format!(
                "invalid IPv6 prefix {value:?}; expected address/length"
            )));
        };
        let addr = addr
            .parse::<Ipv6Addr>()
            .map_err(|err| HeRouterError::Config(format!("invalid IPv6 prefix address: {err}")))?;
        let length = length
            .parse::<u8>()
            .map_err(|err| HeRouterError::Config(format!("invalid IPv6 prefix length: {err}")))?;
        Self::new(addr, length)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsBackend {
    Default,
    NativeTls,
    Rustls,
}

pub struct RouteRequest<'a> {
    pub account_id: &'a str,
    pub access_token: Option<&'a str>,
    pub upstream_url: &'a str,
    pub timeout: Duration,
    pub tls_backend: TlsBackend,
    pub proxy_url: Option<&'a str>,
}

impl fmt::Debug for RouteRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteRequest")
            .field("account_id", &self.account_id)
            .field(
                "access_token",
                &self.access_token.map(|token| {
                    if token.trim().is_empty() {
                        "<empty>"
                    } else {
                        "<redacted>"
                    }
                }),
            )
            .field("upstream_url", &self.upstream_url)
            .field("timeout", &self.timeout)
            .field("tls_backend", &self.tls_backend)
            .field("proxy_url", &normalized_proxy_mode(self.proxy_url))
            .finish()
    }
}

#[derive(Clone)]
pub struct RouteDecision {
    pub source_ip: Ipv6Addr,
    pub binding_key_prefix: String,
    pub upstream_origin: String,
    pub client: reqwest::Client,
}

impl fmt::Debug for RouteDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteDecision")
            .field("source_ip", &self.source_ip)
            .field("binding_key_prefix", &self.binding_key_prefix)
            .field("upstream_origin", &self.upstream_origin)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPreparePlan {
    prefix: Ipv6Prefix,
}

impl KernelPreparePlan {
    pub fn new(prefix: Ipv6Prefix) -> Self {
        Self { prefix }
    }

    pub fn prefix(self) -> Ipv6Prefix {
        self.prefix
    }

    pub fn shell_commands(self) -> [String; 3] {
        [
            "sudo sysctl -w net.ipv6.ip_nonlocal_bind=1".to_string(),
            "sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0".to_string(),
            format!(
                "sudo ip -6 route replace local {} dev lo table local",
                self.prefix
            ),
        ]
    }

    pub fn systemd_unit(self, before_service: Option<&str>) -> String {
        let mut unit = String::new();
        unit.push_str("[Unit]\n");
        unit.push_str("Description=Prepare he-router IPv6 non-local binding\n");
        if let Some(before_service) = before_service
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            unit.push_str(&format!("Before={before_service}\n"));
        }
        unit.push_str("Wants=network-online.target\n");
        unit.push_str("After=network-online.target\n\n");
        unit.push_str("[Service]\n");
        unit.push_str("Type=oneshot\n");
        unit.push_str(&format!("Environment=HE_ROUTER_PREFIX={}\n", self.prefix));
        unit.push_str("ExecStart=/usr/sbin/sysctl -w net.ipv6.ip_nonlocal_bind=1\n");
        unit.push_str("ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=0\n");
        unit.push_str(
            "ExecStart=/usr/sbin/ip -6 route replace local ${HE_ROUTER_PREFIX} dev lo table local\n",
        );
        unit.push_str("RemainAfterExit=yes\n\n");
        unit.push_str("[Install]\n");
        unit.push_str("WantedBy=multi-user.target\n");
        unit
    }

    pub fn apply(self) -> Result<()> {
        run_checked("sysctl", ["-w", "net.ipv6.ip_nonlocal_bind=1"].as_slice())?;
        run_checked(
            "sysctl",
            ["-w", "net.ipv6.conf.all.disable_ipv6=0"].as_slice(),
        )?;
        let prefix = self.prefix.to_string();
        run_checked(
            "ip",
            [
                "-6",
                "route",
                "replace",
                "local",
                prefix.as_str(),
                "dev",
                "lo",
                "table",
                "local",
            ]
            .as_slice(),
        )
    }
}

pub fn kernel_prepare_plan(config: &HeRouterConfig) -> Result<Option<KernelPreparePlan>> {
    config.validate()?;
    if !config.enabled {
        return Ok(None);
    }
    Ok(Some(KernelPreparePlan::new(config.parsed_prefix()?)))
}

#[derive(Debug)]
pub struct HeRouter {
    config: HeRouterConfig,
    prefix: Option<Ipv6Prefix>,
    salt_material: Vec<u8>,
    bindings: Mutex<HashMap<String, BindingMetadata>>,
    clients: Mutex<HashMap<ClientCacheKey, CachedClient>>,
}

impl HeRouter {
    pub fn new(config: HeRouterConfig) -> Result<Self> {
        Self::with_optional_salt_material(config, None)
    }

    pub fn with_salt_material(config: HeRouterConfig, salt_material: Vec<u8>) -> Result<Self> {
        if salt_material.is_empty() {
            return Err(HeRouterError::Config(
                "salt_material must not be empty".to_string(),
            ));
        }
        Self::with_optional_salt_material(config, Some(salt_material))
    }

    fn with_optional_salt_material(
        config: HeRouterConfig,
        salt_material: Option<Vec<u8>>,
    ) -> Result<Self> {
        config.validate()?;
        if config.enabled && config.require_kernel_ready {
            validate_kernel_ready(&config)?;
        }
        let prefix = if config.enabled {
            Some(config.parsed_prefix()?)
        } else {
            None
        };
        let salt_material = salt_material.unwrap_or_else(|| default_salt_material(&config, prefix));

        Ok(Self {
            config,
            prefix,
            salt_material,
            bindings: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
        })
    }

    pub fn route(&self, request: RouteRequest<'_>) -> Result<Option<RouteDecision>> {
        if !self.config.enabled {
            return Ok(None);
        }
        validate_proxy_compatibility(&self.config, request.proxy_url)?;

        let Some(prefix) = self.prefix else {
            return Err(HeRouterError::Config(
                "ipv6_prefix is required when enabled=true".to_string(),
            ));
        };

        let Some(binding) = self.resolve_binding(
            request.account_id,
            request.access_token,
            Some(request.upstream_url),
            prefix,
        )?
        else {
            return Ok(None);
        };
        let origin = binding
            .upstream_origin
            .expect("resolve_binding returns origin when upstream_url was provided");
        let client = self.client_for_binding(
            binding.source_ip,
            origin.clone(),
            request.timeout,
            request.tls_backend,
            request.proxy_url,
        )?;

        if self.config.log_decisions {
            eprintln!(
                "he-router selected source IPv6 binding_key_prefix={} source_ip={} upstream_origin={}",
                binding.binding_key_prefix, binding.source_ip, origin
            );
        }

        Ok(Some(RouteDecision {
            source_ip: binding.source_ip,
            binding_key_prefix: binding.binding_key_prefix,
            upstream_origin: origin,
            client,
        }))
    }

    pub fn derive_source_ip(
        &self,
        account_id: &str,
        access_token: Option<&str>,
    ) -> Result<Option<Ipv6Addr>> {
        if !self.config.enabled {
            return Ok(None);
        }
        let Some(prefix) = self.prefix else {
            return Err(HeRouterError::Config(
                "ipv6_prefix is required when enabled=true".to_string(),
            ));
        };
        Ok(self
            .resolve_binding(account_id, access_token, None, prefix)?
            .map(|binding| binding.source_ip))
    }

    fn resolve_binding(
        &self,
        account_id: &str,
        access_token: Option<&str>,
        upstream_url: Option<&str>,
        prefix: Ipv6Prefix,
    ) -> Result<Option<ResolvedBinding>> {
        let Some(binding_material) = binding_material(
            self.config.binding_namespace.as_str(),
            self.config.binding_scope,
            account_id,
            access_token,
        )?
        else {
            return Ok(None);
        };

        let binding_digest = Sha256::digest(binding_material.as_bytes());
        let binding_key_prefix = hex_prefix(&binding_digest, 12);
        let source_ip = derive_source_ipv6(prefix, &self.salt_material, &binding_digest);
        debug_assert!(prefix.contains(source_ip));
        let upstream_origin = upstream_url.map(upstream_origin).transpose()?;

        let now_ms = now_ms();
        let mut bindings = self
            .bindings
            .lock()
            .expect("he-router binding cache poisoned");
        prune_bindings(
            &mut bindings,
            now_ms,
            self.config.binding_ttl_grace_seconds.saturating_mul(1_000),
        );
        bindings
            .entry(binding_key_prefix.clone())
            .and_modify(|entry| entry.expires_at_ms = None)
            .or_insert_with(|| BindingMetadata {
                expires_at_ms: None,
            });

        Ok(Some(ResolvedBinding {
            source_ip,
            binding_key_prefix,
            upstream_origin,
        }))
    }

    fn client_for_binding(
        &self,
        source_ip: Ipv6Addr,
        origin: String,
        timeout: Duration,
        tls_backend: TlsBackend,
        proxy_url: Option<&str>,
    ) -> Result<reqwest::Client> {
        let key = ClientCacheKey::new(source_ip, origin, timeout, tls_backend, proxy_url);
        let now = Instant::now();
        {
            let mut clients = self
                .clients
                .lock()
                .expect("he-router client cache poisoned");
            prune_client_cache(&mut clients, now, self.config.client_idle_timeout_seconds);
            if let Some(entry) = clients.get_mut(&key) {
                entry.last_used_at = now;
                return Ok(entry.client.clone());
            }
        }

        let client = build_client(source_ip, timeout, tls_backend, proxy_url)?;
        let mut clients = self
            .clients
            .lock()
            .expect("he-router client cache poisoned");
        prune_client_cache(&mut clients, now, self.config.client_idle_timeout_seconds);
        clients.insert(
            key,
            CachedClient {
                client: client.clone(),
                last_used_at: now,
            },
        );
        enforce_client_cache_limit(&mut clients, self.config.max_client_cache_entries);
        Ok(client)
    }
}

#[derive(Debug, Clone)]
struct ResolvedBinding {
    source_ip: Ipv6Addr,
    binding_key_prefix: String,
    upstream_origin: Option<String>,
}

#[derive(Debug, Clone)]
struct BindingMetadata {
    expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
struct CachedClient {
    client: reqwest::Client,
    last_used_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientCacheKey {
    source_ip: Ipv6Addr,
    origin: String,
    timeout_ms: u64,
    tls_backend: TlsBackend,
    proxy_mode: String,
}

impl ClientCacheKey {
    fn new(
        source_ip: Ipv6Addr,
        origin: String,
        timeout: Duration,
        tls_backend: TlsBackend,
        proxy_url: Option<&str>,
    ) -> Self {
        Self {
            source_ip,
            origin,
            timeout_ms: duration_ms(timeout),
            tls_backend,
            proxy_mode: normalized_proxy_mode(proxy_url),
        }
    }
}

pub fn validate_kernel_ready(config: &HeRouterConfig) -> Result<()> {
    config.validate()?;
    if !config.enabled {
        return Ok(());
    }
    let prefix = config.parsed_prefix()?;

    let ip_nonlocal_bind = read_proc_sys_trimmed("/proc/sys/net/ipv6/ip_nonlocal_bind")?;
    if ip_nonlocal_bind != "1" {
        return Err(HeRouterError::Config(format!(
            "he-router requires net.ipv6.ip_nonlocal_bind=1, got {ip_nonlocal_bind}"
        )));
    }

    let disable_ipv6 = read_proc_sys_trimmed("/proc/sys/net/ipv6/conf/all/disable_ipv6")?;
    if disable_ipv6 != "0" {
        return Err(HeRouterError::Config(format!(
            "he-router requires net.ipv6.conf.all.disable_ipv6=0, got {disable_ipv6}"
        )));
    }

    validate_local_route(prefix)
}

pub fn bind_dry_run(source_ip: Ipv6Addr) -> Result<String> {
    let listener = TcpListener::bind(SocketAddrV6::new(source_ip, 0, 0, 0)).map_err(|err| {
        HeRouterError::Config(format!("failed to bind non-local IPv6 {source_ip}: {err}"))
    })?;
    let local_addr = listener.local_addr()?;
    Ok(local_addr.to_string())
}

pub fn route_get(target_ipv6: Ipv6Addr, source_ip: Ipv6Addr) -> Result<String> {
    let output = Command::new("ip")
        .args([
            "-6",
            "route",
            "get",
            &target_ipv6.to_string(),
            "from",
            &source_ip.to_string(),
        ])
        .output()
        .map_err(|err| HeRouterError::Config(format!("failed to run ip route get: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(HeRouterError::Config(format!(
            "ip -6 route get failed for target {target_ipv6} from {source_ip}: {stderr}"
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_checked(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| HeRouterError::Config(format!("failed to run {program}: {err}")))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(HeRouterError::Config(format!(
        "{program} {} failed: {detail}",
        args.join(" ")
    )))
}

fn binding_material(
    binding_namespace: &str,
    binding_scope: BindingScope,
    account_id: &str,
    access_token: Option<&str>,
) -> Result<Option<String>> {
    let binding_namespace = binding_namespace.trim();
    if binding_namespace.is_empty() {
        return Err(HeRouterError::Config(
            "binding_namespace must not be empty".to_string(),
        ));
    }
    let account_id = account_id.trim();
    if account_id.is_empty() {
        return Err(HeRouterError::Config(
            "account_id must not be empty".to_string(),
        ));
    }

    match binding_scope {
        BindingScope::AccessToken => {
            let Some(token) = access_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Ok(None);
            };
            Ok(Some(format!("{binding_namespace}:{account_id}:{token}")))
        }
        BindingScope::Account => Ok(Some(format!("{binding_namespace}:{account_id}:account"))),
    }
}

fn validate_proxy_compatibility(config: &HeRouterConfig, proxy_url: Option<&str>) -> Result<()> {
    if !config.enabled || config.allow_proxy || !is_real_proxy(proxy_url) {
        return Ok(());
    }
    Err(HeRouterError::Config(
        "he-router refuses proxy_url unless allow_proxy=true".to_string(),
    ))
}

fn is_real_proxy(proxy_url: Option<&str>) -> bool {
    proxy_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !matches!(value.to_ascii_lowercase().as_str(), "direct" | "none"))
}

fn normalized_proxy_mode(proxy_url: Option<&str>) -> String {
    proxy_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !matches!(value.as_str(), "direct" | "none"))
        .unwrap_or_else(|| "direct".to_string())
}

fn build_client(
    source_ip: Ipv6Addr,
    timeout: Duration,
    tls_backend: TlsBackend,
    proxy_url: Option<&str>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .local_address(IpAddr::V6(source_ip));

    match tls_backend {
        TlsBackend::Default => {}
        TlsBackend::NativeTls => {
            builder = builder.tls_backend_native();
        }
        TlsBackend::Rustls => {
            builder = builder.tls_backend_rustls();
        }
    }

    if let Some(proxy_url) = proxy_url.map(str::trim).filter(|value| !value.is_empty()) {
        if matches!(proxy_url.to_ascii_lowercase().as_str(), "direct" | "none") {
            builder = builder.no_proxy();
        } else {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|err| HeRouterError::Config(format!("invalid proxy_url: {err}")))?;
            builder = builder.no_proxy().proxy(proxy);
        }
    }

    builder
        .build()
        .map_err(|err| HeRouterError::Config(format!("failed to build reqwest client: {err}")))
}

fn upstream_origin(raw_url: &str) -> Result<String> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|err| HeRouterError::Config(format!("invalid upstream URL: {err}")))?;
    let scheme = url.scheme();
    let host = url
        .host_str()
        .ok_or_else(|| HeRouterError::Config("upstream URL must include a host".to_string()))?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| HeRouterError::Config("upstream URL must include a port".to_string()))?;
    Ok(format!("{scheme}://{host}:{port}"))
}

fn default_salt_material(config: &HeRouterConfig, prefix: Option<Ipv6Prefix>) -> Vec<u8> {
    let salt = config.binding_salt.trim();
    if !salt.is_empty() {
        return salt.as_bytes().to_vec();
    }
    let prefix = prefix
        .map(|prefix| prefix.to_string())
        .unwrap_or_else(|| "disabled".to_string());
    Sha256::digest(format!("he-router:default-binding-salt:v1:{prefix}").as_bytes()).to_vec()
}

fn derive_source_ipv6(prefix: Ipv6Prefix, salt_material: &[u8], binding_digest: &[u8]) -> Ipv6Addr {
    let mut hasher = Sha256::new();
    hasher.update(salt_material);
    hasher.update(b":");
    hasher.update(binding_digest);
    let digest = hasher.finalize();

    let mut first_128 = [0_u8; 16];
    first_128.copy_from_slice(&digest[..16]);
    let material = u128::from_be_bytes(first_128);
    let prefix_len = prefix.length();
    let host_bits = 128_u8.saturating_sub(prefix_len);
    let host_mask = if host_bits == 128 {
        u128::MAX
    } else if host_bits == 0 {
        0
    } else {
        (1_u128 << host_bits) - 1
    };
    let host = if host_bits == 0 {
        0
    } else {
        material >> prefix_len
    } & host_mask;
    Ipv6Addr::from(u128::from(prefix.network()) | host)
}

fn prefix_mask(length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(length))
    }
}

fn read_proc_sys_trimmed(path: &str) -> Result<String> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .map_err(|err| HeRouterError::Config(format!("failed to read {path}: {err}")))
}

fn validate_local_route(prefix: Ipv6Prefix) -> Result<()> {
    let prefix = prefix.to_string();
    let output = Command::new("ip")
        .args([
            "-6", "route", "show", "table", "local", "type", "local", &prefix,
        ])
        .output()
        .map_err(|err| {
            HeRouterError::Config(format!("failed to run ip route validation: {err}"))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(HeRouterError::Config(format!(
            "failed to validate local IPv6 route for {prefix}: {stderr}"
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout
        .lines()
        .any(|line| line.contains(&prefix) && line.contains("local"))
    {
        return Ok(());
    }
    Err(HeRouterError::Config(format!(
        "he-router requires local IPv6 route: ip -6 route replace local {prefix} dev lo table local"
    )))
}

fn prune_bindings(bindings: &mut HashMap<String, BindingMetadata>, now_ms: i64, grace_ms: u64) {
    let grace_ms = i64::try_from(grace_ms).unwrap_or(i64::MAX);
    bindings.retain(|_, binding| {
        binding
            .expires_at_ms
            .map(|expires_at_ms| expires_at_ms.saturating_add(grace_ms) > now_ms)
            .unwrap_or(true)
    });
}

fn prune_client_cache(
    clients: &mut HashMap<ClientCacheKey, CachedClient>,
    now: Instant,
    idle_timeout_seconds: u64,
) {
    let idle_timeout = Duration::from_secs(idle_timeout_seconds);
    clients.retain(|_, entry| now.duration_since(entry.last_used_at) <= idle_timeout);
}

fn enforce_client_cache_limit(
    clients: &mut HashMap<ClientCacheKey, CachedClient>,
    max_entries: usize,
) {
    while clients.len() > max_entries {
        let Some(oldest_key) = clients
            .iter()
            .min_by_key(|(_, entry)| entry.last_used_at)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        clients.remove(&oldest_key);
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(chars);
    for byte in bytes {
        if out.len() >= chars {
            break;
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        if out.len() >= chars {
            break;
        }
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn now_ms() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HeRouterConfig {
        HeRouterConfig {
            enabled: true,
            ipv6_prefix: "2001:470:f41e::/48".to_string(),
            require_kernel_ready: false,
            binding_salt: "unit-test-salt".to_string(),
            max_client_cache_entries: 2,
            ..HeRouterConfig::default()
        }
    }

    #[test]
    fn prefix_parser_masks_host_bits() {
        let prefix: Ipv6Prefix = "2001:470:f41e:ffff::1/48".parse().unwrap();
        assert_eq!(prefix.to_string(), "2001:470:f41e::/48");
        assert!(prefix.contains("2001:470:f41e:d4a9::1".parse().unwrap()));
        assert!(!prefix.contains("2001:470:f41f::1".parse().unwrap()));
    }

    #[test]
    fn same_access_token_derives_same_source_ipv6() {
        let router = HeRouter::new(config()).unwrap();
        let first = router
            .derive_source_ip("42", Some("token-a"))
            .unwrap()
            .unwrap();
        let second = router
            .derive_source_ip("42", Some("token-a"))
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_access_tokens_normally_derive_different_source_ipv6() {
        let router = HeRouter::new(config()).unwrap();
        let first = router
            .derive_source_ip("42", Some("token-a"))
            .unwrap()
            .unwrap();
        let second = router
            .derive_source_ip("42", Some("token-b"))
            .unwrap()
            .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn derived_source_ipv6_stays_inside_prefix() {
        let cfg = config();
        let prefix: Ipv6Prefix = cfg.ipv6_prefix.parse().unwrap();
        let router = HeRouter::new(cfg).unwrap();
        let source_ip = router
            .derive_source_ip("42", Some("token-a"))
            .unwrap()
            .unwrap();
        assert!(prefix.contains(source_ip));
    }

    #[test]
    fn access_token_scope_without_token_returns_none() {
        let router = HeRouter::new(config()).unwrap();
        assert!(router.derive_source_ip("42", None).unwrap().is_none());
    }

    #[test]
    fn account_scope_does_not_need_token() {
        let mut cfg = config();
        cfg.binding_scope = BindingScope::Account;
        let router = HeRouter::new(cfg).unwrap();
        assert!(router.derive_source_ip("42", None).unwrap().is_some());
    }

    #[test]
    fn example_config_uses_typed_toml_enums() {
        let cfg: HeRouterConfig = toml::from_str(include_str!("../config.toml.example")).unwrap();
        assert_eq!(cfg.mode, HeRouterMode::NativeNonlocalBind);
        assert_eq!(cfg.binding_namespace, "he-router");
        assert_eq!(cfg.binding_scope, BindingScope::AccessToken);
        assert_eq!(cfg.server.listen_port, "[::]:7443");
        assert_eq!(cfg.client.server_addr, "your-vps.example.com:7443");
    }

    #[test]
    fn namespace_and_raw_salt_material_preserve_legacy_derivation() {
        let mut cfg = config();
        cfg.binding_namespace = "openai".to_string();
        cfg.binding_salt.clear();
        let salt_material = Sha256::digest(b"tt:magic-access:auth-secret").to_vec();
        let router = HeRouter::with_salt_material(cfg.clone(), salt_material.clone()).unwrap();
        let source_ip = router
            .derive_source_ip("42", Some("token-a"))
            .unwrap()
            .unwrap();

        let prefix: Ipv6Prefix = cfg.ipv6_prefix.parse().unwrap();
        let binding_digest = Sha256::digest(b"openai:42:token-a");
        let expected = derive_source_ipv6(prefix, &salt_material, &binding_digest);
        assert_eq!(source_ip, expected);
    }

    #[test]
    fn prepare_plan_is_explicit_and_replayable() {
        let plan = kernel_prepare_plan(&config()).unwrap().unwrap();
        let commands = plan.shell_commands();
        assert_eq!(commands[0], "sudo sysctl -w net.ipv6.ip_nonlocal_bind=1");
        assert_eq!(
            commands[2],
            "sudo ip -6 route replace local 2001:470:f41e::/48 dev lo table local"
        );
        assert!(
            plan.systemd_unit(Some("tt.service"))
                .contains("Before=tt.service")
        );
    }

    #[test]
    fn proxy_conflict_fails_closed_by_default() {
        let router = HeRouter::new(config()).unwrap();
        let err = router
            .route(RouteRequest {
                account_id: "42",
                access_token: Some("token-a"),
                upstream_url: "https://chatgpt.com/backend-api/codex/responses",
                timeout: Duration::from_secs(30),
                tls_backend: TlsBackend::Default,
                proxy_url: Some("http://127.0.0.1:8899"),
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("allow_proxy"));
    }

    #[test]
    fn debug_output_does_not_include_raw_access_token() {
        let request = RouteRequest {
            account_id: "42",
            access_token: Some("secret-token-should-not-leak"),
            upstream_url: "https://chatgpt.com/backend-api/codex/responses",
            timeout: Duration::from_secs(30),
            tls_backend: TlsBackend::Default,
            proxy_url: None,
        };
        assert!(!format!("{request:?}").contains("secret-token-should-not-leak"));
    }

    #[test]
    fn client_cache_key_includes_source_ipv6() {
        let left = ClientCacheKey::new(
            "2001:470:f41e::1".parse().unwrap(),
            "https://chatgpt.com:443".to_string(),
            Duration::from_secs(30),
            TlsBackend::Default,
            None,
        );
        let right = ClientCacheKey::new(
            "2001:470:f41e::2".parse().unwrap(),
            "https://chatgpt.com:443".to_string(),
            Duration::from_secs(30),
            TlsBackend::Default,
            None,
        );
        assert_ne!(left, right);
    }
}
