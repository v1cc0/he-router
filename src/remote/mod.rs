use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    EmbeddedClientConfig, EmbeddedClientProxyConfig, EmbeddedServerConfig, HeRouter,
    HeRouterConfig, HeRouterError, Result,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

mod client;
mod proxy;
mod server;

pub use client::{
    ClientCommandOptions, RemoteTunnelClient, RemoteTunnelSession, ReusableRemoteTunnel,
    run_client_command,
};
pub use proxy::{ClientProxyOptions, run_client_proxy};
pub use server::{RemoteServerOptions, run_server};

pub const ALPN_HE_ROUTER: &[u8] = b"he-router/1";
pub const MAX_PROXY_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
static INSTALL_RUSTLS_PROVIDER: Once = Once::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteHttpRequest {
    pub request_id: String,
    pub auth_token: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderPair>,
    pub body: Vec<u8>,
    pub timeout_ms: u64,
    pub tunnel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteHttpResponse {
    pub status: u16,
    pub headers: Vec<HeaderPair>,
    pub body: Vec<u8>,
    pub source_ip: Option<String>,
    pub error: Option<String>,
    pub tunnel_established: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteClientConfig {
    pub server_addr: String,
    pub server_name: String,
    pub auth_token: String,
    pub ca_cert_path: PathBuf,
    pub bind_addr: String,
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteClientProxyConfig {
    pub listen: String,
}

impl Default for RemoteClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:7443".to_string(),
            server_name: "localhost".to_string(),
            auth_token: String::new(),
            ca_cert_path: PathBuf::from("ca-cert.pem"),
            bind_addr: "[::]:0".to_string(),
            request_timeout_seconds: 60,
        }
    }
}

impl RemoteClientConfig {
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let config = HeRouterConfig::load_from(path)?;
        Self::from_embedded(&config.client)
    }

    pub fn validate(&self) -> Result<()> {
        if self.server_addr.trim().is_empty() {
            return Err(HeRouterError::Config(
                "remote client server_addr must not be empty".to_string(),
            ));
        }
        if self.server_name.trim().is_empty() {
            return Err(HeRouterError::Config(
                "remote client server_name must not be empty".to_string(),
            ));
        }
        if self.auth_token.trim().is_empty() {
            return Err(HeRouterError::Config(
                "remote client auth_token must not be empty".to_string(),
            ));
        }
        if self.request_timeout_seconds == 0 {
            return Err(HeRouterError::Config(
                "remote client request_timeout_seconds must be > 0".to_string(),
            ));
        }
        if self.bind_addr.trim().parse::<SocketAddr>().is_err() {
            return Err(HeRouterError::Config(format!(
                "invalid remote client bind_addr {}",
                self.bind_addr
            )));
        }
        Ok(())
    }

    pub fn from_embedded(config: &EmbeddedClientConfig) -> Result<Self> {
        let config = Self {
            server_addr: config.server_addr.clone(),
            server_name: config.server_name.clone(),
            auth_token: config.auth_token.clone(),
            ca_cert_path: if config.ca_cert_path.trim().is_empty() {
                PathBuf::from("ca-cert.pem")
            } else {
                PathBuf::from(config.ca_cert_path.trim())
            },
            bind_addr: if config.bind_addr.trim().is_empty() {
                "[::]:0".to_string()
            } else {
                config.bind_addr.clone()
            },
            request_timeout_seconds: if config.request_timeout_seconds == 0 {
                60
            } else {
                config.request_timeout_seconds
            },
        };
        config.validate()?;
        Ok(config)
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        self.bind_addr
            .parse()
            .map_err(|err| HeRouterError::Config(format!("invalid remote client bind_addr: {err}")))
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }

    pub fn write_example(path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, include_str!("../../remote-client.toml.example"))?;
        Ok(())
    }
}

impl RemoteClientProxyConfig {
    pub fn from_embedded(config: &EmbeddedClientProxyConfig) -> Self {
        Self {
            listen: if config.listen.trim().is_empty() {
                "127.0.0.1:8787".to_string()
            } else {
                config.listen.clone()
            },
        }
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen.parse().map_err(|err| {
            HeRouterError::Config(format!("invalid remote client proxy listen address: {err}"))
        })
    }
}

pub fn request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("req-{nanos}")
}

pub fn server_router_config(config: &HeRouterConfig) -> HeRouterConfig {
    let mut config = config.clone();
    config.binding_scope = crate::BindingScope::Account;
    if config.binding_namespace == "he-router" {
        config.binding_namespace = "he-router-remote".to_string();
    }
    config
}

pub fn server_options_from_embedded(config: &EmbeddedServerConfig) -> Result<RemoteServerOptions> {
    let listen = if config.listen_port.trim().is_empty() {
        "[::]:7443".parse().map_err(|err| {
            HeRouterError::Config(format!("invalid default server listen_port: {err}"))
        })?
    } else {
        config
            .listen_port
            .parse()
            .map_err(|err| HeRouterError::Config(format!("invalid server listen_port: {err}")))?
    };

    Ok(RemoteServerOptions {
        listen,
        cert_path: PathBuf::from(config.cert.trim()),
        key_path: PathBuf::from(config.key.trim()),
        auth_token: config.auth_token.trim().to_string(),
    })
}

pub fn build_server_config(cert_path: &Path, key_path: &Path) -> Result<quinn::ServerConfig> {
    ensure_rustls_provider_installed();
    let key_raw = fs::read(key_path)?;
    let key = if key_path.extension().is_some_and(|ext| ext == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_raw))
    } else {
        rustls_pemfile::private_key(&mut &*key_raw)
            .map_err(|err| HeRouterError::Protocol(format!("invalid private key: {err}")))?
            .ok_or_else(|| HeRouterError::Config("no private key found".to_string()))?
    };

    let cert_raw = fs::read(cert_path)?;
    let certs = if cert_path.extension().is_some_and(|ext| ext == "der") {
        vec![CertificateDer::from(cert_raw)]
    } else {
        rustls_pemfile::certs(&mut &*cert_raw)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| HeRouterError::Protocol(format!("invalid certificate: {err}")))?
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| {
            HeRouterError::Protocol(format!("failed building rustls server config: {err}"))
        })?;
    server_crypto.alpn_protocols = vec![ALPN_HE_ROUTER.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).map_err(|err| {
            HeRouterError::Protocol(format!("failed building QUIC server config: {err}"))
        })?,
    ));
    if let Some(transport) = Arc::get_mut(&mut server_config.transport) {
        transport.max_concurrent_uni_streams(0_u8.into());
    }
    Ok(server_config)
}

pub fn build_client_config(client: &RemoteClientConfig) -> Result<quinn::ClientConfig> {
    ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    let cert_raw = fs::read(&client.ca_cert_path)?;
    if client
        .ca_cert_path
        .extension()
        .is_some_and(|ext| ext == "der")
    {
        roots
            .add(CertificateDer::from(cert_raw))
            .map_err(|err| HeRouterError::Protocol(format!("failed adding CA cert: {err}")))?;
    } else {
        for cert in rustls_pemfile::certs(&mut &*cert_raw) {
            let cert =
                cert.map_err(|err| HeRouterError::Protocol(format!("invalid CA cert: {err}")))?;
            roots
                .add(cert)
                .map_err(|err| HeRouterError::Protocol(format!("failed adding CA cert: {err}")))?;
        }
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN_HE_ROUTER.to_vec()];

    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(|err| {
            HeRouterError::Protocol(format!("failed building QUIC client config: {err}"))
        })?,
    )))
}

pub fn map_async_error(label: &str, err: impl std::fmt::Display) -> HeRouterError {
    HeRouterError::Protocol(format!("{label}: {err}"))
}

pub async fn write_envelope<T>(send: &mut quinn::SendStream, value: &T) -> Result<()>
where
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| HeRouterError::Protocol("control envelope too large to encode".to_string()))?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|err| map_async_error("failed writing envelope length", err))?;
    send.write_all(&payload)
        .await
        .map_err(|err| map_async_error("failed writing envelope payload", err))?;
    Ok(())
}

pub async fn read_envelope<T>(recv: &mut quinn::RecvStream) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut header = [0u8; 4];
    recv.read_exact(&mut header)
        .await
        .map_err(|err| map_async_error("failed reading envelope length", err))?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_PROXY_MESSAGE_BYTES {
        return Err(HeRouterError::Protocol(format!(
            "control envelope length {length} exceeds safety limit"
        )));
    }
    let mut payload = vec![0u8; length];
    recv.read_exact(&mut payload)
        .await
        .map_err(|err| map_async_error("failed reading envelope payload", err))?;
    Ok(serde_json::from_slice(&payload)?)
}

fn ensure_rustls_provider_installed() {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn build_server_router(config_path: &Path) -> Result<HeRouter> {
    let config = HeRouterConfig::load_from(config_path)?;
    HeRouter::new(server_router_config(&config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_client_config_defaults_are_valid() {
        let config = RemoteClientConfig {
            auth_token: "token".to_string(),
            ..RemoteClientConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn request_ids_have_prefix() {
        assert!(request_id().starts_with("req-"));
    }

    #[test]
    fn remote_client_example_parses_from_client_section() {
        let path = std::env::temp_dir().join(format!("he-router-client-{}.toml", request_id()));
        fs::write(&path, include_str!("../../remote-client.toml.example")).unwrap();
        let parsed = RemoteClientConfig::load_from(&path).unwrap();
        assert_eq!(parsed.server_addr, "your-vps.example.com:7443");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn remote_client_proxy_defaults_to_local_listener() {
        let proxy = RemoteClientProxyConfig::from_embedded(&EmbeddedClientProxyConfig::default());
        assert_eq!(proxy.listen, "127.0.0.1:8787");
    }

    #[test]
    fn remote_client_example_includes_proxy_section() {
        let path =
            std::env::temp_dir().join(format!("he-router-client-proxy-{}.toml", request_id()));
        fs::write(&path, include_str!("../../remote-client.toml.example")).unwrap();
        let full: HeRouterConfig = HeRouterConfig::load_from(&path).unwrap();
        let proxy = RemoteClientProxyConfig::from_embedded(&full.client_proxy);
        assert_eq!(proxy.listen, "127.0.0.1:8787");
        let _ = fs::remove_file(path);
    }
}
