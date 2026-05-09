use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use quinn::Endpoint;

use super::{
    RemoteClientConfig, RemoteHttpRequest, RemoteHttpResponse, build_client_config,
    map_async_error, request_id,
};
use crate::{HeRouterError, Result};

#[derive(Debug, Clone)]
pub struct ClientCommandOptions {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct RemoteTunnelClient {
    config: RemoteClientConfig,
}

impl RemoteTunnelClient {
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let config = RemoteClientConfig::load_from(path)?;
        Ok(Self { config })
    }

    pub fn from_config(config: RemoteClientConfig) -> Self {
        Self { config }
    }

    pub async fn request(&self, options: ClientCommandOptions) -> Result<RemoteHttpResponse> {
        let remote = resolve_remote(&self.config.server_addr)?;
        let mut endpoint = Endpoint::client(self.config.bind_addr()?).map_err(|err| {
            HeRouterError::Protocol(format!("failed to create QUIC client endpoint: {err}"))
        })?;
        endpoint.set_default_client_config(build_client_config(&self.config)?);

        let connection = endpoint
            .connect(remote, self.config.server_name.trim())
            .map_err(|err| HeRouterError::Protocol(format!("failed to start QUIC connect: {err}")))?
            .await
            .map_err(|err| map_async_error("failed to establish QUIC connection", err))?;

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|err| map_async_error("failed to open QUIC stream", err))?;

        let request = RemoteHttpRequest {
            request_id: request_id(),
            auth_token: self.config.auth_token.clone(),
            method: options.method,
            url: options.url,
            headers: options
                .headers
                .into_iter()
                .map(|(name, value)| super::HeaderPair { name, value })
                .collect(),
            body: options.body,
            timeout_ms: duration_ms(self.config.request_timeout()),
        };

        let payload = serde_json::to_vec(&request)?;
        send.write_all(&payload)
            .await
            .map_err(|err| map_async_error("failed to write QUIC request", err))?;
        send.finish()
            .map_err(|err| map_async_error("failed to finish QUIC request stream", err))?;

        let response = recv
            .read_to_end(super::MAX_PROXY_MESSAGE_BYTES)
            .await
            .map_err(|err| map_async_error("failed to read QUIC response", err))?;
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;

        let response: RemoteHttpResponse = serde_json::from_slice(&response)?;
        Ok(response)
    }
}

pub async fn run_client_command(
    config_path: &Path,
    options: ClientCommandOptions,
) -> Result<RemoteHttpResponse> {
    let client = RemoteTunnelClient::load_from(config_path)?;
    client.request(options).await
}

fn resolve_remote(server_addr: &str) -> Result<SocketAddr> {
    server_addr
        .to_socket_addrs()
        .map_err(|err| {
            HeRouterError::Config(format!("failed to resolve remote server_addr: {err}"))
        })?
        .next()
        .ok_or_else(|| {
            HeRouterError::Config("remote server_addr resolved to no address".to_string())
        })
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
