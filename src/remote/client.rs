use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::Mutex;

use super::{
    RemoteClientConfig, RemoteHttpRequest, RemoteHttpResponse, build_client_config,
    map_async_error, read_envelope, request_id, write_envelope,
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

    pub async fn connect(&self) -> Result<RemoteTunnelSession> {
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

        Ok(RemoteTunnelSession {
            config: self.config.clone(),
            endpoint,
            connection,
        })
    }

    pub async fn request(&self, options: ClientCommandOptions) -> Result<RemoteHttpResponse> {
        let session = self.connect().await?;
        let response = session.request(options).await?;
        session.close().await;
        Ok(response)
    }
}

pub struct ReusableRemoteTunnel {
    client: RemoteTunnelClient,
    session: Mutex<Option<RemoteTunnelSession>>,
}

impl ReusableRemoteTunnel {
    pub fn from_config(config: RemoteClientConfig) -> Self {
        Self {
            client: RemoteTunnelClient::from_config(config),
            session: Mutex::new(None),
        }
    }

    pub async fn request(&self, options: ClientCommandOptions) -> Result<RemoteHttpResponse> {
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.ensure_session().await?;
            match session.request(options.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) if should_reconnect(&err) && attempt == 0 => {
                    self.reset_session().await;
                    last_error = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            HeRouterError::Protocol("request retry logic exhausted unexpectedly".to_string())
        }))
    }

    pub async fn open_connect_tunnel(
        &self,
        authority: &str,
        headers: Vec<(String, String)>,
    ) -> Result<(SendStream, RecvStream, RemoteHttpResponse)> {
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.ensure_session().await?;
            match session
                .open_connect_tunnel(authority, headers.clone())
                .await
            {
                Ok(result) => return Ok(result),
                Err(err) if should_reconnect(&err) && attempt == 0 => {
                    self.reset_session().await;
                    last_error = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            HeRouterError::Protocol("CONNECT retry logic exhausted unexpectedly".to_string())
        }))
    }

    async fn ensure_session(&self) -> Result<RemoteTunnelSession> {
        let mut guard = self.session.lock().await;
        if guard.is_none() {
            *guard = Some(self.client.connect().await?);
        }
        guard
            .clone()
            .ok_or_else(|| HeRouterError::Protocol("session unexpectedly missing".to_string()))
    }

    async fn reset_session(&self) {
        let session = self.session.lock().await.take();
        if let Some(session) = session {
            session.close().await;
        }
    }
}

#[derive(Clone)]
pub struct RemoteTunnelSession {
    config: RemoteClientConfig,
    endpoint: Endpoint,
    connection: Connection,
}

impl RemoteTunnelSession {
    pub async fn request(&self, options: ClientCommandOptions) -> Result<RemoteHttpResponse> {
        let (mut send, mut recv) = self
            .connection
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
            tunnel: false,
        };

        write_envelope(&mut send, &request).await?;
        send.finish()
            .map_err(|err| map_async_error("failed to finish QUIC request stream", err))?;

        let response: RemoteHttpResponse = read_envelope(&mut recv).await?;
        Ok(response)
    }

    pub async fn open_connect_tunnel(
        &self,
        authority: &str,
        headers: Vec<(String, String)>,
    ) -> Result<(SendStream, RecvStream, RemoteHttpResponse)> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|err| map_async_error("failed to open QUIC stream", err))?;

        let request = RemoteHttpRequest {
            request_id: request_id(),
            auth_token: self.config.auth_token.clone(),
            method: "CONNECT".to_string(),
            url: authority.to_string(),
            headers: headers
                .into_iter()
                .map(|(name, value)| super::HeaderPair { name, value })
                .collect(),
            body: Vec::new(),
            timeout_ms: duration_ms(self.config.request_timeout()),
            tunnel: true,
        };

        write_envelope(&mut send, &request).await?;
        let response: RemoteHttpResponse = read_envelope(&mut recv).await?;
        Ok((send, recv, response))
    }

    pub async fn close(&self) {
        self.connection.close(0u32.into(), b"done");
        self.endpoint.wait_idle().await;
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

fn should_reconnect(err: &HeRouterError) -> bool {
    match err {
        HeRouterError::Protocol(message) => {
            message.contains("connection lost")
                || message.contains("failed to open QUIC stream")
                || message.contains("ApplicationClosed")
                || message.contains("ConnectionLost")
                || message.contains("0-RTT rejected")
        }
        _ => false,
    }
}
