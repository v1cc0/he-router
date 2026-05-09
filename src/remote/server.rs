use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use quinn::Endpoint;
use reqwest::Method;

use super::{
    RemoteHttpRequest, RemoteHttpResponse, build_server_config, build_server_router,
    map_async_error,
};
use crate::{Result, RouteRequest, TlsBackend};

#[derive(Debug, Clone)]
pub struct RemoteServerOptions {
    pub listen: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub auth_token: String,
}

impl RemoteServerOptions {
    pub fn validate(&self) -> Result<()> {
        if self.auth_token.trim().is_empty() {
            return Err(crate::HeRouterError::Config(
                "remote server auth token must not be empty".to_string(),
            ));
        }
        if !self.cert_path.exists() {
            return Err(crate::HeRouterError::Config(format!(
                "remote server certificate not found: {}",
                self.cert_path.display()
            )));
        }
        if !self.key_path.exists() {
            return Err(crate::HeRouterError::Config(format!(
                "remote server private key not found: {}",
                self.key_path.display()
            )));
        }
        Ok(())
    }
}

pub async fn run_server(config_path: &Path, options: RemoteServerOptions) -> Result<()> {
    options.validate()?;
    let router = Arc::new(build_server_router(config_path)?);
    let endpoint = Endpoint::server(
        build_server_config(&options.cert_path, &options.key_path)?,
        options.listen,
    )
    .map_err(|err| crate::HeRouterError::Protocol(format!("failed to bind QUIC server: {err}")))?;

    eprintln!(
        "he-router remote server listening on {}",
        endpoint.local_addr().map_err(crate::HeRouterError::Io)?
    );

    while let Some(incoming) = endpoint.accept().await {
        let router = Arc::clone(&router);
        let auth_token = options.auth_token.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(router, auth_token, incoming).await {
                eprintln!("he-router remote connection failed: {err}");
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    router: Arc<crate::HeRouter>,
    auth_token: String,
    incoming: quinn::Incoming,
) -> Result<()> {
    let connection = incoming
        .await
        .map_err(|err| map_async_error("failed to accept QUIC connection", err))?;

    loop {
        let stream = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
            Err(err) => return Err(map_async_error("failed accepting QUIC stream", err)),
        };

        let router = Arc::clone(&router);
        let auth_token = auth_token.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(router, auth_token, stream).await {
                eprintln!("he-router remote stream failed: {err}");
            }
        });
    }
}

async fn handle_stream(
    router: Arc<crate::HeRouter>,
    auth_token: String,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let request_bytes = recv
        .read_to_end(super::MAX_PROXY_MESSAGE_BYTES)
        .await
        .map_err(|err| map_async_error("failed reading QUIC request", err))?;
    let request: RemoteHttpRequest = serde_json::from_slice(&request_bytes)?;

    let response = proxy_request(router.as_ref(), &auth_token, request).await;
    let payload = serde_json::to_vec(&response)?;
    send.write_all(&payload)
        .await
        .map_err(|err| map_async_error("failed writing QUIC response", err))?;
    send.finish()
        .map_err(|err| map_async_error("failed finishing QUIC response", err))?;
    Ok(())
}

async fn proxy_request(
    router: &crate::HeRouter,
    expected_auth_token: &str,
    request: RemoteHttpRequest,
) -> RemoteHttpResponse {
    if request.auth_token != expected_auth_token {
        return RemoteHttpResponse {
            status: 401,
            headers: Vec::new(),
            body: Vec::new(),
            source_ip: None,
            error: Some("unauthorized".to_string()),
        };
    }

    let timeout = std::time::Duration::from_millis(request.timeout_ms.max(1));
    let decision = match router.route(RouteRequest {
        account_id: &request.request_id,
        access_token: None,
        upstream_url: &request.url,
        timeout,
        tls_backend: TlsBackend::Default,
        proxy_url: None,
    }) {
        Ok(Some(decision)) => decision,
        Ok(None) => {
            return RemoteHttpResponse {
                status: 503,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: None,
                error: Some("no route decision available".to_string()),
            };
        }
        Err(err) => {
            return RemoteHttpResponse {
                status: 500,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: None,
                error: Some(err.to_string()),
            };
        }
    };

    let method = match Method::from_str(&request.method) {
        Ok(method) => method,
        Err(err) => {
            return RemoteHttpResponse {
                status: 400,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: Some(decision.source_ip.to_string()),
                error: Some(format!("invalid HTTP method: {err}")),
            };
        }
    };

    let mut builder = decision.client.request(method, &request.url);
    for header in &request.headers {
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }
    if !request.body.is_empty() {
        builder = builder.body(request.body.clone());
    }

    match builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value.to_str().ok().map(|value| super::HeaderPair {
                        name: name.to_string(),
                        value: value.to_string(),
                    })
                })
                .collect::<Vec<_>>();
            match response.bytes().await {
                Ok(body) => RemoteHttpResponse {
                    status,
                    headers,
                    body: body.to_vec(),
                    source_ip: Some(decision.source_ip.to_string()),
                    error: None,
                },
                Err(err) => RemoteHttpResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: Vec::new(),
                    source_ip: Some(decision.source_ip.to_string()),
                    error: Some(format!("failed to read upstream body: {err}")),
                },
            }
        }
        Err(err) => RemoteHttpResponse {
            status: 502,
            headers: Vec::new(),
            body: Vec::new(),
            source_ip: Some(decision.source_ip.to_string()),
            error: Some(format!("failed to proxy upstream request: {err}")),
        },
    }
}
