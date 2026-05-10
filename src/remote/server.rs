use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use quinn::Endpoint;
use reqwest::Method;
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpSocket, TcpStream, lookup_host};

use super::{
    RemoteHttpRequest, RemoteHttpResponse, build_server_config, build_server_router,
    map_async_error, read_envelope, write_envelope,
};
use crate::{HeRouterError, Result, RouteRequest, TlsBackend};

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
    let peer = incoming.remote_address();
    let local_ip = incoming.local_ip();
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(err) => {
            eprintln!(
                "he-router remote connection failed peer={peer} local_ip={} stage=accept_handshake reason={}",
                format_optional_ip(local_ip),
                describe_connection_error(&err)
            );
            return Ok(());
        }
    };
    let connection_id = connection.stable_id();
    eprintln!(
        "he-router remote connection established peer={peer} conn_id={connection_id} local_ip={}",
        format_optional_ip(local_ip)
    );

    loop {
        let stream = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "he-router remote connection closed peer={peer} conn_id={connection_id} stage=accept_stream reason={}",
                    describe_connection_error(&err)
                );
                return Ok(());
            }
        };

        let router = Arc::clone(&router);
        let auth_token = auth_token.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(router, auth_token, stream, peer, connection_id).await {
                eprintln!(
                    "he-router remote stream failed peer={peer} conn_id={connection_id}: {err}"
                );
            }
        });
    }
}

async fn handle_stream(
    router: Arc<crate::HeRouter>,
    auth_token: String,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    peer: SocketAddr,
    connection_id: usize,
) -> Result<()> {
    let request: RemoteHttpRequest = read_envelope(&mut recv).await?;

    if request.auth_token != auth_token {
        eprintln!(
            "he-router remote stream unauthorized peer={peer} conn_id={connection_id} request_id={} method={} target={}",
            request.request_id, request.method, request.url
        );
        let response = RemoteHttpResponse {
            status: 401,
            headers: Vec::new(),
            body: Vec::new(),
            source_ip: None,
            error: Some("unauthorized".to_string()),
            tunnel_established: false,
        };
        write_envelope(&mut send, &response).await?;
        send.finish()
            .map_err(|err| map_async_error("failed finishing unauthorized response", err))?;
        return Ok(());
    }

    if request.tunnel || request.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect_stream(router, request, send, recv, peer, connection_id).await
    } else {
        let response = proxy_http_request(router.as_ref(), request, peer, connection_id).await;
        write_envelope(&mut send, &response).await?;
        send.finish()
            .map_err(|err| map_async_error("failed finishing QUIC response", err))?;
        Ok(())
    }
}

async fn handle_connect_stream(
    router: Arc<crate::HeRouter>,
    request: RemoteHttpRequest,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    connection_id: usize,
) -> Result<()> {
    let source_ip = router
        .derive_source_ip(&request.request_id, None)?
        .ok_or_else(|| {
            HeRouterError::Protocol("no source IPv6 available for CONNECT tunnel".to_string())
        })?;
    eprintln!(
        "he-router remote assigned source IPv6 peer={peer} conn_id={connection_id} request_id={} method=CONNECT authority={} source_ip={} timeout_ms={}",
        request.request_id, request.url, source_ip, request.timeout_ms
    );

    let upstream = match connect_upstream_with_source(source_ip, &request.url).await {
        Ok((stream, used_source_ip)) => {
            eprintln!(
                "he-router remote CONNECT established peer={peer} conn_id={connection_id} request_id={} authority={} assigned_source_ip={} socket_local_ip={}",
                request.request_id, request.url, source_ip, used_source_ip
            );
            let response = RemoteHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: Some(used_source_ip.to_string()),
                error: None,
                tunnel_established: true,
            };
            write_envelope(&mut send, &response).await?;
            stream
        }
        Err(err) => {
            eprintln!(
                "he-router remote CONNECT failed peer={peer} conn_id={connection_id} request_id={} authority={} source_ip={} reason={err}",
                request.request_id, request.url, source_ip
            );
            let response = RemoteHttpResponse {
                status: 502,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: Some(source_ip.to_string()),
                error: Some(err.to_string()),
                tunnel_established: false,
            };
            write_envelope(&mut send, &response).await?;
            send.finish().map_err(|finish_err| {
                map_async_error("failed finishing failed CONNECT response", finish_err)
            })?;
            return Ok(());
        }
    };

    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_upstream = async {
        copy(&mut recv, &mut upstream_write).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed relaying QUIC tunnel to upstream: {err}"))
        })?;
        upstream_write.shutdown().await.ok();
        Ok::<(), HeRouterError>(())
    };

    let upstream_to_client = async {
        copy(&mut upstream_read, &mut send).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed relaying upstream tunnel to QUIC: {err}"))
        })?;
        send.finish()
            .map_err(|err| map_async_error("failed finishing CONNECT tunnel send stream", err))?;
        Ok::<(), HeRouterError>(())
    };

    let _ = tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok(())
}

async fn proxy_http_request(
    router: &crate::HeRouter,
    request: RemoteHttpRequest,
    peer: SocketAddr,
    connection_id: usize,
) -> RemoteHttpResponse {
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
                tunnel_established: false,
            };
        }
        Err(err) => {
            return RemoteHttpResponse {
                status: 500,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: None,
                error: Some(err.to_string()),
                tunnel_established: false,
            };
        }
    };
    eprintln!(
        "he-router remote assigned source IPv6 peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} binding_key_prefix={} timeout_ms={}",
        request.request_id,
        request.method,
        request.url,
        decision.source_ip,
        decision.binding_key_prefix,
        request.timeout_ms
    );

    let method = match Method::from_str(&request.method) {
        Ok(method) => method,
        Err(err) => {
            return RemoteHttpResponse {
                status: 400,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: Some(decision.source_ip.to_string()),
                error: Some(format!("invalid HTTP method: {err}")),
                tunnel_established: false,
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
            eprintln!(
                "he-router remote HTTP upstream responded peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} status={}",
                request.request_id, request.method, request.url, decision.source_ip, status
            );
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
                    tunnel_established: false,
                },
                Err(err) => {
                    eprintln!(
                        "he-router remote HTTP body read failed peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} reason={err}",
                        request.request_id, request.method, request.url, decision.source_ip
                    );
                    RemoteHttpResponse {
                        status: 502,
                        headers: Vec::new(),
                        body: Vec::new(),
                        source_ip: Some(decision.source_ip.to_string()),
                        error: Some(format!("failed to read upstream body: {err}")),
                        tunnel_established: false,
                    }
                }
            }
        }
        Err(err) => {
            eprintln!(
                "he-router remote HTTP upstream failed peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} reason={err}",
                request.request_id, request.method, request.url, decision.source_ip
            );
            RemoteHttpResponse {
                status: 502,
                headers: Vec::new(),
                body: Vec::new(),
                source_ip: Some(decision.source_ip.to_string()),
                error: Some(format!("failed to proxy upstream request: {err}")),
                tunnel_established: false,
            }
        }
    }
}

async fn connect_upstream_with_source(
    source_ip: std::net::Ipv6Addr,
    authority: &str,
) -> Result<(TcpStream, std::net::IpAddr)> {
    let mut last_err = None;
    let mut resolved = lookup_host(authority)
        .await
        .map_err(|err| {
            HeRouterError::Protocol(format!(
                "failed resolving CONNECT authority {authority}: {err}"
            ))
        })?
        .collect::<Vec<_>>();
    resolved.sort_by_key(|addr| !addr.is_ipv6());

    for addr in resolved {
        match connect_candidate(source_ip, addr).await {
            Ok(stream) => {
                let local_ip = stream.local_addr().map_err(HeRouterError::Io)?.ip();
                return Ok((stream, local_ip));
            }
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        HeRouterError::Protocol(format!(
            "CONNECT authority {authority} resolved to no usable addresses"
        ))
    }))
}

async fn connect_candidate(source_ip: std::net::Ipv6Addr, addr: SocketAddr) -> Result<TcpStream> {
    match addr.ip() {
        IpAddr::V6(_) => {
            let socket = TcpSocket::new_v6().map_err(HeRouterError::Io)?;
            socket
                .bind(SocketAddr::new(IpAddr::V6(source_ip), 0))
                .map_err(HeRouterError::Io)?;
            socket.connect(addr).await.map_err(HeRouterError::Io)
        }
        IpAddr::V4(_) => {
            let socket = TcpSocket::new_v4().map_err(HeRouterError::Io)?;
            socket.connect(addr).await.map_err(HeRouterError::Io)
        }
    }
}

fn format_optional_ip(ip: Option<IpAddr>) -> String {
    ip.map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn describe_connection_error(err: &quinn::ConnectionError) -> String {
    match err {
        quinn::ConnectionError::VersionMismatch => {
            "version_mismatch: peer does not support a QUIC version accepted by this server"
                .to_string()
        }
        quinn::ConnectionError::TransportError(error) => format!(
            "transport_error: code={:?} frame={:?} detail={}",
            error.code, error.frame, error
        ),
        quinn::ConnectionError::ConnectionClosed(close) => format!(
            "transport_closed_by_peer: code={:?} frame={:?} reason={}",
            close.error_code,
            close.frame_type,
            String::from_utf8_lossy(&close.reason)
        ),
        quinn::ConnectionError::ApplicationClosed(close) => format!(
            "application_closed_by_peer: code={} reason={}",
            close.error_code,
            String::from_utf8_lossy(&close.reason)
        ),
        quinn::ConnectionError::Reset => {
            "reset_by_peer: peer endpoint, NAT, or network path reset the QUIC connection"
                .to_string()
        }
        quinn::ConnectionError::TimedOut => {
            "idle_timeout: no QUIC packets were received before the negotiated idle timeout; this can happen when the reusable local proxy tunnel sits idle or the network path drops UDP"
                .to_string()
        }
        quinn::ConnectionError::LocallyClosed => {
            "locally_closed: this process closed the QUIC connection".to_string()
        }
        quinn::ConnectionError::CidsExhausted => {
            "cid_exhausted: not enough QUIC connection IDs were available".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_out_connection_error_names_idle_reason() {
        let detail = describe_connection_error(&quinn::ConnectionError::TimedOut);
        assert!(detail.contains("idle_timeout"));
        assert!(detail.contains("reusable local proxy tunnel"));
    }
}
