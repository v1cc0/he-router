use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::Endpoint;
use reqwest::Method;
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpSocket, TcpStream, lookup_host};

use super::{
    RemoteHttpRequest, RemoteHttpResponseHead, bind_udp_socket, build_endpoint_config,
    build_server_config, build_server_router, map_async_error, read_envelope, write_envelope,
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
    let root_config = crate::HeRouterConfig::load_from(config_path)?;
    let router = Arc::new(build_server_router(config_path)?);
    let socket = bind_udp_socket(options.listen)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| HeRouterError::Protocol("no async runtime found".to_string()))?;
    let endpoint = Endpoint::new(
        build_endpoint_config(&root_config.quic)?,
        Some(build_server_config(
            &options.cert_path,
            &options.key_path,
            &root_config.quic,
        )?),
        socket,
        runtime,
    )
    .map_err(|err| HeRouterError::Protocol(format!("failed to bind QUIC server: {err}")))?;

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
                log_connection_stats(peer, connection_id, &connection);
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
    let read_envelope_started = Instant::now();
    let request: RemoteHttpRequest = read_envelope(&mut recv).await?;
    let read_envelope_ms = elapsed_ms(read_envelope_started);

    if request.auth_token != auth_token {
        eprintln!(
            "he-router remote stream unauthorized peer={peer} conn_id={connection_id} request_id={} method={} target={} read_envelope_ms={read_envelope_ms:.3}",
            request.request_id, request.method, request.url
        );
        let response = RemoteHttpResponseHead {
            status: 401,
            headers: Vec::new(),
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
        handle_connect_stream(
            router,
            request,
            send,
            recv,
            peer,
            connection_id,
            read_envelope_ms,
        )
        .await
    } else {
        proxy_http_request_stream(
            router.as_ref(),
            request,
            peer,
            connection_id,
            read_envelope_ms,
            send,
        )
        .await
    }
}

async fn handle_connect_stream(
    router: Arc<crate::HeRouter>,
    request: RemoteHttpRequest,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    connection_id: usize,
    read_envelope_ms: f64,
) -> Result<()> {
    let route_started = Instant::now();
    let source_ip = router
        .derive_source_ip(&request.request_id, None)?
        .ok_or_else(|| {
            HeRouterError::Protocol("no source IPv6 available for CONNECT tunnel".to_string())
        })?;
    let route_decision_ms = elapsed_ms(route_started);
    eprintln!(
        "he-router remote assigned source IPv6 peer={peer} conn_id={connection_id} request_id={} method=CONNECT authority={} source_ip={} timeout_ms={} read_envelope_ms={read_envelope_ms:.3} route_decision_ms={route_decision_ms:.3}",
        request.request_id, request.url, source_ip, request.timeout_ms
    );

    let connect_started = Instant::now();
    let upstream = match connect_upstream_with_source(source_ip, &request.url).await {
        Ok((stream, used_source_ip)) => {
            let connect_upstream_ms = elapsed_ms(connect_started);
            eprintln!(
                "he-router remote CONNECT established peer={peer} conn_id={connection_id} request_id={} authority={} assigned_source_ip={} socket_local_ip={} connect_upstream_ms={connect_upstream_ms:.3}",
                request.request_id, request.url, source_ip, used_source_ip
            );
            let response = RemoteHttpResponseHead {
                status: 200,
                headers: Vec::new(),
                source_ip: Some(used_source_ip.to_string()),
                error: None,
                tunnel_established: true,
            };
            write_envelope(&mut send, &response).await?;
            stream
        }
        Err(err) => {
            let connect_upstream_ms = elapsed_ms(connect_started);
            eprintln!(
                "he-router remote CONNECT failed peer={peer} conn_id={connection_id} request_id={} authority={} source_ip={} connect_upstream_ms={connect_upstream_ms:.3} reason={err}",
                request.request_id, request.url, source_ip
            );
            let response = RemoteHttpResponseHead {
                status: 502,
                headers: Vec::new(),
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
        let copy_started = Instant::now();
        let bytes = copy(&mut recv, &mut upstream_write).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed relaying QUIC tunnel to upstream: {err}"))
        })?;
        let copy_ms = elapsed_ms(copy_started);
        upstream_write.shutdown().await.ok();
        Ok::<(u64, f64), HeRouterError>((bytes, copy_ms))
    };

    let upstream_to_client = async {
        let copy_started = Instant::now();
        let bytes = copy(&mut upstream_read, &mut send).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed relaying upstream tunnel to QUIC: {err}"))
        })?;
        let copy_ms = elapsed_ms(copy_started);
        send.finish()
            .map_err(|err| map_async_error("failed finishing CONNECT tunnel send stream", err))?;
        Ok::<(u64, f64), HeRouterError>((bytes, copy_ms))
    };

    let (
        (client_to_upstream_bytes, client_to_upstream_ms),
        (upstream_to_client_bytes, upstream_to_client_ms),
    ) = tokio::try_join!(client_to_upstream, upstream_to_client)?;
    eprintln!(
        "he-router remote CONNECT copy timings peer={peer} conn_id={connection_id} request_id={} authority={} source_ip={} copy_client_to_upstream_bytes={} copy_client_to_upstream_ms={client_to_upstream_ms:.3} copy_upstream_to_client_bytes={} copy_upstream_to_client_ms={upstream_to_client_ms:.3}",
        request.request_id,
        request.url,
        source_ip,
        client_to_upstream_bytes,
        upstream_to_client_bytes,
    );
    Ok(())
}

async fn proxy_http_request_stream(
    router: &crate::HeRouter,
    request: RemoteHttpRequest,
    peer: SocketAddr,
    connection_id: usize,
    read_envelope_ms: f64,
    mut send: quinn::SendStream,
) -> Result<()> {
    let timeout = std::time::Duration::from_millis(request.timeout_ms.max(1));
    let route_started = Instant::now();
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
            let response = RemoteHttpResponseHead {
                status: 503,
                headers: Vec::new(),
                source_ip: None,
                error: Some("no route decision available".to_string()),
                tunnel_established: false,
            };
            write_envelope(&mut send, &response).await?;
            send.finish()
                .map_err(|err| map_async_error("failed finishing no-route response", err))?;
            return Ok(());
        }
        Err(err) => {
            let response = RemoteHttpResponseHead {
                status: 500,
                headers: Vec::new(),
                source_ip: None,
                error: Some(err.to_string()),
                tunnel_established: false,
            };
            write_envelope(&mut send, &response).await?;
            send.finish()
                .map_err(|err| map_async_error("failed finishing route-error response", err))?;
            return Ok(());
        }
    };
    let route_decision_ms = elapsed_ms(route_started);
    eprintln!(
        "he-router remote assigned source IPv6 peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} binding_key_prefix={} timeout_ms={} read_envelope_ms={read_envelope_ms:.3} route_decision_ms={route_decision_ms:.3}",
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
            let response = RemoteHttpResponseHead {
                status: 400,
                headers: Vec::new(),
                source_ip: Some(decision.source_ip.to_string()),
                error: Some(format!("invalid HTTP method: {err}")),
                tunnel_established: false,
            };
            write_envelope(&mut send, &response).await?;
            send.finish()
                .map_err(|err| map_async_error("failed finishing invalid-method response", err))?;
            return Ok(());
        }
    };

    let mut builder = decision.client.request(method, &request.url);
    for header in &request.headers {
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }
    if !request.body.is_empty() {
        builder = builder.body(request.body.clone());
    }

    let upstream_started = Instant::now();
    match builder.send().await {
        Ok(mut response) => {
            let upstream_ttfb_ms = elapsed_ms(upstream_started);
            let status = response.status().as_u16();
            eprintln!(
                "he-router remote HTTP upstream responded peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} status={} upstream_ttfb_ms={upstream_ttfb_ms:.3}",
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
            let head = RemoteHttpResponseHead {
                status,
                headers,
                source_ip: Some(decision.source_ip.to_string()),
                error: None,
                tunnel_established: false,
            };
            let write_head_started = Instant::now();
            write_envelope(&mut send, &head).await?;
            let write_response_head_ms = elapsed_ms(write_head_started);

            let mut body_bytes = 0_u64;
            let mut upstream_body_ms = Duration::ZERO;
            let mut write_body_ms = Duration::ZERO;
            loop {
                let chunk_read_started = Instant::now();
                let chunk = response.chunk().await.map_err(|err| {
                    HeRouterError::Protocol(format!("failed to read upstream body: {err}"))
                })?;
                upstream_body_ms += chunk_read_started.elapsed();
                let Some(chunk) = chunk else {
                    break;
                };
                body_bytes += chunk.len() as u64;
                let write_started = Instant::now();
                send.write_all(&chunk)
                    .await
                    .map_err(|err| map_async_error("failed writing HTTP response body", err))?;
                write_body_ms += write_started.elapsed();
            }
            send.finish()
                .map_err(|err| map_async_error("failed finishing streamed HTTP response", err))?;
            eprintln!(
                "he-router remote HTTP timings peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} status={} read_envelope_ms={read_envelope_ms:.3} route_decision_ms={route_decision_ms:.3} upstream_ttfb_ms={upstream_ttfb_ms:.3} upstream_body_ms={:.3} write_response_head_ms={write_response_head_ms:.3} write_body_ms={:.3} body_bytes={body_bytes}",
                request.request_id,
                request.method,
                request.url,
                decision.source_ip,
                status,
                duration_ms(upstream_body_ms),
                duration_ms(write_body_ms),
            );
            Ok(())
        }
        Err(err) => {
            let upstream_ttfb_ms = elapsed_ms(upstream_started);
            eprintln!(
                "he-router remote HTTP upstream failed peer={peer} conn_id={connection_id} request_id={} method={} url={} source_ip={} upstream_ttfb_ms={upstream_ttfb_ms:.3} reason={err}",
                request.request_id, request.method, request.url, decision.source_ip
            );
            let response = RemoteHttpResponseHead {
                status: 502,
                headers: Vec::new(),
                source_ip: Some(decision.source_ip.to_string()),
                error: Some(format!("failed to proxy upstream request: {err}")),
                tunnel_established: false,
            };
            write_envelope(&mut send, &response).await?;
            send.finish()
                .map_err(|err| map_async_error("failed finishing upstream-error response", err))?;
            Ok(())
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

fn elapsed_ms(started: Instant) -> f64 {
    duration_ms(started.elapsed())
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn log_connection_stats(peer: SocketAddr, connection_id: usize, connection: &quinn::Connection) {
    let stats = connection.stats();
    eprintln!(
        "he-router remote QUIC stats peer={peer} conn_id={connection_id} rtt_ms={:.3} cwnd={} current_mtu={} lost_packets={} lost_bytes={} sent_packets={} congestion_events={} black_holes_detected={} udp_tx_datagrams={} udp_tx_bytes={} udp_rx_datagrams={} udp_rx_bytes={}",
        duration_ms(stats.path.rtt),
        stats.path.cwnd,
        stats.path.current_mtu,
        stats.path.lost_packets,
        stats.path.lost_bytes,
        stats.path.sent_packets,
        stats.path.congestion_events,
        stats.path.black_holes_detected,
        stats.udp_tx.datagrams,
        stats.udp_tx.bytes,
        stats.udp_rx.datagrams,
        stats.udp_rx.bytes,
    );
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
