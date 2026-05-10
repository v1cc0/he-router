use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{RemoteClientConfig, RemoteClientProxyConfig, ReusableRemoteTunnel};
use crate::{EmbeddedClientProxyConfig, HeRouterConfig, HeRouterError, Result};

#[derive(Debug, Clone)]
pub struct ClientProxyOptions {
    pub listen: SocketAddr,
}

impl ClientProxyOptions {
    pub fn from_embedded(config: &EmbeddedClientProxyConfig) -> Result<Self> {
        Ok(Self {
            listen: RemoteClientProxyConfig::from_embedded(config).listen_addr()?,
        })
    }
}

pub async fn run_client_proxy(
    config_path: &Path,
    override_listen: Option<SocketAddr>,
) -> Result<()> {
    let root_config = HeRouterConfig::load_from(config_path)?;
    let client_config = RemoteClientConfig::from_embedded(&root_config.client)?;
    let mut proxy_options = ClientProxyOptions::from_embedded(&root_config.client_proxy)?;
    if let Some(listen) = override_listen {
        proxy_options.listen = listen;
    }

    let tunnel = Arc::new(ReusableRemoteTunnel::from_config(client_config));
    let listener = TcpListener::bind(proxy_options.listen)
        .await
        .map_err(|err| {
            HeRouterError::Protocol(format!("failed to bind local proxy listener: {err}"))
        })?;
    eprintln!(
        "he-router local proxy listening on {}",
        listener.local_addr().map_err(HeRouterError::Io)?
    );

    loop {
        let (stream, peer) = listener.accept().await.map_err(|err| {
            HeRouterError::Protocol(format!("failed accepting local proxy connection: {err}"))
        })?;
        let tunnel = Arc::clone(&tunnel);
        tokio::spawn(async move {
            if let Err(err) = handle_local_proxy_connection(stream, tunnel, peer).await {
                eprintln!("he-router local proxy connection from {peer} failed: {err}");
            }
        });
    }
}

async fn handle_local_proxy_connection(
    mut stream: tokio::net::TcpStream,
    tunnel: Arc<ReusableRemoteTunnel>,
    peer: SocketAddr,
) -> Result<()> {
    let mut buffer = Vec::with_capacity(4096);
    let header_end = read_until_headers_end(&mut stream, &mut buffer).await?;
    let (request_line, headers, body_offset) = parse_request_head(&buffer[..header_end])?;
    let mut body = buffer[body_offset..header_end].to_vec();

    let content_length = header_value(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if body.len() < content_length {
        let missing = content_length - body.len();
        let mut rest = vec![0u8; missing];
        stream.read_exact(&mut rest).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed reading local proxy body: {err}"))
        })?;
        body.extend_from_slice(&rest);
    }

    if header_value(&headers, "transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        write_error_response(&mut stream, 501, "chunked request bodies are not supported").await?;
        return Ok(());
    }

    match request_line.method.as_str() {
        "CONNECT" => handle_connect(stream, tunnel, request_line.target, headers, peer).await,
        _ => handle_http(stream, tunnel, request_line, headers, body, peer).await,
    }
}

async fn handle_http(
    mut stream: tokio::net::TcpStream,
    tunnel: Arc<ReusableRemoteTunnel>,
    request_line: ParsedRequestLine,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    peer: SocketAddr,
) -> Result<()> {
    let method = request_line.method;
    let target = request_line.target;
    let response = tunnel
        .request(super::ClientCommandOptions {
            method: method.clone(),
            url: target.clone(),
            headers: filter_forward_headers(headers),
            body,
        })
        .await?;
    if let Some(source_ip) = response.source_ip.as_deref() {
        eprintln!(
            "he-router local proxy routed request peer={peer} method={method} target={target} source_ip={source_ip} status={}",
            response.status
        );
    }

    if let Some(error) = response.error.as_deref() {
        write_error_response(&mut stream, response.status.max(500), error).await?;
        return Ok(());
    }

    let status_text = status_text(response.status);
    let mut response_head = format!("HTTP/1.1 {} {}\r\n", response.status, status_text);
    let mut seen = HashSet::new();
    for header in response.headers {
        let lower = header.name.to_ascii_lowercase();
        if HOP_BY_HOP_HEADERS.iter().any(|header| *header == lower) {
            continue;
        }
        if lower == "content-length" || lower == "connection" {
            seen.insert(lower);
            continue;
        }
        response_head.push_str(&format!("{}: {}\r\n", header.name, header.value));
    }
    if !seen.contains("content-length") {
        response_head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    }
    response_head.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(response_head.as_bytes())
        .await
        .map_err(|err| {
            HeRouterError::Protocol(format!("failed writing HTTP proxy response head: {err}"))
        })?;
    if !response.body.is_empty() {
        stream.write_all(&response.body).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed writing HTTP proxy response body: {err}"))
        })?;
    }
    stream.flush().await.ok();
    Ok(())
}

async fn handle_connect(
    mut stream: tokio::net::TcpStream,
    tunnel: Arc<ReusableRemoteTunnel>,
    authority: String,
    headers: Vec<(String, String)>,
    peer: SocketAddr,
) -> Result<()> {
    let (mut send, mut recv, response) = tunnel
        .open_connect_tunnel(&authority, filter_forward_headers(headers))
        .await?;
    let source_ip = response
        .source_ip
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "he-router local proxy routed request peer={peer} method=CONNECT authority={authority} source_ip={source_ip} status={}",
        response.status
    );

    if !response.tunnel_established || response.status != 200 {
        let message = response
            .error
            .unwrap_or_else(|| "remote tunnel refused CONNECT".to_string());
        write_error_response(&mut stream, response.status.max(502), &message).await?;
        return Ok(());
    }

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|err| {
            HeRouterError::Protocol(format!("failed acknowledging CONNECT tunnel: {err}"))
        })?;

    let (mut local_read, mut local_write) = stream.into_split();

    let upstream_to_remote = async {
        tokio::io::copy(&mut local_read, &mut send)
            .await
            .map_err(|err| {
                tunnel_copy_error(
                    "failed forwarding CONNECT data to remote tunnel",
                    "remote QUIC stream closed before local client bytes were forwarded",
                    peer,
                    &authority,
                    &source_ip,
                    err,
                )
            })?;
        send.finish().map_err(|err| {
            HeRouterError::Protocol(format!("failed finishing CONNECT send stream: {err}"))
        })?;
        Ok::<(), HeRouterError>(())
    };

    let remote_to_upstream = async {
        tokio::io::copy(&mut recv, &mut local_write)
            .await
            .map_err(|err| {
                tunnel_copy_error(
                    "failed forwarding CONNECT data from remote tunnel",
                    "local client closed before remote tunnel bytes were written",
                    peer,
                    &authority,
                    &source_ip,
                    err,
                )
            })?;
        local_write.shutdown().await.ok();
        Ok::<(), HeRouterError>(())
    };

    let _ = tokio::try_join!(upstream_to_remote, remote_to_upstream)?;
    Ok(())
}

#[derive(Debug)]
struct ParsedRequestLine {
    method: String,
    target: String,
}

type ParsedHeaders = Vec<(String, String)>;

fn parse_request_head(buffer: &[u8]) -> Result<(ParsedRequestLine, ParsedHeaders, usize)> {
    let mut header_slots = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut header_slots);
    let status = request.parse(buffer).map_err(|err| {
        HeRouterError::Protocol(format!("failed parsing local proxy request: {err}"))
    })?;
    let header_end = match status {
        httparse::Status::Complete(length) => length,
        httparse::Status::Partial => {
            return Err(HeRouterError::Protocol(
                "local proxy request headers were incomplete".to_string(),
            ));
        }
    };
    let method = request
        .method
        .ok_or_else(|| HeRouterError::Protocol("local proxy request missing method".to_string()))?
        .to_string();
    let target = request
        .path
        .ok_or_else(|| HeRouterError::Protocol("local proxy request missing target".to_string()))?
        .to_string();
    let headers = request
        .headers
        .iter()
        .map(|header| {
            (
                header.name.to_string(),
                String::from_utf8_lossy(header.value).trim().to_string(),
            )
        })
        .collect::<Vec<_>>();

    Ok((ParsedRequestLine { method, target }, headers, header_end))
}

async fn read_until_headers_end(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<usize> {
    loop {
        if let Some(position) = find_header_end(buffer) {
            return Ok(position);
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.map_err(|err| {
            HeRouterError::Protocol(format!("failed reading local proxy request: {err}"))
        })?;
        if read == 0 {
            return Err(HeRouterError::Protocol(
                "client closed connection before sending complete request headers".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > super::MAX_PROXY_MESSAGE_BYTES {
            return Err(HeRouterError::Protocol(
                "local proxy request headers exceeded safety limit".to_string(),
            ));
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn filter_forward_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !HOP_BY_HOP_HEADERS.iter().any(|header| *header == lower)
        })
        .collect()
}

async fn write_error_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
) -> Result<()> {
    let status_text = status_text(status);
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await.map_err(|err| {
        HeRouterError::Protocol(format!("failed writing local proxy error response: {err}"))
    })?;
    Ok(())
}

fn tunnel_copy_error(
    context: &str,
    peer_close_hint: &str,
    peer: SocketAddr,
    authority: &str,
    source_ip: &str,
    err: std::io::Error,
) -> HeRouterError {
    HeRouterError::Protocol(format!(
        "{context} peer={peer} authority={authority} source_ip={source_ip}: reason={} original={err}",
        describe_io_error(&err, peer_close_hint)
    ))
}

fn describe_io_error(err: &std::io::Error, peer_close_hint: &str) -> String {
    let message = err.to_string().to_ascii_lowercase();
    if message.contains("connection lost") {
        return "quic_connection_lost: remote QUIC connection closed while this CONNECT tunnel was copying bytes; check the remote server log for the close reason, commonly idle_timeout or peer reset".to_string();
    }
    if message.contains("timed out") {
        return "io_timeout: no bytes moved before the socket/tunnel timeout expired; the tunnel may have been idle or the network path may have dropped traffic".to_string();
    }

    match err.kind() {
        std::io::ErrorKind::BrokenPipe => {
            format!("broken_pipe: {peer_close_hint}")
        }
        std::io::ErrorKind::ConnectionReset => {
            format!("connection_reset: {peer_close_hint}")
        }
        std::io::ErrorKind::UnexpectedEof => {
            format!("unexpected_eof: {peer_close_hint}")
        }
        std::io::ErrorKind::TimedOut => {
            "io_timeout: no bytes moved before the socket/tunnel timeout expired; the tunnel may have been idle or the network path may have dropped traffic".to_string()
        }
        _ => format!("io_error_kind={}", err.kind()),
    }
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Proxy Response",
    }
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "proxy-connection",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_pipe_error_includes_close_hint() {
        let err = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        let detail = describe_io_error(&err, "local client closed early");
        assert!(detail.contains("broken_pipe"));
        assert!(detail.contains("local client closed early"));
    }

    #[test]
    fn connection_lost_error_points_to_remote_close_reason() {
        let err = std::io::Error::other("connection lost");
        let detail = describe_io_error(&err, "unused hint");
        assert!(detail.contains("quic_connection_lost"));
        assert!(detail.contains("remote server log"));
    }
}
