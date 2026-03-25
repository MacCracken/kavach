//! HTTP credential proxy — intercept outbound requests from sandboxes.
//!
//! Runs an HTTP proxy on `127.0.0.1:<ephemeral>` that:
//! 1. Intercepts outbound HTTP/HTTPS requests from sandboxed processes
//! 2. Injects Authorization headers for known hosts (from CredentialProxy)
//! 3. Enforces a host allowlist (blocks requests to non-allowed hosts)
//! 4. Handles CONNECT tunneling for HTTPS
//!
//! The sandboxed process receives only `http_proxy=http://127.0.0.1:<port>`
//! — no raw credentials are ever passed to the sandbox.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Credential rule: maps a host to its auth header.
#[derive(Debug, Clone)]
pub struct CredentialRule {
    /// HTTP header name (e.g., "Authorization").
    pub header_name: String,
    /// HTTP header value (e.g., "Bearer sk-...").
    pub header_value: String,
}

/// Configuration for the HTTP credential proxy.
#[derive(Debug, Clone, Default)]
pub struct HttpProxyConfig {
    /// Host → credential rule mappings.
    pub credential_rules: HashMap<String, CredentialRule>,
    /// Allowed outbound hosts. Empty = allow all (when credentials are injected).
    pub allowed_hosts: Vec<String>,
    /// Whether to block requests to hosts not in the allowlist.
    pub enforce_allowlist: bool,
}

/// A running HTTP credential proxy instance.
///
/// Created by [`start_proxy`]. The proxy runs in a background tokio task
/// and is stopped by dropping this handle.
#[derive(Debug)]
pub struct HttpProxyHandle {
    /// The address the proxy is listening on (127.0.0.1:<port>).
    pub addr: SocketAddr,
    /// Abort handle to stop the background task.
    abort_handle: tokio::task::AbortHandle,
}

impl HttpProxyHandle {
    /// The proxy URL to set as `http_proxy` environment variable.
    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The port the proxy is listening on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Stop the proxy.
    pub fn stop(&self) {
        self.abort_handle.abort();
    }
}

impl Drop for HttpProxyHandle {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

/// Start an HTTP credential proxy on an ephemeral port.
///
/// Returns a handle with the bound address. Set `http_proxy` and
/// `https_proxy` environment variables on the sandboxed process to
/// point to `handle.proxy_url()`.
pub async fn start_proxy(config: HttpProxyConfig) -> crate::Result<HttpProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| crate::KavachError::CreationFailed(format!("proxy bind: {e}")))?;

    let addr = listener
        .local_addr()
        .map_err(|e| crate::KavachError::CreationFailed(format!("proxy addr: {e}")))?;

    tracing::debug!(%addr, "HTTP credential proxy started");

    let task = tokio::spawn(async move {
        proxy_loop(listener, config).await;
    });

    Ok(HttpProxyHandle {
        addr,
        abort_handle: task.abort_handle(),
    })
}

/// Main proxy accept loop.
async fn proxy_loop(listener: TcpListener, config: HttpProxyConfig) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &config).await {
                        tracing::debug!(%peer, error = %e, "proxy connection error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "proxy accept error");
                break;
            }
        }
    }
}

/// Handle a single proxy connection.
async fn handle_connection(mut client: TcpStream, config: &HttpProxyConfig) -> std::io::Result<()> {
    // Read the first line with a size cap to prevent OOM from malicious clients.
    let mut request_line = String::new();
    {
        use tokio::io::AsyncReadExt;
        let limited = (&mut client).take(8192);
        let mut reader = BufReader::new(limited);
        reader.read_line(&mut request_line).await?;
    }
    if request_line.is_empty() {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Ok(());
    }

    let method = parts[0].to_string();
    let target = parts[1].to_string();

    // Extract host from request
    let host = extract_host(&method, &target);

    // Enforce allowlist
    if config.enforce_allowlist
        && !host.is_empty()
        && !config
            .allowed_hosts
            .iter()
            .any(|h| host == h.as_str() || host.ends_with(&format!(".{h}")))
    {
        tracing::debug!(host = %host, "proxy blocked: host not in allowlist");
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }

    if method == "CONNECT" {
        handle_connect(client, &target, &host, config).await
    } else {
        handle_http(client, &request_line, &host, config).await
    }
}

/// Handle CONNECT tunnel (HTTPS).
async fn handle_connect(
    mut client: TcpStream,
    target: &str,
    host: &str,
    _config: &HttpProxyConfig,
) -> std::io::Result<()> {
    // Connect to the target server
    let server = TcpStream::connect(target).await?;

    // Send 200 Connection Established back to client
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    tracing::debug!(host = %host, "CONNECT tunnel established");

    // Bidirectional copy
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    let c2s = tokio::io::copy(&mut client_read, &mut server_write);
    let s2c = tokio::io::copy(&mut server_read, &mut client_write);

    let _ = tokio::try_join!(c2s, s2c);
    Ok(())
}

/// Handle plain HTTP request with header injection.
async fn handle_http(
    mut client: TcpStream,
    request_line: &str,
    host: &str,
    config: &HttpProxyConfig,
) -> std::io::Result<()> {
    // Read remaining headers from client
    let mut headers = String::from(request_line);
    {
        let mut reader = BufReader::new(&mut client);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            headers.push_str(&line);
        }
    }

    // Inject credential header if we have one for this host
    // Sanitize header name/value to prevent CRLF injection
    if let Some(rule) = config.credential_rules.get(host) {
        let safe_name = rule.header_name.replace(['\r', '\n'], "");
        let safe_value = rule.header_value.replace(['\r', '\n'], "");
        headers.push_str(&format!("{safe_name}: {safe_value}\r\n"));
        tracing::debug!(host = %host, header = %safe_name, "injected credential");
    }
    headers.push_str("\r\n");

    // Connect to the upstream server
    let target_addr = format!("{host}:80");
    let mut server = TcpStream::connect(&target_addr).await?;
    server.write_all(headers.as_bytes()).await?;

    // Bidirectional copy for the rest of the connection
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    let c2s = tokio::io::copy(&mut client_read, &mut server_write);
    let s2c = tokio::io::copy(&mut server_read, &mut client_write);

    let _ = tokio::try_join!(c2s, s2c);
    Ok(())
}

/// Extract host from a proxy request target.
fn extract_host(method: &str, target: &str) -> String {
    if method == "CONNECT" {
        // CONNECT host:port
        target.split(':').next().unwrap_or("").to_string()
    } else if target.starts_with("http://") {
        // http://host/path
        target
            .strip_prefix("http://")
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .unwrap_or("")
            .to_string()
    } else if target.starts_with("https://") {
        target
            .strip_prefix("https://")
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_connect() {
        assert_eq!(
            extract_host("CONNECT", "api.openai.com:443"),
            "api.openai.com"
        );
    }

    #[test]
    fn extract_host_http() {
        assert_eq!(
            extract_host("GET", "http://example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn extract_host_http_with_port() {
        assert_eq!(
            extract_host("GET", "http://example.com:8080/path"),
            "example.com"
        );
    }

    #[test]
    fn extract_host_empty() {
        assert_eq!(extract_host("GET", "/path"), "");
    }

    #[test]
    fn default_config() {
        let config = HttpProxyConfig::default();
        assert!(!config.enforce_allowlist);
        assert!(config.credential_rules.is_empty());
    }

    #[tokio::test]
    async fn start_and_stop_proxy() {
        let config = HttpProxyConfig::default();
        let handle = start_proxy(config).await.unwrap();

        assert_ne!(handle.port(), 0);
        assert!(handle.proxy_url().starts_with("http://127.0.0.1:"));

        handle.stop();
    }

    #[tokio::test]
    async fn proxy_url_format() {
        let config = HttpProxyConfig::default();
        let handle = start_proxy(config).await.unwrap();
        let url = handle.proxy_url();
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(url.len() > "http://127.0.0.1:".len());
    }

    #[test]
    fn credential_rule_creation() {
        let mut config = HttpProxyConfig::default();
        config.credential_rules.insert(
            "api.openai.com".into(),
            CredentialRule {
                header_name: "Authorization".into(),
                header_value: "Bearer test-key".into(),
            },
        );
        assert!(config.credential_rules.contains_key("api.openai.com"));
    }
}
