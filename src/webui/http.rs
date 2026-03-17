use crate::error::AgentError;
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Session token validity duration (1 hour)
pub const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Web UI server configuration
#[derive(Debug, Clone)]
pub struct WebUiConfig {
    /// Address to bind (e.g. "127.0.0.1:9444")
    pub bind_addr: String,
    /// Authentication password (empty = no auth required)
    pub auth_password: String,
    /// CORS allowed origin (empty = derive from bind_addr)
    pub cors_origin: String,
}

/// Active session entry
pub struct SessionEntry {
    pub created_at: Instant,
    pub peer_ip: String,
}

/// Session manager for web UI authentication
pub struct SessionManager {
    pub sessions: Mutex<HashMap<String, SessionEntry>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session, returning the token
    pub async fn create_session(&self, peer_ip: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        // Cleanup expired sessions
        sessions.retain(|_, entry| entry.created_at.elapsed() < SESSION_TTL);
        sessions.insert(
            token.clone(),
            SessionEntry {
                created_at: Instant::now(),
                peer_ip: peer_ip.to_string(),
            },
        );
        token
    }

    /// Validate a session token
    pub async fn validate(&self, token: &str, peer_ip: &str) -> bool {
        let sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.get(token) {
            entry.created_at.elapsed() < SESSION_TTL && entry.peer_ip == peer_ip
        } else {
            false
        }
    }

    /// Number of active sessions (for tests)
    #[cfg(test)]
    pub async fn count(&self) -> usize {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .filter(|(_, e)| e.created_at.elapsed() < SESSION_TTL)
            .count()
    }
}

/// API access level for RBAC middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiAccessLevel {
    /// Any authenticated user
    Viewer = 0,
    /// Viewer + search/export
    Operator = 1,
    /// Operator + config/write ops
    Admin = 2,
    /// All access
    Owner = 3,
}

/// Parse a query parameter from the raw HTTP request path.
pub fn parse_query_param<'a>(request: &'a str, key: &str) -> Option<&'a str> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

/// Extract the HTTP body from a raw request string
pub fn extract_body(request: &str) -> String {
    if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    }
}

/// Extract Bearer token from Authorization header
pub fn extract_bearer_token(request: &str) -> Option<&str> {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization: bearer ") {
            return Some(line["authorization: bearer ".len()..].trim());
        }
    }
    None
}

/// Parse Content-Length header from raw HTTP request
pub fn parse_content_length(request: &str) -> usize {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(val) = lower.strip_prefix("content-length:") {
                return val.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Send an HTTP response with dynamic CORS origin
pub async fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    cors_origin: &str,
) -> Result<(), AgentError> {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: {}\r\n\
         Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Connection: close\r\n\
         \r\n",
        status,
        status_text,
        content_type,
        body.len(),
        cors_origin
    );

    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    Ok(())
}

/// Handle CORS preflight OPTIONS request
pub async fn send_cors_preflight(
    stream: &mut TcpStream,
    cors_origin: &str,
) -> Result<(), AgentError> {
    send_response(stream, 200, "text/plain", b"", cors_origin).await
}

/// Send a JSON response with pagination headers (Link + X-Total-Count).
pub async fn send_paginated_response(
    stream: &mut TcpStream,
    body: &[u8],
    cors_origin: &str,
    total: usize,
    offset: usize,
    limit: usize,
    base_path: &str,
) -> Result<(), AgentError> {
    let mut link_parts = Vec::new();
    if offset + limit < total {
        link_parts.push(format!(
            "<{base_path}?offset={}&limit={limit}>; rel=\"next\"",
            offset + limit,
        ));
    }
    if offset > 0 {
        let prev = offset.saturating_sub(limit);
        link_parts.push(format!(
            "<{base_path}?offset={prev}&limit={limit}>; rel=\"prev\"",
        ));
    }

    let link_header = if link_parts.is_empty() {
        String::new()
    } else {
        format!("Link: {}\r\n", link_parts.join(", "))
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Total-Count: {total}\r\n\
         {link_header}\
         Access-Control-Allow-Origin: {cors_origin}\r\n\
         Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Access-Control-Expose-Headers: Link, X-Total-Count\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );

    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    Ok(())
}
