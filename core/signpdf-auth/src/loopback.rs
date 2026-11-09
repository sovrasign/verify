//! Loopback redirect server for the desktop Authorization Code flow.
//!
//! Per OAuth 2.0 for Native Apps (RFC 8252 §7.3) the redirect URI is `http://127.0.0.1:{port}`
//! on an ephemeral port. We bind the socket, hand the browser the authorization URL, and wait
//! for the provider to redirect back with `?code=…&state=…`.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::error::{AuthError, Result};

/// A one-shot loopback HTTP server that captures a single OAuth redirect.
pub struct LoopbackServer {
    listener: TcpListener,
    redirect_uri: String,
    path: String,
}

impl LoopbackServer {
    /// Bind a loopback listener. `port` 0 picks an ephemeral port; `path` is the redirect path
    /// (e.g. `/callback`).
    pub fn bind(host: IpAddr, port: u16, path: &str) -> Result<Self> {
        let listener = TcpListener::bind((host, port))
            .map_err(|e| AuthError::Network(format!("binding loopback {host}:{port}: {e}")))?;
        let local = listener
            .local_addr()
            .map_err(|e| AuthError::Network(format!("reading loopback address: {e}")))?;
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let redirect_uri = format!("http://{}:{}{}", host, local.port(), path);
        Ok(Self {
            listener,
            redirect_uri,
            path,
        })
    }

    /// Bind to `127.0.0.1` on an ephemeral port with the default `/callback` path.
    pub fn bind_default() -> Result<Self> {
        Self::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, "/callback")
    }

    /// The `redirect_uri` to register in the authorization request.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Block until the provider redirects back, returning the authorization `code`.
    ///
    /// Validates that the returned `state` equals `expected_state` (CSRF defense) and surfaces
    /// any `error`/`error_description` the provider sent. Requests to other paths are answered
    /// `404` and ignored. Gives up after `timeout`.
    pub fn wait_for_code(
        &self,
        expected_state: &str,
        timeout: Duration,
        success_html: &str,
    ) -> Result<String> {
        self.listener
            .set_nonblocking(true)
            .map_err(|e| AuthError::Network(format!("configuring loopback: {e}")))?;
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(result) = self.handle(stream, expected_state, success_html)? {
                        return Ok(result);
                    }
                    // Not the callback path (e.g. a favicon probe) — keep waiting.
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(AuthError::Timeout(
                            "timed out waiting for the browser redirect".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
                Err(e) => return Err(AuthError::Network(format!("accept on loopback: {e}"))),
            }
        }
    }

    /// Handle one connection. Returns `Ok(Some(code))` on the callback, `Ok(None)` for unrelated
    /// requests, or an error if the provider reported one (or `state` mismatched).
    fn handle(
        &self,
        stream: TcpStream,
        expected_state: &str,
        success_html: &str,
    ) -> Result<Option<String>> {
        stream
            .set_nonblocking(false)
            .map_err(|e| AuthError::Network(format!("configuring callback stream: {e}")))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| AuthError::Network(format!("configuring callback stream: {e}")))?;
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| AuthError::Network(format!("cloning callback stream: {e}")))?,
        );
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .map_err(|e| AuthError::Network(format!("reading callback request: {e}")))?;

        let target = request_line.split_whitespace().nth(1).unwrap_or("");
        let parsed = url::Url::parse(&format!("http://localhost{target}")).map_err(|e| {
            AuthError::Protocol(format!("malformed callback request '{target}': {e}"))
        })?;

        if parsed.path() != self.path {
            write_response(stream, "404 Not Found", "text/plain", b"Not found");
            return Ok(None);
        }

        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_desc = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                "error_description" => error_desc = Some(v.into_owned()),
                _ => {}
            }
        }

        if let Some(err) = error {
            let detail = error_desc.unwrap_or_default();
            write_response(
                stream,
                "400 Bad Request",
                "text/plain",
                b"Sign-in failed. You can close this window.",
            );
            return Err(AuthError::Provider(format!(
                "authorization request rejected: {err} {detail}"
            )));
        }

        if state.as_deref() != Some(expected_state) {
            write_response(
                stream,
                "400 Bad Request",
                "text/plain",
                b"State mismatch. You can close this window.",
            );
            return Err(AuthError::Protocol(
                "callback `state` did not match (possible CSRF) — aborting".into(),
            ));
        }

        let code = code.ok_or_else(|| {
            AuthError::Protocol("callback is missing the authorization `code`".into())
        })?;
        write_response(
            stream,
            "200 OK",
            "text/html; charset=utf-8",
            success_html.as_bytes(),
        );
        Ok(Some(code))
    }
}

/// Write a minimal HTTP/1.1 response and close the connection.
fn write_response(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_uses_the_bound_port_and_path() {
        let server = LoopbackServer::bind_default().unwrap();
        let uri = server.redirect_uri();
        assert!(uri.starts_with("http://127.0.0.1:"));
        assert!(uri.ends_with("/callback"));
        // Port 0 must have been replaced by a real ephemeral port.
        assert!(!uri.contains(":0/"));
    }
}
