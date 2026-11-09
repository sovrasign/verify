//! End-to-end tests for the Authorization Code + PKCE loopback flow against an in-process mock
//! OpenID provider served over real TCP sockets. No network, no TLS, no live credentials — yet
//! the entire `signpdf-auth` code path (discovery, authorize redirect, loopback capture, token
//! exchange with PKCE verification, JWKS fetch, and offline validation by the core) runs for
//! real, and the resulting token is shown to drive an actual SignPDF signature.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use signpdf_auth::{authenticate, fetch_jwks, AuthError, BrowserOpener, LoginOptions, Provider};
use signpdf_core::crypto::{sha256_hex, KeyPair};
use signpdf_core::oidc::testing::TestIssuer;
use signpdf_core::workflow::SignerSpec;
use signpdf_core::{
    compute_nonce, prepare, sign, verify, Field, FieldType, IdentityPolicy, Policy, PrepareRequest,
    Rect, SignRequest, SigningOrder, TrustStore,
};

const CLIENT_ID: &str = "signpdf-test-client";
const SIGNER_EMAIL: &str = "signer@example.com";

/// How the mock provider should behave at the authorize endpoint.
#[derive(Clone, Copy)]
enum AuthorizeBehavior {
    /// Redirect back with a valid `code`.
    Succeed,
    /// Redirect back with `error=access_denied` (user declined consent).
    Deny,
}

/// A minimal in-process OpenID provider: discovery, authorize (302), JWKS, and a PKCE-checking
/// token endpoint, all backed by the core's bundled `TestIssuer`.
struct MockIdp {
    base_url: String,
}

impl MockIdp {
    fn start(behavior: AuthorizeBehavior, email: &str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let issuer = Arc::new(TestIssuer::es256());
        let codes: Arc<Mutex<HashMap<String, CodeData>>> = Arc::new(Mutex::new(HashMap::new()));

        let state = Arc::new(ServerState {
            base_url: base_url.clone(),
            issuer,
            codes,
            behavior,
            email: email.to_string(),
        });

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&state);
                std::thread::spawn(move || handle_connection(stream, &state));
            }
        });

        MockIdp { base_url }
    }
}

struct CodeData {
    nonce: String,
    code_challenge: String,
}

struct ServerState {
    base_url: String,
    issuer: Arc<TestIssuer>,
    codes: Arc<Mutex<HashMap<String, CodeData>>>,
    behavior: AuthorizeBehavior,
    email: String,
}

struct ParsedRequest {
    path: String,
    query: HashMap<String, String>,
    body: HashMap<String, String>,
}

fn handle_connection(stream: TcpStream, state: &ServerState) {
    let Some(req) = parse_request(&stream) else {
        return;
    };
    match req.path.as_str() {
        "/.well-known/openid-configuration" => {
            let body = format!(
                r#"{{"issuer":"{b}","authorization_endpoint":"{b}/authorize",
                    "token_endpoint":"{b}/token","jwks_uri":"{b}/jwks",
                    "response_types_supported":["code"],
                    "code_challenge_methods_supported":["S256"]}}"#,
                b = state.base_url
            );
            respond(stream, "200 OK", "application/json", body.as_bytes());
        }
        "/authorize" => handle_authorize(stream, state, &req),
        "/jwks" => {
            let body = serde_json::to_string(&state.issuer.jwks()).unwrap();
            respond(stream, "200 OK", "application/json", body.as_bytes());
        }
        "/token" => handle_token(stream, state, &req),
        _ => respond(stream, "404 Not Found", "text/plain", b"not found"),
    }
}

fn handle_authorize(stream: TcpStream, state: &ServerState, req: &ParsedRequest) {
    let redirect_uri = req.query.get("redirect_uri").cloned().unwrap_or_default();
    let client_state = req.query.get("state").cloned().unwrap_or_default();

    let location = match state.behavior {
        AuthorizeBehavior::Deny => format!(
            "{redirect_uri}?error=access_denied&error_description=user+declined&state={client_state}"
        ),
        AuthorizeBehavior::Succeed => {
            let code = format!("code-{}", rand_suffix());
            state.codes.lock().unwrap().insert(
                code.clone(),
                CodeData {
                    nonce: req.query.get("nonce").cloned().unwrap_or_default(),
                    code_challenge: req.query.get("code_challenge").cloned().unwrap_or_default(),
                },
            );
            format!("{redirect_uri}?code={code}&state={client_state}")
        }
    };
    let header = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut s = stream;
    let _ = s.write_all(header.as_bytes());
    let _ = s.flush();
}

fn handle_token(stream: TcpStream, state: &ServerState, req: &ParsedRequest) {
    let code = req.body.get("code").cloned().unwrap_or_default();
    let verifier = req.body.get("code_verifier").cloned().unwrap_or_default();
    let client_id = req.body.get("client_id").cloned().unwrap_or_default();

    let entry = state.codes.lock().unwrap().remove(&code);
    let Some(entry) = entry else {
        respond(
            stream,
            "400 Bad Request",
            "application/json",
            br#"{"error":"invalid_grant"}"#,
        );
        return;
    };
    // Enforce PKCE: the verifier must hash to the challenge from the authorize request.
    if signpdf_auth::pkce::s256_challenge(&verifier) != entry.code_challenge {
        respond(
            stream,
            "400 Bad Request",
            "application/json",
            br#"{"error":"invalid_grant","error_description":"PKCE mismatch"}"#,
        );
        return;
    }

    let now = now_unix();
    let claims = serde_json::json!({
        "iss": state.base_url,
        "sub": format!("mock|{}", state.email),
        "aud": client_id,
        "iat": now - 5,
        "exp": now + 3600,
        "email": state.email,
        "email_verified": true,
        "name": "Mock Signer",
        "nonce": entry.nonce,
    });
    let id_token = state.issuer.mint(claims);
    let body = format!(
        r#"{{"access_token":"mock-access","token_type":"Bearer","expires_in":3600,"id_token":"{id_token}"}}"#
    );
    respond(stream, "200 OK", "application/json", body.as_bytes());
}

/// Read a full HTTP request: request line, headers, and (for POST) a Content-Length body.
fn parse_request(stream: &TcpStream) -> Option<ParsedRequest> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let target = request_line.split_whitespace().nth(1)?.to_string();

    let parsed = url::Url::parse(&format!("http://localhost{target}")).ok()?;
    let path = parsed.path().to_string();
    let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let mut body = HashMap::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf).ok()?;
        let raw = String::from_utf8_lossy(&buf);
        for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
            body.insert(k.into_owned(), v.into_owned());
        }
    }

    Some(ParsedRequest { path, query, body })
}

fn respond(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn rand_suffix() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    format!("{:016x}", u64::from_le_bytes(b))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A test browser: instead of launching a real browser it fetches the authorization URL on a
/// background thread, following the provider's 302 back to the loopback redirect (exactly what a
/// real user-agent does). Returns immediately, per the `BrowserOpener` contract.
struct FetchingBrowser;

impl BrowserOpener for FetchingBrowser {
    fn open(&self, url: &str) -> signpdf_auth::Result<()> {
        let url = url.to_string();
        std::thread::spawn(move || {
            // ureq follows the 302 to http://127.0.0.1:<loopback>/callback, delivering the code.
            let _ = ureq::get(&url).timeout(Duration::from_secs(10)).call();
        });
        Ok(())
    }
}

fn fast_options() -> LoginOptions {
    LoginOptions {
        timeout: Duration::from_secs(15),
        ..LoginOptions::default()
    }
}

#[test]
fn loopback_pkce_flow_against_mock_idp_yields_validated_identity() {
    let idp = MockIdp::start(AuthorizeBehavior::Succeed, SIGNER_EMAIL);
    let config = Provider::Enterprise {
        issuer: idp.base_url.clone(),
    }
    .config(CLIENT_ID);

    // The caller binds the token to a specific signing key + document via the nonce.
    let key = KeyPair::generate();
    let digest = sha256_hex(b"a document to sign");
    let nonce = compute_nonce(&key.public_sec1(), &digest);

    let outcome =
        authenticate(&config, &nonce, &FetchingBrowser, &fast_options()).expect("login flow");

    assert_eq!(outcome.identity.email, SIGNER_EMAIL);
    assert_eq!(outcome.issuer, idp.base_url);
    assert_eq!(outcome.audience, CLIENT_ID);
    assert!(outcome.identity.email_verified);
    assert_eq!(outcome.identity.organization(), None);

    // The archived JWK must be a single well-formed key (what the engine stores per signature).
    let jwk: signpdf_core::Jwk = serde_json::from_str(&outcome.idp_jwk).unwrap();
    assert_eq!(jwk.kty, "EC");

    // And the verified identity satisfies a matching slot policy — the engine's resolution gate.
    let policy = IdentityPolicy {
        allowed_issuers: vec![idp.base_url.clone()],
        required_email: Some(SIGNER_EMAIL.to_string()),
        ..Default::default()
    };
    assert!(outcome.identity.satisfies(&policy).is_ok());
}

#[test]
fn provider_denial_is_surfaced_as_an_error() {
    let idp = MockIdp::start(AuthorizeBehavior::Deny, SIGNER_EMAIL);
    let config = Provider::Enterprise {
        issuer: idp.base_url.clone(),
    }
    .config(CLIENT_ID);

    let err = authenticate(&config, "any-nonce", &FetchingBrowser, &fast_options()).unwrap_err();
    match err {
        AuthError::Provider(msg) => assert!(msg.contains("access_denied"), "got: {msg}"),
        other => panic!("expected a provider error, got {other:?}"),
    }
}

#[test]
fn token_obtained_via_oidc_signs_and_verifies_a_real_document() {
    let idp = MockIdp::start(AuthorizeBehavior::Succeed, SIGNER_EMAIL);
    let config = Provider::Enterprise {
        issuer: idp.base_url.clone(),
    }
    .config(CLIENT_ID);

    // 1. Prepare a one-signer document whose slot is pinned to the OIDC identity above.
    let source = signpdf_core::container::make_sample_pdf("OIDC-signed agreement");
    let preparer = TestIssuer::es256();
    let preparer_key = KeyPair::generate();
    let prep_nonce = compute_nonce(&preparer_key.public_sec1(), &sha256_hex(&source));
    let prep_token = preparer.mint(serde_json::json!({
        "iss": "https://preparer.test", "sub": "prep|admin", "aud": "signpdf-prep",
        "iat": now_unix() - 5, "exp": now_unix() + 3600,
        "email": "admin@example.com", "email_verified": true, "nonce": prep_nonce,
    }));

    let prepare_req = PrepareRequest {
        title: "OIDC NDA".into(),
        signers: vec![SignerSpec {
            id: "s1".into(),
            name: "Signer".into(),
            handle: SIGNER_EMAIL.into(),
            role: "Signer".into(),
            order: 1,
            identity_policy: IdentityPolicy {
                allowed_issuers: vec![idp.base_url.clone()],
                required_email: Some(SIGNER_EMAIL.to_string()),
                ..Default::default()
            },
        }],
        fields: vec![Field {
            id: "f1".into(),
            field_type: FieldType::Signature,
            page: 0,
            rect: Rect {
                x: 72.0,
                y: 120.0,
                w: 200.0,
                h: 48.0,
            },
            assigned_signer: "s1".into(),
            required: true,
            value: None,
            label: None,
            group: None,
            options: None,
            date_format: None,
            signing_date: false,
            number_format: None,
            value_format: None,
            length: None,
            check_message: None,
            formula: None,
        }],
        policy: Policy {
            signing_order: SigningOrder::Sequential,
            allowed_signature_types: vec!["PAdES".into()],
            expiry: None,
            ..Default::default()
        },
        id_token: prep_token,
        idp_jwk: serde_json::to_string(&preparer.jwk()).unwrap(),
        audience: "signpdf-prep".into(),
        allowed_issuers: vec!["https://preparer.test".into()],
        service_link: None,
        documents: Vec::new(),
        verify_at: None,
    };
    let prepared = prepare(&source, &prepare_req, &preparer_key).expect("prepare");

    // 2. The signer logs in via OIDC, binding the token to their key + THIS document digest.
    let signer_key = KeyPair::generate();
    let nonce = compute_nonce(&signer_key.public_sec1(), &sha256_hex(&prepared));
    let outcome =
        authenticate(&config, &nonce, &FetchingBrowser, &fast_options()).expect("signer login");

    // 3. The OIDC outcome drops straight into a SignRequest — no self-selection.
    let sign_req = SignRequest {
        id_token: outcome.id_token,
        idp_jwk: outcome.idp_jwk,
        audience: outcome.audience,
        allowed_issuers: vec![outcome.issuer],
        ..Default::default()
    };
    let signed = sign(&prepared, &signer_key, &sign_req).expect("sign with OIDC token");

    // 4. Verify: the signature is valid and the verified email is surfaced.
    // The verifier pins the IdP key it fetched itself (and the preparer issuer's key).
    let mut trust = TrustStore::empty();
    trust.add_jwks(
        &idp.base_url,
        &fetch_jwks(&idp.base_url, None).expect("fetch jwks"),
    );
    trust.add_jwks("https://preparer.test", &preparer.jwks());
    // ...and trusts exactly the applications the two sign-ins went through.
    trust.add_audience(&idp.base_url, CLIENT_ID);
    trust.add_audience("https://preparer.test", "signpdf-prep");
    let report = verify(&signed, &trust).expect("verify");
    assert!(report.valid, "document should verify: {report:?}");
    assert!(report.complete);
    assert_eq!(report.signatures[0].idp_email, SIGNER_EMAIL);
}
