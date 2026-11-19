//! Compiles the built-in Google client secret in from outside version control.
//!
//! Google's "Desktop app" OAuth clients must present a secret at the token endpoint even with
//! PKCE. Every copy of the app carries it, so it is not confidential, but it is still kept out of
//! the repository: a build takes it from the `SIGNPDF_GOOGLE_CLIENT_SECRET` environment variable
//! or, failing that, from the git-ignored `secrets/client-secrets.json` at the repository root
//! (the file `flutter --dart-define-from-file` reads). With neither, Google sign-in needs
//! `--client-id`.
//!
//! The value goes into `$OUT_DIR/google_client_secret.txt` (empty without one), which
//! `providers.rs` reads with `include_str!`: never into a `cargo:` directive, which
//! `cargo build -vv` echoes into build logs.

use std::path::Path;

const VAR: &str = "SIGNPDF_GOOGLE_CLIENT_SECRET";
const OUT_FILE: &str = "google_client_secret.txt";

fn main() {
    println!("cargo:rerun-if-env-changed={VAR}");
    let out = Path::new(&std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join(OUT_FILE);
    let secret = std::env::var(VAR)
        .ok()
        .or_else(from_file)
        .unwrap_or_default();
    std::fs::write(&out, secret.trim()).expect("write the client secret into OUT_DIR");
}

/// The value in the git-ignored `secrets/client-secrets.json`, if there is one.
fn from_file() -> Option<String> {
    // Watch the folder, not the file: a missing file would make this script rerun on every build,
    // and the folder is what notices the file being created.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../secrets");
    if !dir.is_dir() {
        return None;
    }
    println!("cargo:rerun-if-changed={}", dir.display());
    let text = std::fs::read_to_string(dir.join("client-secrets.json")).ok()?;
    let json = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    json.get(VAR)?.as_str().map(str::to_owned)
}
