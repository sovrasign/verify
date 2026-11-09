//! Compiles the built-in Google client secret in from outside version control.
//!
//! Google's "Desktop app" OAuth clients must present a secret at the token endpoint even with
//! PKCE. Every copy of the app carries it, so it is not confidential, but it is still kept out of
//! the repository: a build takes it from the `SIGNPDF_GOOGLE_CLIENT_SECRET` environment variable
//! or, failing that, from the git-ignored `secrets/client-secrets.json` at the repository root
//! (the file `flutter --dart-define-from-file` reads). With neither, Google sign-in needs
//! `--client-id`.

use std::path::Path;

const VAR: &str = "SIGNPDF_GOOGLE_CLIENT_SECRET";

fn main() {
    println!("cargo:rerun-if-env-changed={VAR}");
    // Watch the folder, not the file: a missing file would make this script rerun on every build,
    // and the folder is what notices the file being created.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../secrets");
    if !dir.is_dir() {
        return;
    }
    println!("cargo:rerun-if-changed={}", dir.display());
    if std::env::var_os(VAR).is_some() {
        // `option_env!` reads the environment directly, and it wins over the file.
        return;
    }
    let secret = std::fs::read_to_string(dir.join("client-secrets.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|json| json.get(VAR)?.as_str().map(str::to_owned));
    if let Some(secret) = secret {
        println!("cargo:rustc-env={VAR}={secret}");
    }
}
