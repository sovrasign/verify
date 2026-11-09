# Sovrasign Verify

Check a document signed with [Sovrasign](https://sovrasign.com) yourself, on your own computer,
without us: who signed it, with which identity, when, and that nothing changed after each
signature. This repository holds everything that check needs, under open licences:

- **Sovrasign Verify**, the verifier page at `sovrasign.com/verify/` (`sovrasign-verify/`);
- **the open signing engine it is built on** (`core/`), whose WebAssembly module makes every
  decision the page shows; its crates keep their working name, SignPDF, for now;
- **the engine's own verifier page** and **command-line verifier**, which need no service at all;
- **the description of the document format** (`spec/envelope-format.md`) and its **test files**,
  so anyone can write a second, independent verifier and prove it against the same documents.

Nothing is uploaded: the verifier runs in your browser or on your machine, and reads the file you
give it. A signed document keeps verifying with this code even if the service that signed it is
gone.

## What is where

| Path | What it is |
| --- | --- |
| `sovrasign-verify/` | Sovrasign Verify: the page, the plain-language report (`words.js`), the check of the certificate of completion's seal (`seal.js`), the signed trust list (`trust-list.js`) |
| `core/signpdf-core/` | the rules: PDF revisions, PAdES signatures, identity evidence, timestamps, trust lists |
| `core/signpdf-wasm/` | the WebAssembly module both verifier pages load |
| `core/signpdf-cli/` | `signpdf`, the command-line reference verifier |
| `core/signpdf-auth/`, `core/signpdf-ffi/` | sign-in helpers and the native binding the engine's apps use |
| `web/verifier/` | the engine's own verifier page |
| `spec/` | the format description (`envelope-format.md`) and the shared trust-list test vectors |
| `core/signpdf-core/tests/corpus/`, `core/signpdf-core/tests/attack/` | test documents: ones that must verify, and attacks that must fail |
| `tools/archive/`, `.github/workflows/trust-archive.yml` | the public, append-only archive of the signed trust lists |
| `scripts/` | building the module reproducibly and the pages with their integrity hashes |
| `docs/` | the security model (`SECURITY_MODEL.md`) and two security reviews of the engine, the dependency audits (`SUPPLY_CHAIN.md`), releases and archives (`RELEASES.md`) |

## Check a document

**In the browser.** Build Sovrasign Verify (it needs the tools listed under "Build" below),
serve the folder with any static file server and open it:

```sh
sh scripts/build-sovrasign-verify.sh
python3 -m http.server -d dist/sovrasign-verify 8080   # then open http://localhost:8080/
```

Served from anywhere other than the service, the page cannot fetch the service's current trust
list: it starts from the engine's built-in list of well-known sign-in providers, and "Load a
trust.json" under "Technical details and trust list" takes the list you choose.

**On the command line**, with Rust installed:

```sh
cd core
cargo run -p signpdf-cli -- verify --input document.pdf               # well-known providers
cargo run -p signpdf-cli -- verify --input document.pdf --trust trust.json
cargo run -p signpdf-cli -- verify --help
```

It exits 0 for a valid document and 1 otherwise; `--json` prints the full report.

## Build

| Need | For |
| --- | --- |
| Rust, with the toolchain in `scripts/wasm-toolchain` and the `wasm32-unknown-unknown` target | the engine and its module |
| Node.js 22 | the pages' integrity hashes (`scripts/sri.mjs`) |
| podman or docker (optional) | the reproducible build in a pinned container |

```sh
sh scripts/build-verifier.sh                         # the module, and the engine's page in web/verifier/
sh scripts/build-sovrasign-verify.sh                 # Sovrasign Verify in dist/sovrasign-verify/
scripts/build-wasm-reproducible.sh --container       # the module byte for byte as published
```

`build-wasm-reproducible.sh` prints the SHA-256 of the module; the same commit gives the same
bytes on any machine, so you can compare it with the module the service serves. To build Sovrasign
Verify with that module instead, `WASM=core/target/wasm-repro/out/signpdf_verifier.wasm sh
scripts/build-sovrasign-verify.sh`.

Tests: `cd core && cargo test --all` runs the engine's tests, the compatibility corpus and the
attack vectors. [CONTRIBUTING.md](CONTRIBUTING.md) lists the rest.

## Licences

- Code: the [MIT licence](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your choice.
- The format description (`spec/`): [CC BY 4.0](LICENSES/CC-BY-4.0.txt).
- The test files (`spec/vectors/`, `core/signpdf-core/tests/corpus/`, `core/signpdf-core/tests/attack/`):
  [CC0 1.0](LICENSES/CC0-1.0.txt), so you can copy them into your own tests.

[`REUSE.toml`](REUSE.toml) says which licence covers which file. The licences do not cover the
names Sovrasign and SignPDF or their logos. Forks are welcome, and may say that they are based on
SignPDF, but may not use these names or logos as their own product's name, and may not claim that
documents they sign are verified by Sovrasign.

## Security

A flaw that lets a forged or altered document pass is the most serious bug this code can have.
Report it privately, never in a public issue: [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome: [CONTRIBUTING.md](CONTRIBUTING.md).
