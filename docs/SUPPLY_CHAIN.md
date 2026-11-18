# Supply chain: cargo vet

Every Rust crate the engine builds with is vouched for by [cargo vet](https://mozilla.github.io/cargo-vet/).
Its files are in `core/supply-chain/`:

| File | What it holds |
| --- | --- |
| `config.toml` | The audits we import, and the **exemptions**: crate versions trusted without an audit |
| `audits.toml` | Our own audits |
| `imports.lock` | The imported audits as they were when last fetched (`cargo vet --locked` reads only this) |
| `critical.txt` | The crates on the signing and verification path: RustCrypto, X.509, CMS, PDF parsing, the JSON of envelopes and tokens |
| `critical-baseline.txt` | The frozen baseline for those crates: the (crate, version) pairs exempted when cargo vet came in. It only shrinks |

## Imported audits

Audits published by Mozilla, Google, the Bytecode Alliance, the Zcash Foundation, ISRG, Embark
Studios and Ariel OS. Together they cover 54 of the 197 crates in the tree (October 2026).

## The baseline and the rule for new versions

When cargo vet was introduced, every crate version not covered by an imported audit was
recorded as an exemption: the **baseline**. From then on:

- `cargo vet --locked` (in CI on every pull request that touches the engine) fails when a dependency is added or updated to a version nobody vouches
  for. Before adopting it: find an imported audit (`cargo vet` fetches newer ones), or audit it
  (`cargo vet diff` from the last vouched version, then `cargo vet certify`).
- For the crates in `critical.txt`, that is the only way: `scripts/vet-critical.py` fails when one
  of them is exempted at a (crate, version) that `critical-baseline.txt` does not list, whatever
  the exemption's notes say. That list only shrinks: when an audit covers a version, its line goes
  (the script fails while the list names a version that is no longer exempted), and a pull request
  that adds a line to it is refused in review. For other crates an exemption is allowed when the
  pull request says why.
- cargo vet compares its store files byte for byte, with LF line endings. `.gitattributes` keeps
  `core/supply-chain/` LF on Windows checkouts (`core.autocrlf=true`); `scripts/vet-critical.py`
  says so plainly if a checkout still has CRLF there.

## The audit backlog

`scripts/vet-critical.py` prints the critical crate versions still vouched for by the baseline
only: 39 in October 2026, most of them the RustCrypto release candidates the engine adopted for
constant-time arithmetic (p256 0.14, ecdsa 0.17, crypto-bigint 0.7, rsa 0.10, cms 0.3, der 0.8 and
their helpers), which no imported audit covers yet. Each one leaves the backlog when an imported
audit covers it or we audit it; a newer version of one is adopted only with an audit.

Two were cleared at once when cargo vet came in, by moving to patch releases that imported audits
cover: zeroize 1.9.1 (it fixes a possible read of uninitialised memory in the fallback
optimisation barrier, the one WebAssembly uses) and cpufeatures 0.3.1 (it fixes the detection of
AVX on x86).

**November 2026: 11 left.** 28 of the 39 were audited (`audits.toml`, 2026-11-18): the helpers
and smaller crates in full (base16ct, base64ct, hybrid-array, spki, sec1, pkcs1, pkcs8, rfc6979,
ff, group, primefield, primeorder, der_derive, digest, ecdsa, elliptic-curve, const-oid, weezl)
and the rest as deltas from a vouched version (block-buffer, cpufeatures, crypto-common, hmac, pem-rfc7468, sha1, sha2,
signature, flate2; rsa and pkcs1 to their final releases earlier). These are AI-assisted reviews
(Claude Code), and their notes say so and what they covered: every unsafe block, build-time code,
file, network and process access, and panics reachable from untrusted input. They are not a
review of cryptographic correctness; the engine's test vectors and fuzz targets cover that part.

The 11 left are the large ones, each exemption's `notes` in `config.toml` saying why and when it
is reviewed: crypto-bigint (52,000 lines), der (the delta from 0.7 is 8,000 lines), lopdf and nom
(to be replaced by the planned move to lopdf 0.47), x509-cert and cms, serde_json, getrandom (one
OS backend per platform), p256 (field arithmetic, which needs a correctness review rather than an
unsafe-code review), crypto-primes (RSA key generation only), and
rsa 0.10.0-rc.19 (the base of the audited delta to 0.10.0, which the engine builds). Cargo vet
itself is clean: `cargo vet --locked` passes and no critical crate is exempted outside the
baseline. Trusting a publisher instead (`cargo vet trust`, as Mozilla does for some) is not used
for the critical crates: the rule stays an audit or an imported audit.

## Commands

```sh
cargo install cargo-vet --locked
cd core
cargo vet --locked            # what CI runs: no network
cargo vet                     # also fetch newer imported audits
cargo vet suggest             # the cheapest audits that would shrink the exemptions
cargo vet diff <crate> <from> <to>
cargo vet certify <crate> <from> <to>
python3 ../scripts/vet-critical.py
```
