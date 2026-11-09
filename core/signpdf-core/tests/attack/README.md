# Attack corpus

One document per attack class of `docs/SECURITY_MODEL.md` §6 that a file can show, with the
verdict a verifier must give it. Published as test vectors with the compatibility corpus
(`../corpus/`) and described in `spec/envelope-format.md` §12.2.

| File | What it is |
| --- | --- |
| `<name>.pdf` | the document |
| `<name>.expected.json` | the attack in a sentence, its row in `SECURITY_MODEL.md` §6, the regression test that keeps testing the defence, the envelope's schema version, and the verdict: `outcome` (`report`, or `error` when the input is refused before a report can be made, with `error_code`), `valid`, `integrity_ok`, `identities_trusted`, and the sorted codes of the `errors` and `warnings` the report lists |
| `trust.json` | the trust store for every vector: it pins the test identity provider (`https://issuer.test`) and its application (`signpdf-test`), and nothing else |

`control-two-signers.pdf` is an honest envelope signed by Alice then Bob: it must verify as valid
under `trust.json`, which shows that every other failure is the attack's.
`signer-redirects-service-link.pdf` is valid too: the service link is not a prepared term, so a
signer who changes it gets a warning and the preparer's link is the one reported.

A conforming verifier (spec §1.2) reaches every stated verdict and should report the same codes.
`tests/attack_vectors.rs` checks this build on every `cargo test`.

## Rules

- The vectors record attacks on documents of envelope schema version 7, which is experimental
  until the first hosted release (`docs/SECURITY_MODEL.md` §8). Until then, when a format change
  breaks them, delete every file here and write them again (below). From the hosted release, a
  vector is never edited or regenerated; new attacks add new vectors.
- Every new attack class in `SECURITY_MODEL.md` §6 that a file can show gets a vector here, made
  by `tests/attack_vectors.rs` (add it to `VECTORS`).

## Writing them

```bash
cargo test -p signpdf-core --test attack_vectors -- --ignored write_attack_vectors
```

It refuses to run while any vector exists, and writes `trust.json`, every `<name>.pdf` and its
`<name>.expected.json` from this build's verifier.

## Licence

The files in this directory are dedicated to the public domain under CC0 1.0
(`LICENSES/CC0-1.0.txt`, `REUSE.toml`): copy them into your own tests freely.
