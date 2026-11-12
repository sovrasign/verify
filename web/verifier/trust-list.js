// The signed trust list this page follows (spec/envelope-format.md §9.2): the address of a
// publisher's `trust.json` (its detached JWS is the same address with `.jws`) and the publisher's
// trust-list key chain this build pins, in order (the key in use, then the keys it pre-committed).
// The page believes a list only when its signature verifies under that chain (the engine's
// key-chain rule, `signpdf_trust_list_consider`), so a server or a network in between cannot hand
// it a list of their own; the pins are part of the page, covered by its integrity hashes.
//
// Empty here: the engine's own page follows no publisher. scripts/build-pages-site.sh writes this
// file when TRUST_LIST_URL is set, with the keys of tools/archive/trust-list-keys.json, the same
// keys the trust-list archive checks the published lists with.
"use strict";
globalThis.SignpdfTrustList = { url: "", keys: [] };
