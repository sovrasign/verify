// Writes spec/vectors/trust-list-rotation.json: the shared test vectors for the signed trust
// list's key-chain accept rule (spec/envelope-format.md §9.2, §12.4). Released under CC0 1.0.
//
//   node spec/vectors/make-trust-list-vectors.mjs > spec/vectors/trust-list-rotation.json
//
// Five fresh P-256 trust-list keys are made in memory; only their public halves and the lists
// they signed are written (the private keys are discarded, so regenerating gives new vectors).
// Node 20+ (WebCrypto only).

const enc = new TextEncoder();
const b64u = (b) => Buffer.from(b).toString("base64url");

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canonical))));
}

const names = ["A", "B", "C", "D", "X"];
const keys = {};
for (const n of names) {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { kty, crv, x, y };
  jwk.kid = await thumbprint(jwk);
  keys[n] = { jwk, priv: pair.privateKey };
}

async function sign(by, sequence, { next = [], schema = 2 } = {}) {
  const list = {
    type: "sovrasign-trust-list",
    schema,
    sequence,
    issued_at: "2026-11-01T00:00:00Z",
    expires_at: "2026-12-01T00:00:00Z",
    publisher: "vectors",
    issuers: [],
    tsa_anchors: [],
    next_keys: next.map((n) => keys[n].jwk),
  };
  const payload = JSON.stringify(list);
  const header = { alg: "ES256", kid: keys[by].jwk.kid, typ: "JOSE", cty: "sovrasign-trust-list" };
  const h = b64u(enc.encode(JSON.stringify(header)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keys[by].priv,
    enc.encode(`${h}.${b64u(enc.encode(payload))}`),
  );
  return { signed_by: by, payload, jws: `${h}..${b64u(new Uint8Array(sig))}` };
}

const lists = {
  a1: await sign("A", 1, { next: ["B"] }),
  // Forged with the stolen key A: the largest safe integer, nothing pre-committed.
  a_forged: await sign("A", 9007199254740991),
  // A list from A pre-committing a key of its own choosing: A is not the chain's last key.
  a_announces_x: await sign("A", 4, { next: ["X"] }),
  // The bridge list from the pre-committed backup B, pre-committing C and D.
  b2: await sign("B", 2, { next: ["C", "D"] }),
  // The old key replayed after the rotation, with a higher sequence than b2.
  a3: await sign("A", 3, { next: ["B"] }),
  c3: await sign("C", 3, { next: ["D"] }),
  b4: await sign("B", 4, { next: ["C", "D"] }),
  c5: await sign("C", 5, { next: ["D"] }),
  x5: await sign("X", 5),
  d6: await sign("D", 6),
  a7_schema3: await sign("A", 7, { schema: 3 }),
};
// The same list with its signature over other bytes.
lists.a1_tampered = { ...lists.a1, payload: lists.a1.payload.replace('"sequence":1', '"sequence":8') };

// Each case: a client pinning `pins` (in chain order) takes the steps in order. A step is
// `{list, expect}` (the outcome of considering the list, then the client saves its state), or
// `{restart: true}` (a new client with the same pins loads the saved state), or
// `{update: [pins]}` (a new client with other pins loads the saved state: an app update).
// `held` is the sequence of the list held after the last step (null: none).
const cases = [
  {
    name: "a forged high sequence from the old key, then the new key's real list: the new key wins",
    pins: ["A", "B"],
    steps: [
      { list: "a1", expect: "ok" },
      { list: "a_forged", expect: "ok" },
      { list: "b2", expect: "ok" },
      { list: "a_forged", expect: "older_key" },
      { list: "a3", expect: "older_key" },
      { restart: true },
      { list: "a_forged", expect: "older_key" },
    ],
    held: 2,
  },
  {
    name: "a key outside the chain is refused",
    pins: ["A", "B"],
    steps: [
      { list: "a1", expect: "ok" },
      { list: "x5", expect: "unknown_key" },
    ],
    held: 1,
  },
  {
    name: "the old key's list replayed after the rotation is refused, also after a restart",
    pins: ["A", "B"],
    steps: [
      { list: "b2", expect: "ok" },
      { restart: true },
      { list: "a3", expect: "older_key" },
      { list: "a1", expect: "older_key" },
    ],
    held: 2,
  },
  {
    name: "keys pre-committed by the chain's last key are followed, in order, also after a restart",
    pins: ["A", "B"],
    steps: [
      { list: "a1", expect: "ok" },
      { list: "b2", expect: "ok" },
      { restart: true },
      { list: "c3", expect: "ok" },
      { list: "b4", expect: "older_key" },
      { list: "c5", expect: "ok" },
      { list: "d6", expect: "ok" },
      { list: "c5", expect: "older_key" },
    ],
    held: 6,
  },
  {
    name: "next keys from a key that is not the chain's last add nothing",
    pins: ["A", "B"],
    steps: [
      { list: "a_announces_x", expect: "ok" },
      { list: "x5", expect: "unknown_key" },
      { restart: true },
      { list: "x5", expect: "unknown_key" },
    ],
    held: 4,
  },
  {
    name: "a build pinning one key follows that key's next keys",
    pins: ["A"],
    steps: [
      { list: "a1", expect: "ok" },
      { list: "b2", expect: "ok" },
      { list: "a3", expect: "older_key" },
    ],
    held: 2,
  },
  {
    name: "under one key the higher sequence wins",
    pins: ["A", "B"],
    steps: [
      { list: "a3", expect: "ok" },
      { list: "a1", expect: "older" },
      { list: "a3", expect: "ok" },
      { list: "a_announces_x", expect: "ok" },
    ],
    held: 4,
  },
  {
    name: "refusals: a bad signature, a newer layout",
    pins: ["A", "B"],
    steps: [
      { list: "a1_tampered", expect: "bad_signature" },
      { list: "a7_schema3", expect: "newer_schema" },
      { list: "a1", expect: "ok" },
    ],
    held: 1,
  },
  {
    name: "an update with new pins drops the chain the old pins grew and the list of a key it no longer pins",
    pins: ["A", "B"],
    steps: [
      { list: "b2", expect: "ok" },
      { update: ["C", "D"] },
      { list: "b4", expect: "unknown_key" },
      { list: "c3", expect: "ok" },
    ],
    held: 3,
  },
];

const out = {
  about:
    "Shared test vectors for the signed trust list's key-chain accept rule (spec/envelope-format.md §9.2, §12.4). GENERATED by spec/vectors/make-trust-list-vectors.mjs; CC0 1.0. Keys are public halves only.",
  keys: Object.fromEntries(names.map((n) => [n, keys[n].jwk])),
  lists,
  cases,
};
console.log(JSON.stringify(out, null, 1));
