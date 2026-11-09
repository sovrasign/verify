// The signed trust list in a client.
//
// The service signs `trust.json` with its trust-list key (a detached ES256 JWS, served beside the
// list as `trust.json.jws`; service/api/src/trust_list.rs). A client believes a list only when
// that signature verifies under a key of its key chain: the keys built into this release, in
// order (trust/pins/<environment>.json: the key in use, then its pre-committed successors), plus
// the `next_keys` that lists of the chain's last key pre-committed. So a server cannot hand the
// page a list of its own.
//
// The key-chain rule (the engine's signpdf_core::trust_list, signpdf spec,
// the shared vectors tools/fixtures/trust-list-rotation.json):
// - the signing key's position in the chain decides first: a list signed by a key later in the
//   chain than the list held wins over any sequence an earlier key signed, and the earlier keys'
//   lists are then refused (`older_key`). A list forged with a stolen key and a huge sequence so
//   loses to the first real list of the next key;
// - under the same key, the higher sequence wins (`older` for a lower one);
// - only a list signed by the chain's last key extends the chain with its `next_keys`. The
//   extensions are kept as steps (`{by, keys}`) and replayed on the pins at every load: a step
//   counts only when its key is then the chain's last, so a release with new pins drops what an
//   older chain added. The key in use cannot rewrite or withdraw its successors; a pre-committed
//   key that is itself compromised is removed by new pins.
//
// - Bundled: each release build carries the newest list at build time, so the page verifies
//   offline and on first use.
// - Cached: the newest list the client has believed is kept on the device and used when the
//   service cannot be reached.
// - Refreshed: at most once a day (the web verifier on every load), never replacing a list by an
//   older one (the key-chain rule above).
// - Warnings: a list more than 30 days old (its `issued_at`), and "Update the app" when the
//   service's newest list is signed by a key this build cannot follow: pins carry the current key
//   and the two pre-committed next keys, so that means more than two trust-list keys behind.
//
// The same rules are written in Dart for the web app (web/sender/lib/trust/) and the desktop app
// (signpdf app/lib/src/trust/); docs/design/trust-list-clients.md describes them.
// Runs in browsers and in Node 20+ (tests): only WebCrypto, TextEncoder and fetch.

export const LIST_TYPE = "sovrasign-trust-list";
/** The newest list layout this client reads (trust_list.rs LIST_SCHEMA): 2 adds `tsa_distrusted`
 * and the key-chain rule. */
export const SCHEMA = 2;
/** A list older than this is stale: the client warns. */
export const STALE_DAYS = 30;
/** How often a client asks for a newer list (daily). */
export const REFRESH_MS = 24 * 3600 * 1000;
const DAY_MS = 24 * 3600 * 1000;

const enc = new TextEncoder();
const b64uDecode = (s) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};
const b64uEncode = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** RFC 7638 thumbprint of a P-256 public JWK. */
export async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64uEncode(await crypto.subtle.digest("SHA-256", enc.encode(canonical)));
}

/** A key's id: its `kid`, else its thumbprint. */
const keyIds = async (jwk) => new Set([jwk.kid, await thumbprint(jwk)].filter(Boolean));

/**
 * Check the detached JWS `jws` (`header..signature`) over the exact text `payload` against
 * `keys` (public P-256 JWKs). Returns `{ok: true, list, kid}` or `{ok: false, reason, kid?}` with
 * reason `malformed`, `unknown_key` (signed by a key this client does not pin), `bad_signature`,
 * `not_a_list` or `newer_schema` (a list layout this build cannot read: update the app).
 */
export async function verifySigned(payload, jws, keys) {
  const parts = String(jws || "").trim().split(".");
  if (parts.length !== 3 || parts[1] !== "") return { ok: false, reason: "malformed" };
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(b64uDecode(parts[0])));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (header.alg !== "ES256") return { ok: false, reason: "malformed" };
  const kid = String(header.kid || "");
  let key = null;
  let position = -1;
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (k && k.kty === "EC" && k.crv === "P-256" && (await keyIds(k)).has(kid)) {
      key = k;
      position = i;
      break;
    }
  }
  if (!key) return { ok: false, reason: "unknown_key", kid };
  let good = false;
  try {
    const pub = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: key.x, y: key.y, ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const input = enc.encode(`${parts[0]}.${b64uEncode(enc.encode(payload))}`);
    good = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, b64uDecode(parts[2]), input);
  } catch {
    good = false;
  }
  if (!good) return { ok: false, reason: "bad_signature", kid };
  let list;
  try {
    list = JSON.parse(payload);
  } catch {
    return { ok: false, reason: "not_a_list", kid };
  }
  if (!list || list.type !== LIST_TYPE || !Array.isArray(list.issuers) || !Number.isInteger(list.sequence)) {
    return { ok: false, reason: "not_a_list", kid };
  }
  if (!(list.schema <= SCHEMA)) return { ok: false, reason: "newer_schema", kid };
  return { ok: true, list, kid, key, position };
}

/** Whole days since the list was issued (0 when unknown or in the future). */
export function ageDays(list, now = Date.now()) {
  const t = Date.parse(list?.issued_at || "");
  return Number.isFinite(t) ? Math.max(0, Math.floor((now - t) / DAY_MS)) : 0;
}

/** The key chain: the pins, then each step's keys. */
export const chainOf = (pins, steps) => [...(pins || []), ...(steps || []).flatMap((s) => s.keys)];

/** The public P-256 keys of `next` that `chain` does not hold yet, in order. */
export async function freshKeys(chain, next) {
  const have = new Set(await Promise.all(chain.map(thumbprint)));
  const out = [];
  for (const k of Array.isArray(next) ? next : []) {
    if (!publicP256(k)) continue;
    const t = await thumbprint(k);
    if (!have.has(t)) {
      have.add(t);
      out.push(k);
    }
  }
  return out;
}

/** Kept `steps` replayed on `pins`: each counts only when its key (`by`, a thumbprint) is then the
 * chain's last; the first that does not ends the replay. */
export async function replaySteps(pins, steps) {
  const out = [];
  for (const s of Array.isArray(steps) ? steps : []) {
    const chain = chainOf(pins, out);
    if (!s || !chain.length || (await thumbprint(chain[chain.length - 1])) !== s.by) break;
    const keys = await freshKeys(chain, s.keys);
    if (keys.length) out.push({ by: s.by, keys });
  }
  return out;
}

/** The browser's localStorage as this module's storage, or nothing when it is unavailable. */
export function browserStorage() {
  return {
    get(key) {
      try {
        return localStorage.getItem(key);
      } catch {
        return null;
      }
    },
    set(key, value) {
      try {
        localStorage.setItem(key, value);
      } catch {
        /* storage unavailable (private mode): nothing kept */
      }
    },
  };
}

function publicP256(k) {
  return Boolean(k) && k.kty === "EC" && k.crv === "P-256" && typeof k.x === "string" && typeof k.y === "string" && !("d" in k);
}

export const CACHE_KEY = "sovrasign.trust-list.v1";

/**
 * A client's signed trust list: what it believes now, where that came from, and how fresh it is.
 *
 * `pins`: this build's pinned trust-list keys; `bundle`: `{payload, jws}` built into this release
 * (or null); `url`: where the service serves `trust.json` (its signature at `url + ".jws"`);
 * `storage`: `{get, set}` of strings; `fetch` and `now` for tests.
 */
export class TrustList {
  constructor({ pins = [], bundle = null, url = "", storage = null, fetch: f = globalThis.fetch?.bind(globalThis), now = () => Date.now() } = {}) {
    Object.assign(this, { pins, bundle, url, storage, fetchFn: f, now });
    this.held = null; // {payload, jws, list, source, checkedAt, position}
    this.steps = []; // the chain's extensions beyond the pins, `{by, keys}` (kept with the cache)
    this.behind = false; // the newest list is signed by a key this build cannot follow
    this.newerSchema = false;
    this.lastError = "";
  }

  /** True when this build pins at least one key (a release build). */
  get pinned() {
    return this.pins.length > 0;
  }

  /** The key chain a list must be signed by: the pins, then the keys the chain's last keys
   * pre-committed. */
  keys() {
    return chainOf(this.pins, this.steps);
  }

  /** Take `{payload, jws}` from `source` when it verifies and the key-chain rule allows it. */
  async consider(payload, jws, source, checkedAt = 0) {
    if (typeof payload !== "string" || typeof jws !== "string") return { ok: false, reason: "malformed" };
    const chain = this.keys();
    const r = await verifySigned(payload, jws, chain);
    if (!r.ok) return r;
    const held = this.held?.list;
    if (held) {
      // The key's position in the chain first, then the sequence.
      if (r.position < this.held.position) return { ok: false, reason: "older_key" };
      if (r.position === this.held.position) {
        if (r.list.sequence < held.sequence) return { ok: false, reason: "older" };
        if (r.list.sequence === held.sequence) {
          this.held.checkedAt = Math.max(this.held.checkedAt, checkedAt);
          return { ok: true, list: held, same: true };
        }
      }
    }
    // Only the chain's last key extends it.
    if (r.position === chain.length - 1) {
      const keys = await freshKeys(chain, r.list.next_keys);
      if (keys.length) this.steps = [...this.steps, { by: await thumbprint(r.key), keys }];
    }
    this.held = { payload, jws, list: r.list, source, checkedAt, position: r.position };
    return r;
  }

  /** The bundled list, then the cached one (whichever is newer wins). No network. */
  async load() {
    if (!this.pinned) return this;
    if (this.bundle) await this.consider(this.bundle.payload, this.bundle.jws, "bundled");
    const raw = this.storage?.get(CACHE_KEY);
    if (!raw) return this;
    try {
      const c = JSON.parse(raw);
      // The cache keeps the chain's extensions (`steps`), so a list signed after a rotation
      // still verifies after a restart; they are replayed on this release's pins. The device's
      // storage is trusted as much as the app's own code; a key there is only ever a P-256
      // public key.
      this.steps = await replaySteps(this.pins, c.steps);
      const r = await this.consider(c.payload, c.jws, "cached", Number(c.checkedAt) || 0);
      if (r.ok) this.behind = Boolean(c.behind);
    } catch {
      /* a damaged cache is ignored */
    }
    return this;
  }

  /** Keep the list held, with the keys it can be checked under, on the device. */
  save() {
    if (!this.storage || !this.held) return;
    this.storage.set(
      CACHE_KEY,
      JSON.stringify({ payload: this.held.payload, jws: this.held.jws, checkedAt: this.held.checkedAt, steps: this.steps, behind: this.behind }),
    );
  }

  /** True when the last check is older than a day (or there never was one). */
  due() {
    return !this.held || this.now() - (this.held.checkedAt || 0) >= REFRESH_MS;
  }

  /**
   * Ask the service for its newest list when a day has passed since the last check (`force`:
   * now). Offline or refused, the list held stays. Returns the outcome's reason or "ok".
   */
  async refresh({ force = false } = {}) {
    if (!this.pinned || !this.url || !this.fetchFn) return "off";
    if (!force && !this.due()) return "fresh";
    let payload, jws;
    try {
      const get = async (u) => {
        const resp = await this.fetchFn(u, { credentials: "omit", cache: "no-cache" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.text();
      };
      [payload, jws] = await Promise.all([get(this.url), get(`${this.url}.jws`)]);
    } catch (e) {
      this.lastError = e.message || String(e);
      return "unreachable";
    }
    const now = this.now();
    const r = await this.consider(payload, jws, "fetched", now);
    this.behind = !r.ok && r.reason === "unknown_key";
    this.newerSchema = !r.ok && r.reason === "newer_schema";
    if (r.ok || r.reason === "older" || r.reason === "older_key" || this.behind || this.newerSchema) {
      // A check that reached the service counts as today's, even when it changed nothing.
      if (this.held) this.held.checkedAt = Math.max(this.held.checkedAt || 0, now);
    }
    if (!r.ok) this.lastError = r.reason;
    this.save();
    return r.ok ? "ok" : r.reason;
  }

  /**
   * What the client shows: `{source, sequence, issuedAt, ageDays, stale, updateApp, list}`;
   * `source` is "fetched", "cached", "bundled" or "none".
   */
  status() {
    const list = this.held?.list || null;
    const days = list ? ageDays(list, this.now()) : 0;
    return {
      source: this.held?.source || "none",
      sequence: list?.sequence ?? null,
      issuedAt: list?.issued_at ?? null,
      ageDays: days,
      stale: Boolean(list) && days > STALE_DAYS,
      updateApp: this.behind || this.newerSchema,
      list,
    };
  }
}

/** The status's sentences in English: the age warning and "Update the app" (or none). */
export function statusWords(s, { app = "this page" } = {}) {
  const out = [];
  if (s.updateApp) {
    out.push(
      `Update the app: ${app} cannot check Sovrasign's newest trust list (it is signed with a newer key than this version knows), so documents signed with new sign-in keys may show as unknown.`,
    );
  }
  if (s.stale) {
    out.push(`The trust list on this device is ${s.ageDays} days old. Connect to the internet so it can be refreshed.`);
  }
  return out;
}
