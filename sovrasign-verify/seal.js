// The service's seal on a certificate of completion. The
// same rules as service/api/src/evidence/seal.rs:
//
//   <the certificate's bytes, ending in %%EOF and a line break>
//   %SOVRASIGN-SEAL <compact JWS, ES256, typ sovrasign-seal+jws>
//   startxref
//   <the same offset as the certificate's last startxref>
//   %%EOF
//
// The JWS payload names how many bytes come before the seal line and their SHA-256. Anything
// changed before the line changes the hash; anything added after it is not the exact ending
// above. The keys are the service's evidence keys (GET /v1/evidence/jwks), checked by their
// RFC 7638 thumbprint. Pure functions over bytes, with WebCrypto: tools/seal.test.mjs runs them.

const MARKER = "%SOVRASIGN-SEAL ";
const TYP = "sovrasign-seal+jws";
const FORMAT = "sovrasign.seal/1";

const latin1 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return s;
};

function b64urlBytes(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

/** The offset of the last `startxref` of `text` (a latin1 view of a PDF), or null. */
function lastStartxref(text) {
  const at = text.lastIndexOf("startxref");
  if (at < 0) return null;
  const m = /^\s*(\d+)/.exec(text.slice(at + 9, at + 40));
  return m ? m[1] : null;
}

/**
 * The seal line of `bytes`, when there is one: `{at, jws, tailOk}` (`at`: the number of bytes
 * before it; `tailOk`: what follows is exactly the ending the service writes). Null: no seal.
 */
export function findSeal(bytes) {
  const text = latin1(bytes);
  const at = text.lastIndexOf(`\n${MARKER}`);
  if (at < 0) return null;
  const start = at + 1;
  const after = text.slice(start + MARKER.length);
  const end = after.indexOf("\n");
  if (end < 0) return null;
  const jws = after.slice(0, end);
  if (!/^[A-Za-z0-9_.-]+$/.test(jws)) return null;
  const xref = lastStartxref(text.slice(0, start));
  const tailOk = xref !== null && after.slice(end + 1) === `startxref\n${xref}\n%%EOF\n`;
  return { at: start, jws, tailOk };
}

/** RFC 7638 thumbprint of an EC P-256 JWK. */
async function thumbprint(jwk) {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return btoa(String.fromCharCode(...new Uint8Array(d))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Check a sealed certificate against `jwks` (`{keys: [...]}`). Returns `{state, statement?}`:
 * `sealed` (unchanged since it was sealed), `changed`, `added` (something appended after the
 * seal), `unknown_key`, `bad` (the seal is not readable or does not verify) or `none` (no seal).
 */
export async function checkSeal(bytes, jwks) {
  const found = findSeal(bytes);
  if (!found) return { state: "none" };
  const parts = found.jws.split(".");
  if (parts.length !== 3) return { state: "bad" };
  let header;
  let statement;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlBytes(parts[0])));
    statement = JSON.parse(new TextDecoder().decode(b64urlBytes(parts[1])));
  } catch {
    return { state: "bad" };
  }
  if (header.alg !== "ES256" || header.typ !== TYP || statement.format !== FORMAT) return { state: "bad" };
  let key = null;
  for (const k of (jwks && jwks.keys) || []) {
    if (k.kty === "EC" && k.crv === "P-256" && (await thumbprint(k)) === header.kid) key = k;
  }
  if (!key) return { state: "unknown_key", statement };
  let ok = false;
  try {
    const pub = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: key.x, y: key.y, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, b64urlBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  } catch {
    ok = false;
  }
  if (!ok) return { state: "bad", statement };
  const digest = hex(await crypto.subtle.digest("SHA-256", bytes.subarray(0, found.at)));
  if (statement.len !== found.at || statement.sha256 !== digest) return { state: "changed", statement };
  if (!found.tailOk) return { state: "added", statement };
  return { state: "sealed", statement };
}
