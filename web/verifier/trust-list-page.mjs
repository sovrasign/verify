// The signed trust list in the built browser verifier, end to end in Chromium (spec/envelope-format.md
// §9.2; trust-list.js). A provider's key that it no longer publishes is still trusted when the
// signed list the page follows holds it, and only then:
//
// 1. The page's own store knows the provider (https://issuer.test, its application) but not the
//    key that signed the attack corpus's honest control document, as when the provider rotated
//    the key out of its JWKS: the signers' identities are not verified (`unknown-key`).
// 2. The same page following a signed list that holds the key (signed by a trust-list key the
//    build pins): the document is valid and its signers verified; the page names the list.
// 3. A list holding the key but signed by a key the build does not pin is refused: not verified.
// 4. The publisher unreachable on a later visit: the list kept in the browser is used (checked
//    again under the pins), and the page says so.
//
// Needs Playwright with its Chromium (as a11y.mjs). Run after scripts/build-verifier.sh:
//
//   node web/verifier/trust-list-page.mjs
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch (_) {
  console.error("needs playwright (npm install --no-save --no-package-lock playwright@1.63.0)");
  process.exit(2);
}

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..", "..");
const attack = join(root, "core/signpdf-core/tests/attack");
if (!existsSync(join(here, "signpdf_wasm.wasm"))) {
  console.error("usage: node web/verifier/trust-list-page.mjs  (after scripts/build-verifier.sh)");
  process.exit(2);
}
const pdf = join(attack, "control-two-signers.pdf");
const full = JSON.parse(readFileSync(join(attack, "trust.json"), "utf8"));

// --- a publisher's signed list (detached ES256 JWS, kid = RFC 7638 thumbprint) ----------------

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
async function listKey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const pub = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
  const kid = b64u(await crypto.subtle.digest("SHA-256", Buffer.from(JSON.stringify({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y }))));
  return { pair, pub, kid };
}
async function signList(key, store, sequence) {
  const issued = new Date();
  const list = {
    ...store,
    type: "sovrasign-trust-list",
    schema: 2,
    sequence,
    issued_at: issued.toISOString().replace(/\.\d+Z$/, "Z"),
    expires_at: new Date(issued.getTime() + 30 * 86400000).toISOString().replace(/\.\d+Z$/, "Z"),
    publisher: "https://publisher.test",
    cells: ["test-1"],
    next_keys: [],
  };
  const payload = JSON.stringify(list, null, 2);
  const header = b64u(Buffer.from(JSON.stringify({ alg: "ES256", kid: key.kid })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.pair.privateKey, Buffer.from(`${header}.${b64u(Buffer.from(payload))}`));
  return { payload, jws: `${header}..${b64u(sig)}` };
}

const pinned = await listKey();
const stranger = await listKey();
const good = await signList(pinned, full, 1);
const forged = await signList(stranger, full, 99);

// The page's own store: the provider and its application, without the key (rotated out).
const withoutKey = { ...full, issuers: full.issuers.map((i) => ({ ...i, keys: [], jwks_uri: undefined })) };

// --- the built page, in a folder of its own, with a trust-list.js pinning `pinned` -----------

const site = mkdtempSync(join(tmpdir(), "signpdf-trust-list-"));
for (const f of ["index.template.html", "verifier-i18n.js", "verifier.js", "verifier.css", "signpdf_wasm.wasm"]) copyFileSync(join(here, f), join(site, f));
let served = null; // the list the publisher serves now: {payload, jws}, or null (unreachable)
const server = createServer((req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^[/\\]+/, "") || "index.html";
  if (path.startsWith("list")) {
    if (!served) return res.writeHead(503).end();
    const body = path.endsWith(".jws") ? served.jws : served.payload;
    return res.writeHead(200, { "content-type": "application/json" }).end(body);
  }
  const file = join(site, path);
  const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".wasm": "application/wasm" };
  if (!file.startsWith(site) || !existsSync(file)) return res.writeHead(404).end();
  res.writeHead(200, { "content-type": types[extname(file)] || "application/octet-stream" }).end(readFileSync(file));
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const url = `http://127.0.0.1:${server.address().port}/`;

function build(follow) {
  const head = readFileSync(join(here, "trust-list.js"), "utf8").split("globalThis.SignpdfTrustList")[0];
  const cfg = follow ? { url: `${url}list/trust.json`, keys: [pinned.pub] } : { url: "", keys: [] };
  writeFileSync(join(site, "trust-list.js"), `${head}globalThis.SignpdfTrustList = ${JSON.stringify(cfg)};\n`);
  execFileSync(process.execPath, [join(root, "scripts/sri.mjs"), site], { stdio: "ignore" });
}

const problems = [];
const browser = await chromium.launch();
async function visit(context, label) {
  const page = await context.newPage();
  page.on("pageerror", (e) => problems.push(`${label}: page error ${e.message}`));
  await page.goto(url);
  await page.waitForFunction(() => document.querySelectorAll("#issuers li").length > 0);
  await page.setInputFiles("#pdf", pdf);
  await page.waitForFunction(() => !document.getElementById("result").hidden && document.getElementById("raw").textContent.length > 0);
  const report = JSON.parse(await page.textContent("#raw"));
  const note = await page.evaluate(() => {
    const p = document.getElementById("trust-list-status");
    return p.hidden ? "" : p.textContent;
  });
  await page.close();
  return { report, note, trust: report.signatures.map((s) => s.identity_trust) };
}
const ok = (cond, msg) => cond || problems.push(msg);

try {
  // 1. No list: the provider is known, its old key is not.
  build(false);
  let context = await browser.newContext({ locale: "en-US" });
  await context.addInitScript((store) => localStorage.setItem("signpdf.trust.v1", store), JSON.stringify(withoutKey));
  let r = await visit(context, "no list");
  ok(r.trust.length === 2 && r.trust.every((t) => t === "unknown-key"), `no list: identities ${r.trust}`);
  ok(!r.report.identities_trusted, "no list: identities trusted without the key");
  ok(r.note === "", `no list: a trust-list note: ${r.note}`);
  await context.close();

  // 2. The signed list holds the key: verified.
  build(true);
  served = good;
  context = await browser.newContext({ locale: "en-US" });
  await context.addInitScript((store) => {
    if (!sessionStorage.getItem("seeded")) {
      localStorage.setItem("signpdf.trust.v1", store);
      sessionStorage.setItem("seeded", "1");
    }
  }, JSON.stringify(withoutKey));
  r = await visit(context, "signed list");
  ok(r.report.valid === true && r.report.identities_trusted === true, `signed list: valid ${r.report.valid}, identities ${r.trust}`);
  ok(r.trust.every((t) => t === "trusted"), `signed list: identities ${r.trust}`);
  ok(/Signed trust list 1 of https:\/\/publisher\.test/.test(r.note), `signed list: note ${r.note}`);

  // 4. Later, the publisher is unreachable: the kept list still verifies the document.
  served = null;
  r = await visit(context, "offline");
  ok(r.report.identities_trusted === true, `offline: identities ${r.trust}`);
  ok(/Signed trust list 1 .*could not be reached/.test(r.note), `offline: note ${r.note}`);
  await context.close();

  // 3. A list signed by a key the build does not pin: refused, never used.
  served = forged;
  context = await browser.newContext({ locale: "en-US" });
  await context.addInitScript((store) => localStorage.setItem("signpdf.trust.v1", store), JSON.stringify(withoutKey));
  r = await visit(context, "stranger's list");
  ok(r.trust.every((t) => t === "unknown-key"), `stranger's list: identities ${r.trust}`);
  ok(/needs a newer version of this page/.test(r.note), `stranger's list: note ${r.note}`);
  // A tampered list under the pinned key: refused too.
  served = { payload: good.payload.replace('"sequence": 1', '"sequence": 2'), jws: good.jws };
  r = await visit(context, "tampered list");
  ok(r.trust.every((t) => t === "unknown-key"), `tampered list: identities ${r.trust}`);
  ok(/was refused \(bad_signature\)/.test(r.note), `tampered list: note ${r.note}`);
  await context.close();
} finally {
  await browser.close();
  server.close();
  rmSync(site, { recursive: true, force: true });
}

if (problems.length) {
  for (const p of problems) console.error(`trust list: ${p}`);
  process.exit(1);
}
console.log("browser verifier trust-list check passed (a rotated-out key verified through the signed list; a stranger's and a tampered list refused; offline uses the kept list)");
