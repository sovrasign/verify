// Sovrasign Verify, built on SignPDF: the hosted verifier page.
//
// It loads the engine's verifier module (signpdf_wasm.wasm: the SignPDF Rust core compiled to
// WebAssembly, the same module as the engine's own offline verifier) and drives its C-style ABI:
// signpdf_verify_at, signpdf_certificate, signpdf_well_known_trust, signpdf_trust_add_jwks. The
// engine decides; words.js says what its report means.
//
// Every string in a report comes from the PDF, which anyone can write, so it is shown with
// textContent only: the page's CSP enforces Trusted Types with no policy, so no string can reach
// an HTML sink.
//
// "Check it yourself": a page of this site that holds a signed PDF (the signer's
// Done card, the completed copy, the sender's envelope page) opens /verify/#check=<id> and hands
// the bytes over a BroadcastChannel, which only pages of the same origin can join. Nothing is
// uploaded; the file goes from one tab of this browser to another.
import {
  documentsView,
  documentTimeLine,
  errorVerdict,
  fmtTime,
  isDevTrust,
  providerName,
  revisionCard,
  revisionView,
  stampView,
  statusLine,
  sealVerdict,
  verdict,
} from "./words.js";
import { checkSeal, findSeal } from "./seal.js";
import { TrustList, browserStorage, statusWords } from "./trust-list.js";
import { TRUST as BUILD_TRUST } from "./trust-pins.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (id) => document.getElementById(id);

/** The channel "Check it yourself" hands files over (web/app/src/lib/check-yourself.js). */
const CHANNEL = "sovrasign-verify";

let wasmModule = null; // compiled once; a fresh instance per operation isolates any trap
let trust = null; // the trust list in use (the engine's JSON format)
let published = null; // the service's published list, when it loaded
let currentPdf = null; // Uint8Array
let currentName = "";

// --- the engine -------------------------------------------------------------------------------

/**
 * Fetch options for one of this page's files: its Subresource Integrity hash from the import map
 * the build writes into the page (scripts/sri.mjs). A built page refuses a file it does not list.
 */
function integrityFor(name) {
  const map = document.querySelector('script[type="importmap"]');
  if (!map) return {};
  const url = new URL(name, document.baseURI).href;
  for (const [u, integrity] of Object.entries(JSON.parse(map.textContent).integrity || {})) {
    if (new URL(u, document.baseURI).href === url) return { integrity };
  }
  throw new Error(`${name} is not in this page's integrity list`);
}

async function loadModule() {
  if (!wasmModule) wasmModule = await WebAssembly.compile(await fetchModule());
  return wasmModule;
}

/**
 * The verifier module's bytes, fetched when the first file is checked: possibly after a deploy
 * replaced the page's version, whose module then fails its integrity check. Tried once more (a
 * network blip); then, when the site serves another version of the page, the error says so
 * (`code: "updated"`, words.js) instead of the browser's.
 */
async function fetchModule() {
  for (let attempt = 0; ; attempt++) {
    try {
      const resp = await fetch("signpdf_wasm.wasm", { ...integrityFor("signpdf_wasm.wasm"), cache: attempt ? "reload" : "default" });
      if (!resp.ok) throw new Error(`the verifier module did not load (HTTP ${resp.status})`);
      return await resp.arrayBuffer();
    } catch (e) {
      if (attempt === 0) {
        await new Promise((r) => setTimeout(r, 800));
        continue;
      }
      if (await pageReplaced()) throw Object.assign(new Error("Sovrasign Verify was updated"), { code: "updated" });
      throw e;
    }
  }
}

/** Whether the site now lists another module than this page does (its integrity.json, fresh). */
async function pageReplaced() {
  try {
    const mine = integrityFor("signpdf_wasm.wasm").integrity;
    const r = await fetch("integrity.json", { cache: "no-store", credentials: "omit" });
    const now = r.ok ? (await r.json())["signpdf_wasm.wasm"] : null;
    return Boolean(mine && now && now !== mine);
  } catch {
    return false;
  }
}

/** Call an exported operation with byte-array arguments; returns {code, bytes}. */
async function call(name, ...args) {
  const instance = await WebAssembly.instantiate(await loadModule(), {});
  const ex = instance.exports;
  const ptrs = args.map((bytes) => {
    const ptr = ex.signpdf_alloc(bytes.length);
    new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  });
  const code = ex[name](...ptrs.flat());
  const bytes = new Uint8Array(ex.memory.buffer, ex.signpdf_result_ptr(), ex.signpdf_result_len()).slice();
  return { code, bytes };
}

async function callOk(name, ...args) {
  const { code, bytes } = await call(name, ...args);
  if (code !== 0) throw Object.assign(new Error(decoder.decode(bytes)), { code });
  return bytes;
}

// --- the trust list ---------------------------------------------------------------------------

/** The trust list never allows the engine's insecure development opt-in on this page. */
const safe = (t) => ({ ...t, allow_insecure_dev_issuer: false });
const trustBytes = () => encoder.encode(JSON.stringify(safe(trust)));

/**
 * The published list as last loaded, kept on this device so the page still checks documents
 * when the list cannot be fetched (cookie notice A5: public keys only, no personal data). A list
 * the visitor loads from a file is never kept.
 */
const TRUST_KEY = "signpdf.trust.v1";

function keep(t) {
  try {
    localStorage.setItem(TRUST_KEY, JSON.stringify(t));
  } catch {
    /* storage unavailable (private mode): nothing kept */
  }
}

function kept() {
  try {
    const t = JSON.parse(localStorage.getItem(TRUST_KEY) || "null");
    return t && Array.isArray(t.issuers) ? safe(t) : null;
  } catch {
    return null;
  }
}

/**
 * Start with Sovrasign's signed trust list: fetched on every load from the address the
 * meta tag names (same site) and believed only when its signature verifies under the trust-list
 * key built into this page (trust-pins.js); offline, the copy kept on this device, else the one
 * bundled in this build, with a warning when it is more than 30 days old and "Update the app"
 * when the service's list is signed by a key this build cannot follow.
 *
 * A build without pins (local and CI builds) keeps the earlier behaviour: the service's own
 * store, unsigned, then the copy kept from an earlier visit, else the engine's built-in list.
 */
async function initTrust() {
  if (BUILD_TRUST.pins.length) {
    const url = document.querySelector('meta[name="sovrasign-trust-list"]')?.content || "";
    const t = await new TrustList({ ...BUILD_TRUST, url, storage: browserStorage() }).load();
    const outcome = await t.refresh({ force: true });
    const s = t.status();
    if (s.list) {
      published = safe(s.list);
      signedStatus = s;
      usePublished();
      const lines = statusWords(s);
      if (outcome === "unreachable") {
        lines.unshift(`Sovrasign's trust list could not be fetched just now; this page uses ${s.source === "cached" ? "the copy saved on this device" : "the copy built into this page"}.`);
      }
      $("trust-status").textContent = lines.join(" ");
      return;
    }
  }
  const url = document.querySelector('meta[name="sovrasign-trust"]')?.content;
  let why = "";
  if (url) {
    try {
      const resp = await fetch(url, { credentials: "omit", cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const t = await resp.json();
      if (!Array.isArray(t.issuers)) throw new Error("not a trust list");
      published = safe(t);
      keep(published);
    } catch (e) {
      why = `Sovrasign's published trust list did not load (${e.message}).`;
      published = kept();
    }
  }
  if (published) {
    usePublished();
    if (why) $("trust-status").textContent = `${why} Using the copy saved on this device.`;
  } else {
    setTrust(safe(JSON.parse(decoder.decode(await callOk("signpdf_well_known_trust")))), "builtin");
    if (why) $("trust-status").textContent = `${why} Using the engine's built-in list.`;
  }
}

/** The signed list in use, when this build pins a trust-list key (TrustList.status()). */
let signedStatus = null;

const fmtDay = (iso) => (iso ? String(iso).slice(0, 10) : "?");

function usePublished() {
  setTrust(published, "published");
}

function setTrust(t, source) {
  trust = t;
  $("trust-source").textContent = {
    published: signedStatus
      ? `This page uses Sovrasign's signed trust list ${signedStatus.sequence} (issued ${fmtDay(signedStatus.issuedAt)}), checked with the trust-list key built into this page.`
      : "This page uses Sovrasign's published trust list.",
    builtin: "This page uses the engine's built-in list of well-known providers.",
    file: "This page uses a trust list you loaded, for this visit only.",
    fetched: "This page uses the list below, with the keys just fetched, for this visit only.",
  }[source];
  $("use-published").hidden = !published || source === "published";
  $("dev-trust").hidden = !isDevTrust(trust);
  renderIssuers();
}

function renderIssuers() {
  const ul = $("issuers");
  ul.replaceChildren();
  for (const iss of trust.issuers) {
    const li = el("li");
    li.append(el("strong", iss.name || providerName(iss.issuer, trust)));
    const apps = (iss.audiences || []).length;
    li.append(
      el("span", ` — ${iss.issuer} — ${(iss.keys || []).length} key(s), ${apps ? `${apps} app(s)` : "no app"}`, "muted"),
    );
    ul.append(li);
  }
  ul.append(el("li", `Timestamp authorities: ${(trust.tsa_anchors || []).length}`));
}

async function fetchKeys() {
  const lines = [];
  let t = trust;
  for (const iss of t.issuers) {
    if (!iss.jwks_uri) continue;
    try {
      const resp = await fetch(iss.jwks_uri, { credentials: "omit", cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const jwks = new Uint8Array(await resp.arrayBuffer());
      const before = (iss.keys || []).length;
      t = JSON.parse(decoder.decode(await callOk("signpdf_trust_add_jwks", encoder.encode(JSON.stringify(t)), encoder.encode(iss.issuer), jwks)));
      const now = t.issuers.find((i) => i.issuer === iss.issuer).keys.length;
      lines.push(`${iss.name || iss.issuer}: ${now - before} new key(s)`);
    } catch (e) {
      lines.push(`${iss.name || iss.issuer}: not fetched (${e.message})`);
    }
  }
  setTrust(safe(t), "fetched");
  $("trust-status").textContent = lines.join(" · ") || "No provider publishes its keys at a known address.";
  if (currentPdf) await runVerify();
}

async function loadTrustFile(file) {
  const status = $("trust-status");
  try {
    const t = JSON.parse(await file.text());
    if (!Array.isArray(t.issuers)) throw new Error("not a SignPDF trust list");
    // A trust list decides whose signatures this page believes: one from the wrong hands makes
    // forged documents look valid.
    const sure = window.confirm(
      "A trust list decides whose signatures this page believes.\n\n" +
        "Load one only if you made it yourself or got it from someone you trust. " +
        "Never load one because the sender of a document asks you to.\n\nLoad " + file.name + " for this visit?",
    );
    if (!sure) {
      status.textContent = "Trust list not loaded.";
      return;
    }
    setTrust(safe(t), "file");
    status.textContent = `Loaded ${file.name}.`;
    if (currentPdf) await runVerify();
  } catch (e) {
    status.textContent = `Could not load the trust list: ${e.message}`;
  }
}

function download(bytes, name, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --- rendering --------------------------------------------------------------------------------

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function showVerdict(v) {
  $("result").hidden = false;
  const box = $("verdict");
  box.className = `verdict ${v.kind}`;
  $("verdict-title").textContent = v.title;
  $("verdict-line").textContent = v.line;
}

let detailsCount = 0; // ids for each card's "Details" button and the lines it shows

/**
 * One signer's or the sender's card: the summary line and any warning
 * always show; the evidence lines sit behind a "Details" button (aria-expanded, closed by default,
 * open in print: verify.css). A button rather than <details>, so print can open it in every browser.
 */
function renderRevision(s, report) {
  const v = revisionView(s, report, trust);
  const card = revisionCard(v);
  const li = el("li");
  const who = el("div", undefined, "who");
  who.append(el("span", v.role, "role"));
  const label = v.name || v.email || "Unknown";
  who.append(el("strong", label));
  for (const t of v.tags) who.append(el("span", t.text, `tag ${t.kind}`));
  if (v.method) who.append(el("span", v.method, "method"));
  li.append(who);
  if (v.name && v.email && v.name !== v.email) li.append(el("p", v.email, "line small muted"));
  for (const line of card.alerts) li.append(el("p", line, "why"));
  if (card.details.length) {
    const id = `details-${++detailsCount}`;
    const toggle = el("button", undefined, "secondary details-toggle");
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-controls", id);
    toggle.append(el("span", "Details"), el("span", ` for ${label}`, "visually-hidden"));
    const body = el("div", undefined, "details-body");
    body.id = id;
    for (const d of card.details) body.append(el("p", d.text, d.muted ? "line small muted" : "line small"));
    toggle.addEventListener("click", () => {
      const open = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(open));
      body.classList.toggle("open", open);
    });
    li.append(toggle, body);
  }
  return li;
}

function renderTimestamps(report) {
  const box = $("timestamps");
  box.replaceChildren();
  const stamps = report.document_timestamps || [];
  if (!stamps.length) return;
  const card = el("div", undefined, "card");
  card.append(el("h2", stamps.length > 1 ? "Document timestamps" : "Document timestamp"));
  const ol = el("ol", undefined, "revisions");
  for (const d of stamps) {
    const v = stampView(d);
    const li = el("li");
    const who = el("div", undefined, "who");
    who.append(el("strong", v.line));
    who.append(el("span", v.valid ? "Valid" : "Not valid", `tag ${v.valid ? "ok" : "bad"}`));
    li.append(who);
    li.append(el("p", v.trust, "line small muted"));
    if (v.detail) li.append(el("p", v.detail, "why"));
    ol.append(li);
  }
  card.append(ol);
  box.append(card);
}

function renderList(box, title, items, cls) {
  if (!items.length) return;
  const card = el("div", undefined, "card");
  card.append(el("h2", title));
  const ul = el("ul", undefined, cls);
  for (const m of items) ul.append(el("li", m));
  card.append(ul);
  box.append(card);
}

function renderReport(report) {
  showVerdict(verdict(report));
  const env = report.envelope || {};
  $("doc-title").textContent = env.title || currentName || "Signed document";
  const summary = $("summary");
  summary.replaceChildren();
  summary.append(el("div", statusLine(report)));
  if (env.created_by || env.created_by_email) {
    const by = env.created_by && env.created_by_email && env.created_by !== env.created_by_email
      ? `${env.created_by} <${env.created_by_email}>`
      : env.created_by || env.created_by_email;
    summary.append(el("div", `Sent by ${by}`, "muted"));
  }
  // An envelope of several documents, signed together as this one PDF.
  const docs = documentsView(report);
  if (docs.length) {
    summary.append(el("div", `${docs.length} documents, signed together as this one PDF:`));
    const ol = el("ol", undefined, "documents");
    for (const d of docs) {
      const li = el("li", d.line);
      const sha = el("div", "Original file SHA-256: ", "muted");
      sha.append(el("code", d.sha256));
      li.append(sha);
      ol.append(li);
    }
    summary.append(ol);
  }
  const time = documentTimeLine(report);
  if (time) summary.append(el("div", time));
  // The preparer's link back to the service that sent it (never part of the verdict).
  if (report.service_link) {
    const link = new URL(report.service_link);
    const open = el("div", "Open it in the service that sent it: ", "muted");
    const a = el("a", link.host);
    a.href = link.href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    open.append(a);
    summary.append(open);
  }

  const revs = $("revisions");
  revs.replaceChildren();
  for (const s of [report.preparer, ...(report.signatures || [])].filter(Boolean)) revs.append(renderRevision(s, report));
  renderTimestamps(report);

  const problems = $("problems");
  problems.replaceChildren();
  renderList(problems, "What failed", report.messages || [], "problems");
  renderList(problems, "Warnings", report.warnings || [], "warnings");

  const audit = $("audit");
  audit.replaceChildren();
  for (const e of env.audit_log || []) audit.append(el("li", `${fmtTime(e.at, { seconds: true })} · ${e.action} · ${e.actor_name} — ${e.details}`));

  const tech = $("tech");
  tech.replaceChildren();
  const row = (k, v) => {
    if (!v && v !== 0) return;
    tech.append(el("dt", k));
    const dd = el("dd");
    dd.append(el("code", String(v)));
    tech.append(dd);
  };
  row("SHA-256", report.document_sha256);
  row("Envelope", env.envelope_id);
  row("Size", `${report.original_len} bytes`);
  row("PAdES level", report.pades_level);
  row("Algorithm policy", report.algorithm_policy?.version);
  $("tech-report").hidden = false;
  $("raw").textContent = JSON.stringify(report, null, 2);
  $("certificate").hidden = false;
}

function renderError(error) {
  showVerdict(errorVerdict(error));
  $("doc-title").textContent = currentName || "";
  for (const id of ["summary", "revisions", "timestamps", "problems", "audit", "tech"]) $(id).replaceChildren();
  $("certificate").hidden = true;
  $("raw").textContent = "";
}

// --- actions ----------------------------------------------------------------------------------

/**
 * A certificate of completion sealed by Sovrasign: not a signed document, so the
 * engine has nothing to check; its seal is checked against the service's evidence keys.
 */
async function runSealCheck() {
  let jwks = { keys: [] };
  try {
    const url = document.querySelector('meta[name="sovrasign-evidence-keys"]')?.content || "/v1/evidence/jwks";
    const resp = await fetch(url, { credentials: "omit", cache: "no-store" });
    if (resp.ok) jwks = await resp.json();
  } catch {
    /* no keys: the seal reads as unknown */
  }
  const result = await checkSeal(currentPdf, jwks);
  showVerdict(sealVerdict(result));
  const s = result.statement;
  const deletion = s?.what === "deletion";
  const invoice = s?.what === "invoice";
  $("doc-title").textContent =
    currentName || (deletion ? "Certificate of deletion" : invoice ? "Invoice" : "Certificate of completion");
  for (const id of ["summary", "revisions", "timestamps", "problems", "audit", "tech"]) $(id).replaceChildren();
  if (s?.envelope && !invoice) {
    $("summary").append(el("div", `${deletion ? "Certificate" : "Envelope"} ${s.envelope}`, "muted"));
  }
  $("certificate").hidden = true;
  $("raw").textContent = s ? JSON.stringify(s, null, 2) : "";
}

async function runVerify() {
  if (findSeal(currentPdf)) {
    await runSealCheck();
    $("verdict").focus({ preventScroll: true });
    return;
  }
  try {
    // The page's time, for the trust list's algorithm policy (end dates of algorithms).
    const now = encoder.encode(String(Math.floor(Date.now() / 1000)));
    const bytes = await callOk("signpdf_verify_at", currentPdf, trustBytes(), now);
    renderReport(JSON.parse(decoder.decode(bytes)));
  } catch (e) {
    renderError(e);
  }
  $("verdict").focus({ preventScroll: true });
  $("result").scrollIntoView({ block: "start", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

async function onBytes(bytes, name) {
  currentPdf = bytes;
  currentName = name || "";
  $("drop-text").textContent = currentName || "Signed PDF";
  if (!trust) await trustReady;
  await runVerify();
}

async function onFile(file) {
  if (!file) return;
  $("handoff").hidden = true;
  await onBytes(new Uint8Array(await file.arrayBuffer()), file.name);
}

/**
 * "Check it yourself": the page that opened this one hands over the PDF it holds. Only pages of
 * this origin can join the channel; the id in the address says which file is meant, so another
 * tab's hand-over is never mixed up with this one.
 */
function receiveHandOff() {
  const id = new URLSearchParams(location.hash.slice(1)).get("check");
  if (!id) return;
  history.replaceState(null, "", location.pathname + location.search);
  const note = $("handoff");
  if (!/^[A-Za-z0-9-]{8,64}$/.test(id) || typeof BroadcastChannel !== "function") return;
  note.hidden = false;
  note.textContent = "Getting the PDF from the page you came from…";
  const channel = new BroadcastChannel(CHANNEL);
  let got = false;
  let asks = 0;
  const ask = () => {
    if (got) return;
    if (asks++ >= 60) {
      channel.close();
      note.textContent = "The page you came from did not send the PDF. Choose the file you saved instead.";
      return;
    }
    channel.postMessage({ type: "ready", id });
    setTimeout(ask, 500);
  };
  channel.onmessage = (e) => {
    const m = e.data;
    if (got || !m || m.type !== "file" || m.id !== id) return;
    const bytes = m.bytes instanceof Uint8Array ? m.bytes : m.bytes instanceof ArrayBuffer ? new Uint8Array(m.bytes) : null;
    if (!bytes) return;
    got = true;
    channel.close();
    const name = typeof m.name === "string" ? m.name.slice(0, 200) : "";
    note.textContent = `Checking ${name || "the PDF"} from the page you came from. It stays in this browser.`;
    onBytes(bytes, name);
  };
  ask();
}

// A phone or tablet: no dropping, so the drop zone just says "Choose".
function followDevice() {
  if (!matchMedia("(pointer: coarse)").matches) return;
  for (const e of document.querySelectorAll("[data-touch]")) e.textContent = e.dataset.touch;
}

let trustReady;

window.addEventListener("DOMContentLoaded", () => {
  followDevice();
  const drop = $("drop");
  $("pdf").addEventListener("change", (e) => onFile(e.target.files[0]));
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    onFile(e.dataTransfer.files[0]);
  });
  $("fetch-keys").addEventListener("click", fetchKeys);
  $("load-trust").addEventListener("click", () => $("trust-file").click());
  $("trust-file").addEventListener("change", (e) => loadTrustFile(e.target.files[0]));
  $("use-published").addEventListener("click", async () => {
    usePublished();
    $("trust-status").textContent = "";
    if (currentPdf) await runVerify();
  });
  $("export-trust").addEventListener("click", () => {
    download(encoder.encode(JSON.stringify(safe(trust), null, 2)), "trust.json", "application/json");
  });
  $("certificate").addEventListener("click", async () => {
    if (!currentPdf) return;
    try {
      const name = `${(currentName || "document").replace(/\.pdf$/i, "")} - certificate.pdf`;
      download(await callOk("signpdf_certificate", currentPdf, trustBytes()), name, "application/pdf");
    } catch (e) {
      renderError(e);
    }
  });
  trustReady = initTrust().catch((e) => {
    $("trust-status").textContent = `The trust list did not load: ${e.message}`;
  });
  receiveHandOff();
});
