// SignPDF browser verifier.
//
// Loads `signpdf_wasm.wasm` (the Rust core compiled to WebAssembly, built by
// scripts/build-verifier.sh) and drives its small C-style ABI. Every string in a verification
// report comes from the (attacker-controlled) PDF, so it is rendered with textContent only —
// never innerHTML.
"use strict";

const TRUST_KEY = "signpdf.trust.v1";
const LANG_KEY = "signpdf.lang.v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let wasmModule = null; // compiled once; a fresh instance per operation isolates any trap
let trust = null; // current TrustStore (object)
let currentPdf = null; // Uint8Array
let lastReport = null; // the report shown, rendered again when the language changes
let lastError = null; // or the error shown

// --- language (verifier-i18n.js) ------------------------------------------------------------

const I18N = globalThis.SignpdfI18n;
let lang = "en";

/** A string of the page in its current language. */
function t(key, params) {
  return I18N.t(lang, key, params);
}

/** A catalogue word for an engine value (`prefix` + value), else the value itself. */
function word(prefix, value) {
  const key = `${prefix}${value}`;
  const s = t(key);
  return s === key ? String(value) : s;
}

function savedLanguage() {
  try {
    return localStorage.getItem(LANG_KEY);
  } catch (_) {
    return null;
  }
}

/** The page's own words (elements marked data-i18n) in the current language. */
function applyLanguage() {
  document.documentElement.lang = lang;
  for (const node of document.querySelectorAll("[data-i18n]")) {
    if (node.id === "drop-text" && currentPdf) continue; // shows the chosen file's name
    node.textContent = t(node.dataset.i18n);
  }
  document.getElementById("draft-note").hidden = !t("draft_note");
  document.title = t("title");
}

function initLanguage() {
  lang = I18N.pickLanguage(savedLanguage(), navigator.languages || [navigator.language]);
  const select = document.getElementById("lang");
  for (const [code, name] of Object.entries(I18N.LANGUAGES)) {
    const option = el("option", name);
    option.value = code;
    option.lang = code;
    select.append(option);
  }
  select.value = lang;
  select.addEventListener("change", () => {
    lang = select.value;
    try {
      localStorage.setItem(LANG_KEY, lang);
    } catch (_) {
      /* storage unavailable: the choice lasts for this visit */
    }
    applyLanguage();
    if (trust) renderIssuers();
    if (lastReport) renderReport(lastReport);
    else if (lastError) renderError(lastError);
  });
  applyLanguage();
}

// --- wasm plumbing --------------------------------------------------------------------------

/**
 * Fetch options for one of this page's files: its Subresource Integrity hash from the import map
 * the build writes into the page (scripts/sri.mjs). A built page refuses a file it does not list;
 * the unbuilt template has no list and checks nothing.
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
  if (!wasmModule) {
    const resp = await fetch("signpdf_wasm.wasm", integrityFor("signpdf_wasm.wasm"));
    if (!resp.ok) throw new Error("signpdf_wasm.wasm not found — run scripts/build-verifier.sh");
    wasmModule = await WebAssembly.compile(await resp.arrayBuffer());
  }
  return wasmModule;
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
  const ptr = ex.signpdf_result_ptr();
  const len = ex.signpdf_result_len();
  const bytes = new Uint8Array(ex.memory.buffer, ptr, len).slice();
  return { code, bytes };
}

/** The module's code for a document made by a newer SignPDF (its envelope schema version is newer
 * than this module understands). The document was neither verified nor rejected. */
const ERR_UNSUPPORTED_VERSION = 16;

async function callOk(name, ...args) {
  const { code, bytes } = await call(name, ...args);
  if (code !== 0) throw Object.assign(new Error(decoder.decode(bytes)), { code });
  return bytes;
}

// --- trust store ----------------------------------------------------------------------------

function saveTrust() {
  try {
    localStorage.setItem(TRUST_KEY, JSON.stringify(trust));
  } catch (_) {
    /* storage unavailable (private mode): keep in memory only */
  }
}

async function initTrust() {
  try {
    const saved = localStorage.getItem(TRUST_KEY);
    if (saved) trust = JSON.parse(saved);
  } catch (_) {
    trust = null;
  }
  if (!trust || !Array.isArray(trust.issuers)) {
    trust = JSON.parse(decoder.decode(await callOk("signpdf_well_known_trust")));
  }
  // The insecure dev opt-in is never persisted.
  trust.allow_insecure_dev_issuer = false;
  renderIssuers();
}

// The dev identity provider vouches for anyone, so this page never trusts it: demo documents
// are checked with the command-line tool (`signpdf verify --insecure-dev-trust`).
function trustBytes() {
  const t = { ...trust, allow_insecure_dev_issuer: false };
  return encoder.encode(JSON.stringify(t));
}

function renderIssuers() {
  const ul = document.getElementById("issuers");
  ul.replaceChildren();
  for (const iss of trust.issuers) {
    const li = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = iss.name || iss.issuer;
    const detail = document.createElement("span");
    detail.className = "muted";
    const apps = (iss.audiences || []).length;
    detail.textContent =
      ` — ${iss.issuer} — ${t("issuer_keys", { n: iss.keys.length })}, ` +
      (apps ? t("issuer_apps", { n: apps }) : t("issuer_no_apps"));
    li.append(name, detail);
    ul.append(li);
  }
  const li = document.createElement("li");
  li.textContent = t("tsa_anchors", { n: (trust.tsa_anchors || []).length });
  ul.append(li);
}

async function fetchKeys() {
  const status = document.getElementById("trust-status");
  const lines = [];
  for (const iss of trust.issuers) {
    if (!iss.jwks_uri) continue;
    try {
      const resp = await fetch(iss.jwks_uri, { credentials: "omit", cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const jwks = new Uint8Array(await resp.arrayBuffer());
      const before = iss.keys.length;
      const updated = await callOk(
        "signpdf_trust_add_jwks",
        encoder.encode(JSON.stringify(trust)),
        encoder.encode(iss.issuer),
        jwks,
      );
      trust = JSON.parse(decoder.decode(updated));
      const now = trust.issuers.find((i) => i.issuer === iss.issuer).keys.length;
      lines.push(t("fetch_new", { name: iss.name || iss.issuer, n: now - before }));
    } catch (e) {
      lines.push(t("fetch_failed", { name: iss.name || iss.issuer, error: e.message }));
    }
  }
  trust.allow_insecure_dev_issuer = false;
  saveTrust();
  renderIssuers();
  status.textContent = lines.join(" · ");
  if (currentPdf) await runVerify();
}

async function loadTrustFile(file) {
  const status = document.getElementById("trust-status");
  try {
    const store = JSON.parse(await file.text());
    if (!Array.isArray(store.issuers)) throw new Error(t("trust_not_store"));
    // A trust store decides whose signatures this page believes, and it is remembered: one
    // from the wrong hands makes forged documents show as valid from then on.
    const sure = window.confirm(t("trust_confirm", { file: file.name }));
    if (!sure) {
      status.textContent = t("trust_not_loaded");
      return;
    }
    store.allow_insecure_dev_issuer = false;
    trust = store;
    saveTrust();
    renderIssuers();
    status.textContent = t("trust_loaded", { file: file.name });
    if (currentPdf) await runVerify();
  } catch (e) {
    status.textContent = t("trust_load_failed", { error: e.message });
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

// --- rendering ------------------------------------------------------------------------------

function el(tagName, text, cls) {
  const e = document.createElement(tagName);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function tag(text, kind) {
  return el("span", text, `tag ${kind}`);
}

function renderRevision(s) {
  const li = el("li");
  const head = el("div");
  const kindName = word("kind_", s.kind);
  head.append(el("strong", s.signer_id ? t("slot", { kind: kindName, id: s.signer_id }) : kindName));
  head.append(tag(s.valid ? t("valid") : t("not_valid"), s.valid ? "ok" : "bad"));
  if (s.identity_trust) {
    const kind = { trusted: "ok", "insecure-dev": "warn", "no-trusted-time": "warn" }[s.identity_trust] || "bad";
    head.append(tag(word("trust_", s.identity_trust), kind));
  }
  if (s.level) {
    // The level by the evidence it rests on (the verifier computes it; never a grade).
    const level = I18N.levelText(lang, s.level);
    const badge = tag(level.badge, "level");
    badge.title = level.long;
    head.append(badge);
  }
  li.append(head);
  if (s.idp_email) {
    li.append(el("div", t("identity", { email: s.idp_email, provider: I18N.providerName(s.idp_issuer, trust) })));
  }
  // The evidence the level rests on: the method, who vouched for it and, where trust rests on
  // the provider that ran the check, "via" that provider.
  for (const b of s.basis || []) {
    li.append(el("div", I18N.basisText(lang, b, trust), "muted"));
  }
  const clock = s.time_source === "tsa" ? t("clock_tsa") : t("clock_device");
  li.append(el("div", t("time", { time: s.signed_at, clock, code: s.signature_code }), "muted"));
  // A device time is bounded by the identity token's issue time and the first trusted timestamp
  // after the signature (for an envelope without signature timestamps, the one added when it ends).
  if (s.time_source !== "tsa") {
    const eb = s.existed_before;
    const what = eb ? existedBeforeText(eb) : "";
    let made;
    if (s.token_issued_at && eb) made = t("made_between", { after: s.token_issued_at, before: eb.time, what });
    else if (s.token_issued_at) made = t("made_after", { after: s.token_issued_at });
    else if (eb) made = t("made_before", { before: eb.time, what });
    else made = t("made_unbounded");
    li.append(el("div", made, "muted"));
  }
  if (s.local_signed_at) {
    li.append(el("div", t("local_time", { time: s.local_signed_at, offset: s.utc_offset }), "muted"));
  }
  // The drawing beside the caption, from the signer's record: decoration, never who signed.
  if (s.drawing) {
    li.append(el("div", s.drawing === "typed" ? t("drawing_typed") : t("drawing_drawn"), "muted"));
  }
  if (s.esign_consent) {
    const c = s.esign_consent;
    const consent = el("div", `${t("consent", { version: c.version, lang: c.lang, at: c.at })} `, "muted");
    consent.append(el("code", c.sha256));
    li.append(consent);
  }
  if (s.timestamp) li.append(el("div", t("timestamp", { text: timestampText(s.timestamp) }), "muted"));
  if (s.detail) li.append(el("div", s.detail, s.valid ? "muted" : "problems"));
  return li;
}

// Which trusted timestamp bounds a revision, and from which authority.
function existedBeforeText(e) {
  const which = e.source === "document"
    ? t("eb_document", { n: e.document_timestamp })
    : e.source === "later-signature"
      ? t("eb_later", { n: e.revision })
      : t("eb_own");
  return t("eb_text", { which, tsa: e.tsa_name || "?" });
}

// A timestamp's time, authority, trust and, when the document carries validation data, whether
// it holds what long-term validation of the authority's certificates needs.
function timestampText(ts) {
  const trusted = ts.verified && ts.signature_valid && ts.trusted;
  let why = t("ts_trusted");
  if (!trusted) why = ts.detail ? t("ts_not_trusted_detail", { detail: ts.detail }) : t("ts_not_trusted");
  const ltv = { complete: t("ltv_complete"), incomplete: t("ltv_incomplete") }[ts.validation];
  const text = t("ts_text", { time: ts.time, tsa: ts.tsa_name || "?", why });
  return ltv ? `${text} · ${ltv}` : text;
}

function renderTimestamps(report) {
  const box = document.getElementById("timestamps");
  box.replaceChildren();
  const stamps = report.document_timestamps || [];
  if (!stamps.length) return;
  box.append(el("h3", t("doc_ts_h")));
  const ol = el("ol", undefined, "revisions");
  for (const d of stamps) {
    const li = el("li");
    const head = el("div");
    head.append(el("strong", t(d.added_validation_data ? "doc_ts_covers_vd" : "doc_ts_covers", { n: d.after_revision })));
    head.append(tag(d.valid ? t("valid") : t("not_valid"), d.valid ? "ok" : "bad"));
    li.append(head);
    li.append(el("div", t("doc_ts", { text: timestampText(d.timestamp) }), "muted"));
    if (d.detail) li.append(el("div", d.detail, d.valid ? "muted" : "problems"));
    ol.append(li);
  }
  box.append(ol);
  const v = report.validation_data;
  if (v) {
    box.append(el("div", t("validation_data", { certs: v.certificates, ocsp: v.ocsp_responses, crls: v.crls }), "muted"));
  }
}

function renderReport(report) {
  lastReport = report;
  lastError = null;
  document.getElementById("result").hidden = false;
  const verdict = document.getElementById("verdict");
  if (report.valid) {
    verdict.className = "verdict ok";
    verdict.textContent = t("verdict_valid");
  } else if (report.trusted_time_pending) {
    verdict.className = "verdict warn";
    verdict.textContent = t("verdict_pending");
  } else if (report.integrity_ok) {
    verdict.className = "verdict warn";
    verdict.textContent = t("verdict_untrusted");
  } else {
    verdict.className = "verdict bad";
    verdict.textContent = t("verdict_invalid");
  }

  const env = report.envelope || {};
  const summary = document.getElementById("summary");
  summary.replaceChildren();
  if (env.title) summary.append(el("div", t("doc_title", { title: env.title })));
  if (env.envelope_id) summary.append(el("div", t("envelope", { id: env.envelope_id }), "muted"));
  // An envelope of several documents, signed together as one PDF: where each one is in it, and
  // the SHA-256 of the file it was made from (part of the signed terms).
  const documents = env.documents || [];
  if (documents.length) {
    summary.append(el("div", t("documents", { n: documents.length })));
    const ol = el("ol", undefined, "documents");
    for (const d of documents) {
      const last = d.first_page + d.page_count;
      const pages = d.page_count === 1 ? t("page_one", { n: last }) : t("pages", { from: d.first_page + 1, to: last });
      const li = el("li", t("doc_item", { name: d.name, pages }));
      const digest = el("div", `${t("original_sha")} `, "muted");
      digest.append(el("code", d.source_digest));
      li.append(digest);
      ol.append(li);
    }
    summary.append(ol);
  }
  // The preparer's link back to the sending service (the engine reports only an https link the
  // preparer set; it never affects the verdict). Shown with its host, opened in a new tab.
  if (report.service_link) {
    const link = new URL(report.service_link);
    const open = el("div", `${t("open_service")} `);
    const a = el("a", link.host);
    a.href = link.href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    open.append(a);
    summary.append(open);
  }
  const state = report.declined ? t("state_declined") : report.complete ? t("state_complete") : t("state_outstanding");
  summary.append(el("div", t("status", { state })));
  // The trusted upper bound on every signing time: what bounds the last revision bounds all.
  const revisions = [report.preparer, ...(report.signatures || [])].filter(Boolean);
  const last = revisions[revisions.length - 1];
  if (last) {
    summary.append(el("div", last.existed_before
      ? t("existed_all", { time: last.existed_before.time, tsa: last.existed_before.tsa_name || "?" })
      : t("no_ts_yet")));
  }
  const sha = el("div", "SHA-256: ", "muted");
  sha.append(el("code", report.document_sha256));
  summary.append(sha);
  if (report.pades_level) {
    summary.append(el("div", t("pades", { level: report.pades_level, meaning: word("pades_", report.pades_level) }), "muted"));
  }

  const revs = document.getElementById("revisions");
  revs.replaceChildren();
  if (report.preparer) revs.append(renderRevision(report.preparer));
  for (const s of report.signatures || []) revs.append(renderRevision(s));
  renderTimestamps(report);

  const problems = document.getElementById("problems");
  problems.replaceChildren();
  // Problems and warnings are the engine's own words (English; each has a stable code).
  const engineWords = (report.messages || []).length + (report.warnings || []).length;
  if (engineWords && lang !== "en") problems.append(el("p", t("engine_english"), "muted"));
  if ((report.messages || []).length) {
    problems.append(el("h3", t("problems_h")));
    const ul = el("ul", undefined, "problems");
    for (const m of report.messages) ul.append(el("li", m));
    problems.append(ul);
  }
  if ((report.warnings || []).length) {
    problems.append(el("h3", t("warnings_h")));
    const ul = el("ul", undefined, "warnings");
    for (const w of report.warnings) ul.append(el("li", w));
    problems.append(ul);
  }

  const audit = document.getElementById("audit");
  audit.replaceChildren();
  for (const e of env.audit_log || []) {
    audit.append(el("li", `${e.at} · ${e.action} · ${e.actor_name} — ${e.details}`));
  }
  document.getElementById("raw").textContent = JSON.stringify(report, null, 2);
}

function renderError(error) {
  lastError = error;
  lastReport = null;
  document.getElementById("result").hidden = false;
  const verdict = document.getElementById("verdict");
  if (error.code === ERR_UNSUPPORTED_VERSION) {
    // Not a verdict on the document: this copy of the verifier is older than the document.
    verdict.className = "verdict warn";
    verdict.textContent = t("verdict_newer");
  } else {
    verdict.className = "verdict bad";
    verdict.textContent = t("verdict_error", { error: error.message });
  }
  for (const id of ["summary", "revisions", "timestamps", "problems", "audit"]) {
    document.getElementById(id).replaceChildren();
  }
  document.getElementById("raw").textContent = "";
}

// --- actions --------------------------------------------------------------------------------

async function runVerify() {
  try {
    // The page's time, for the trust list's algorithm policy (end dates of algorithms).
    const now = encoder.encode(String(Math.floor(Date.now() / 1000)));
    const bytes = await callOk("signpdf_verify_at", currentPdf, trustBytes(), now);
    renderReport(JSON.parse(decoder.decode(bytes)));
  } catch (e) {
    renderError(e);
  }
}

async function onPdf(file) {
  if (!file) return;
  document.getElementById("drop-text").textContent = file.name;
  currentPdf = new Uint8Array(await file.arrayBuffer());
  await runVerify();
}

window.addEventListener("DOMContentLoaded", async () => {
  initLanguage();
  const drop = document.getElementById("drop");
  document.getElementById("pdf").addEventListener("change", (e) => onPdf(e.target.files[0]));
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    onPdf(e.dataTransfer.files[0]);
  });
  document.getElementById("fetch-keys").addEventListener("click", fetchKeys);
  document.getElementById("trust-file").addEventListener("change", (e) => loadTrustFile(e.target.files[0]));
  document.getElementById("export-trust").addEventListener("click", () => {
    const exported = JSON.stringify({ ...trust, allow_insecure_dev_issuer: false }, null, 2);
    download(encoder.encode(exported), "trust.json", "application/json");
  });
  document.getElementById("certificate").addEventListener("click", async () => {
    if (!currentPdf) return;
    try {
      download(await callOk("signpdf_certificate", currentPdf, trustBytes()), "certificate.pdf", "application/pdf");
    } catch (e) {
      renderError(e);
    }
  });
  try {
    await initTrust();
  } catch (e) {
    document.getElementById("trust-status").textContent = e.message;
  }
});
