// Sovrasign Verify: the hosted verifier page.
//
// It loads the engine's verifier module (signpdf_wasm.wasm: the SignPDF Rust core compiled to
// WebAssembly, the same module as the engine's own offline verifier) and drives its C-style ABI:
// signpdf_verify_at, signpdf_certificate_named, signpdf_well_known_trust, signpdf_trust_add_jwks. The
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
//
// Ten languages: the words come from l10n/verify_<lang>.arb (i18n.js), the page's own
// text from its data-l10n attributes; the visitor picks the language in the header.
import {
  countPdfSignatures,
  documentsView,
  documentTimeLine,
  errorVerdict,
  fmtTime,
  isDevTrust,
  providerName,
  revisionCard,
  senderLine,
  revisionView,
  stampView,
  statusLine,
  sealVerdict,
  verdict,
} from "./words.js";
import { checkSealWithList, findSeal } from "./seal.js";
import { LANGS, NAMES, lang, pickLang, t, useCatalogs } from "./i18n.js";
import EN from "./l10n-en.js";
import { TrustList, browserStorage, trustForHost } from "./trust-list.js";
import { TRUST as BUILT_TRUST } from "./trust-pins.js";

// The pins apply on the hosts they name (production's own; trust-list.js trustForHost).
const BUILD_TRUST = trustForHost(BUILT_TRUST, location.hostname);

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

// --- the page's languages -----------------------------------------------------------

/** Load `code`'s words (its module is in the page's integrity list), then say everything again. */
async function setLanguage(code, { keep = false } = {}) {
  let cat = EN;
  if (code !== "en") {
    try {
      cat = (await import(`./l10n-${code}.js`)).default;
    } catch {
      code = "en"; // a language that did not load: English
    }
  }
  useCatalogs(code, cat, EN);
  if (keep) {
    // The choice stays in the address (?lang=), so a reload or a shared link keeps it; nothing is
    // stored on the device (the cookie notice lists no item for this page's language).
    try {
      const u = new URL(location.href);
      u.searchParams.set("lang", code);
      history.replaceState(history.state, "", u);
    } catch {
      /* this visit only */
    }
  }
  document.documentElement.lang = code;
  applyStatic();
  if (trust) setTrust(trust, trustSource);
  sayTrustStatus();
  if (handOffNote) $("handoff").textContent = handOffNote();
  if (currentPdf) await runVerify({ focus: false });
}

/** The page's own text in the language in use (data-l10n, and data-l10n-touch on phones). */
function applyStatic() {
  const touch = matchMedia("(pointer: coarse)").matches;
  for (const e of document.querySelectorAll("[data-l10n]")) {
    if (e.id === "drop-text" && currentPdf) continue; // shows the file's name
    e.textContent = t(touch && e.dataset.l10nTouch ? e.dataset.l10nTouch : e.dataset.l10n);
  }
  const select = $("lang");
  if (select) select.value = lang();
}

function languageMenu() {
  const select = $("lang");
  for (const code of LANGS) {
    const o = el("option", NAMES[code]);
    o.value = code;
    o.lang = code;
    select.append(o);
  }
  select.value = lang();
  select.addEventListener("change", () => setLanguage(select.value, { keep: true }));
}

/** The trust list's status line: a function, so a change of language says it again. */
let trustStatus = () => "";
function setTrustStatus(fn) {
  trustStatus = fn;
  sayTrustStatus();
}
const sayTrustStatus = () => {
  $("trust-status").textContent = trustStatus();
};

/** The signed list's age warning and "Reload the page" (TrustList.status()), in the page's words. */
function statusLines(s) {
  const out = [];
  if (s.updateApp) out.push(t("trust_update_page"));
  if (s.stale) out.push(t("trust_stale", { n: s.ageDays }));
  return out;
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
      setTrustStatus(() => {
        const lines = statusLines(s);
        if (outcome === "unreachable") lines.unshift(t(s.source === "cached" ? "trust_unreachable_saved" : "trust_unreachable_built"));
        return lines.join(" ");
      });
      return;
    }
  }
  const url = document.querySelector('meta[name="sovrasign-trust"]')?.content;
  let why = "";
  if (url) {
    try {
      const resp = await fetch(url, { credentials: "omit", cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const list = await resp.json();
      if (!Array.isArray(list.issuers)) throw new Error(t("trust_not_a_list"));
      published = safe(list);
      keep(published);
    } catch (e) {
      why = e.message;
      published = kept();
    }
  }
  if (published) {
    usePublished();
    if (why) setTrustStatus(() => t("trust_failed_saved", { error: why }));
  } else {
    setTrust(safe(JSON.parse(decoder.decode(await callOk("signpdf_well_known_trust")))), "builtin");
    if (why) setTrustStatus(() => t("trust_failed_builtin", { error: why }));
  }
}

/** The signed list in use, when this build pins a trust-list key (TrustList.status()). */
let signedStatus = null;

const fmtDay = (iso) => (iso ? String(iso).slice(0, 10) : "?");

function usePublished() {
  setTrust(published, "published");
}

let trustSource = "";

function setTrust(list, source) {
  trust = list;
  trustSource = source;
  $("trust-source").textContent =
    source === "published"
      ? signedStatus
        ? t("source_signed", { sequence: signedStatus.sequence, date: fmtDay(signedStatus.issuedAt) })
        : t("source_published")
      : t(`source_${source}`);
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
    const keys = t("issuer_keys", { n: (iss.keys || []).length });
    li.append(el("span", ` — ${iss.issuer} — ${keys}, ${apps ? t("issuer_apps", { n: apps }) : t("issuer_no_app")}`, "muted"));
    ul.append(li);
  }
  ul.append(el("li", t("tsa_count", { n: (trust.tsa_anchors || []).length })));
}

async function fetchKeys() {
  const lines = [];
  let list = trust;
  for (const iss of list.issuers) {
    if (!iss.jwks_uri) continue;
    try {
      const resp = await fetch(iss.jwks_uri, { credentials: "omit", cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const jwks = new Uint8Array(await resp.arrayBuffer());
      const before = (iss.keys || []).length;
      list = JSON.parse(decoder.decode(await callOk("signpdf_trust_add_jwks", encoder.encode(JSON.stringify(list)), encoder.encode(iss.issuer), jwks)));
      const now = list.issuers.find((i) => i.issuer === iss.issuer).keys.length;
      lines.push({ key: "fetch_new_keys", values: { name: iss.name || iss.issuer, n: now - before } });
    } catch (e) {
      lines.push({ key: "fetch_not_fetched", values: { name: iss.name || iss.issuer, error: e.message } });
    }
  }
  setTrust(safe(list), "fetched");
  setTrustStatus(() => lines.map((l) => t(l.key, l.values)).join(" · ") || t("fetch_none"));
  if (currentPdf) await runVerify();
}

async function loadTrustFile(file) {
  try {
    const list = JSON.parse(await file.text());
    if (!Array.isArray(list.issuers)) throw new Error(t("trust_not_a_list"));
    // A trust list decides whose signatures this page believes: one from the wrong hands makes
    // forged documents look valid.
    const sure = window.confirm(t("trust_confirm", { file: file.name }));
    if (!sure) {
      setTrustStatus(() => t("trust_not_loaded"));
      return;
    }
    setTrust(safe(list), "file");
    setTrustStatus(() => t("trust_loaded", { file: file.name }));
    if (currentPdf) await runVerify();
  } catch (e) {
    setTrustStatus(() => t("trust_load_failed", { error: e.message }));
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
  // Where else to check a file (another service's PDF signatures; words.js OTHER_VERIFIERS).
  const links = $("verdict-links");
  links.replaceChildren();
  for (const l of v.links || []) {
    const a = el("a", l.text);
    a.href = l.href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    links.append(el("li"));
    links.lastChild.append(a);
  }
  links.hidden = !(v.links || []).length;
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
  const label = v.who;
  who.append(el("strong", label));
  for (const t of v.tags) who.append(el("span", t.text, `tag ${t.kind}`));
  if (v.method) who.append(el("span", v.method, "method"));
  li.append(who);
  if (v.label) li.append(el("p", v.label, "line small muted"));
  for (const line of card.alerts) li.append(el("p", line, "why"));
  if (card.details.length) {
    const id = `details-${++detailsCount}`;
    const toggle = el("button", undefined, "secondary details-toggle");
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-controls", id);
    toggle.append(el("span", t("details")));
    toggle.setAttribute("aria-label", t("details_for", { name: label }));
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
  card.append(el("h2", t("stamps_title", { n: stamps.length })));
  const ol = el("ol", undefined, "revisions");
  for (const d of stamps) {
    const v = stampView(d);
    const li = el("li");
    const who = el("div", undefined, "who");
    who.append(el("strong", v.line));
    who.append(el("span", t(v.valid ? "tag_valid" : "tag_not_valid"), `tag ${v.valid ? "ok" : "bad"}`));
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
  $("doc-title").textContent = env.title || currentName || t("doc_untitled");
  const summary = $("summary");
  summary.replaceChildren();
  summary.append(el("div", statusLine(report)));
  const sent = senderLine(report);
  if (sent) summary.append(el("div", sent, "muted"));
  // An envelope of several documents, signed together as this one PDF.
  const docs = documentsView(report);
  if (docs.length) {
    summary.append(el("div", t("docs_together", { n: docs.length })));
    const ol = el("ol", undefined, "documents");
    for (const d of docs) {
      const li = el("li", d.line);
      const sha = el("div", `${t("doc_sha")} `, "muted");
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
    const open = el("div", `${t("open_in_service")} `, "muted");
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
  renderList(problems, t("problems_failed"), report.messages || [], "problems");
  renderList(problems, t("problems_warnings"), report.warnings || [], "warnings");

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
  row(t("tech_envelope"), env.envelope_id);
  row(t("tech_size"), t("tech_bytes", { n: report.original_len }));
  row(t("tech_pades"), report.pades_level);
  row(t("tech_policy"), report.algorithm_policy?.version);
  $("tech-report").hidden = false;
  $("raw").textContent = JSON.stringify(report, null, 2);
  $("certificate").hidden = false;
}

function renderError(error) {
  showVerdict(errorVerdict(error, { pdfSignatures: countPdfSignatures(currentPdf) }));
  $("doc-title").textContent = currentName || "";
  for (const id of ["summary", "revisions", "timestamps", "problems", "audit", "tech"]) $(id).replaceChildren();
  $("certificate").hidden = true;
  $("raw").textContent = "";
}

// --- actions ----------------------------------------------------------------------------------

/**
 * A certificate of completion sealed by Sovrasign: not a signed document, so the
 * engine has nothing to check; its seal is checked against the evidence keys of the signed trust
 * list (verified under this page's pins), else against the keys the service serves.
 */
async function runSealCheck() {
  const fetchKeys = async () => {
    const url = document.querySelector('meta[name="sovrasign-evidence-keys"]')?.content || "/v1/evidence/jwks";
    const resp = await fetch(url, { credentials: "omit", cache: "no-store" });
    return resp.ok ? resp.json() : { keys: [] };
  };
  const result = await checkSealWithList(currentPdf, signedStatus?.list, fetchKeys);
  showVerdict(sealVerdict(result));
  const s = result.statement;
  const deletion = s?.what === "deletion";
  const invoice = s?.what === "invoice";
  $("doc-title").textContent =
    currentName || t(deletion ? "doc_title_deletion" : invoice ? "doc_title_invoice" : "doc_title_certificate");
  for (const id of ["summary", "revisions", "timestamps", "problems", "audit", "tech"]) $(id).replaceChildren();
  if (s?.envelope && !invoice) {
    $("summary").append(el("div", t(deletion ? "seal_certificate" : "seal_envelope", { id: s.envelope }), "muted"));
  }
  $("certificate").hidden = true;
  $("raw").textContent = s ? JSON.stringify(s, null, 2) : "";
}

async function runVerify({ focus = true } = {}) {
  if (findSeal(currentPdf)) {
    await runSealCheck();
    if (focus) $("verdict").focus({ preventScroll: true });
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
  if (!focus) return;
  $("verdict").focus({ preventScroll: true });
  $("result").scrollIntoView({ block: "start", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

async function onBytes(bytes, name) {
  currentPdf = bytes;
  currentName = name || "";
  $("drop-text").textContent = currentName || t("drop_picked");
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
/** The hand-over note, as a function so a change of language says it again. */
let handOffNote = null;

function receiveHandOff() {
  const id = new URLSearchParams(location.hash.slice(1)).get("check");
  if (!id) return;
  history.replaceState(null, "", location.pathname + location.search);
  const note = $("handoff");
  if (!/^[A-Za-z0-9-]{8,64}$/.test(id) || typeof BroadcastChannel !== "function") return;
  note.hidden = false;
  handOffNote = () => t("handoff_getting");
  note.textContent = handOffNote();
  const channel = new BroadcastChannel(CHANNEL);
  let got = false;
  let asks = 0;
  const ask = () => {
    if (got) return;
    if (asks++ >= 60) {
      channel.close();
      handOffNote = () => t("handoff_none");
      note.textContent = handOffNote();
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
    handOffNote = () => (name ? t("handoff_checking", { name }) : t("handoff_checking_unnamed"));
    note.textContent = handOffNote();
    onBytes(bytes, name);
  };
  ask();
}

let trustReady;

window.addEventListener("DOMContentLoaded", async () => {
  // The visitor's language: ?lang= (the language menu sets it), else the browser's.
  // On a phone or tablet the drop zone just says "Choose" (data-l10n-touch).
  const asked = new URLSearchParams(location.search).get("lang");
  const first = pickLang(asked, "", navigator.languages || [navigator.language]);
  useCatalogs("en", EN, EN);
  languageMenu();
  if (first === "en") applyStatic();
  else await setLanguage(first);
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
    setTrustStatus(() => "");
    if (currentPdf) await runVerify();
  });
  $("export-trust").addEventListener("click", () => {
    download(encoder.encode(JSON.stringify(safe(trust), null, 2)), "trust.json", "application/json");
  });
  $("certificate").addEventListener("click", async () => {
    if (!currentPdf) return;
    try {
      const name = `${(currentName || "document").replace(/\.pdf$/i, "")} - certificate.pdf`;
      // Sovrasign names itself in the certificate (title, footer, how to check the signed PDF).
      const cert = await callOk("signpdf_certificate_named", currentPdf, trustBytes(), encoder.encode("Sovrasign"));
      download(cert, name, "application/pdf");
    } catch (e) {
      renderError(e);
    }
  });
  trustReady = initTrust().catch((e) => {
    setTrustStatus(() => t("trust_failed", { error: e.message }));
  });
  receiveHandOff();
});
