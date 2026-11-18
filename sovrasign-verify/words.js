// Sovrasign Verify: what a verification report says, in plain words.
//
// The engine (SignPDF, compiled to WebAssembly) decides; this module only words its report:
// - identities in their long form ("Long (verifier, certificate)"): the
//   method, who vouched, the level by the evidence it rests on, "via Sovrasign" where trust rests
//   on us;
// - signing times: a device time is "not independently confirmed", bounded
//   below by the sign-in token's issue time and above by the first trusted timestamp after it (on
//   Free, the one document timestamp the service adds when the envelope ends).
//
// Every string in a report comes from the PDF, which anyone can write: this module returns plain
// strings and the page shows them with textContent only. No DOM here, so Node tests it
// (tools/verify-words.test.mjs).
//
// The words are in the visitor's language: l10n/verify_<lang>.arb through i18n.js `t`.

import { lang, t } from "./i18n.js";

/** The test identity provider of the engine (its private key is public): dev only. */
export const TEST_ISSUER = "https://mock-idp.signpdf.test";

const BIG = [
  ["https://accounts.google.com", "Google"],
  ["https://appleid.apple.com", "Apple"],
];

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const two = (n) => String(n).padStart(2, "0");

/** The viewer's time zone (an IANA name), or undefined for the browser's own. Tests set it. */
let viewerZone;

/** Show times in `zone` (an IANA name such as "America/Los_Angeles"); undefined: the browser's. */
export function useTimeZone(zone) {
  viewerZone = zone;
}

/** The parts of `d` in `zone`: numbers, and the zone's short English name ("PDT", "GMT+2"). */
function zoneParts(d, zone) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    timeZoneName: "short",
  }).formatToParts(d);
  const get = (type) => parts.find((p) => p.type === type)?.value;
  return { y: +get("year"), m: +get("month"), d: +get("day"), h: +get("hour") % 24, min: +get("minute"), s: +get("second"), zone: get("timeZoneName") };
}

/**
 * A time as the viewer's clock shows it, with its zone's name, and the same instant in UTC as the
 * evidence states it: "29 Oct 2026, 23:04 PDT
 * (30 Oct, 06:04 UTC)"; in UTC itself only "3 Nov 2026, 14:02 UTC". With seconds: "14:02:11".
 * The input as is when it is no time.
 */
export function fmtTime(iso, { seconds = false } = {}) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return iso || t("time_unknown");
  if (lang() !== "en") return fmtTimeIntl(d, seconds);
  const clock = (h, m, s) => `${two(h)}:${two(m)}${seconds ? `:${two(s)}` : ""}`;
  const utc = `${clock(d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds())} UTC`;
  const utcDay = `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
  let local;
  try {
    local = zoneParts(d, viewerZone);
  } catch (_) {
    local = null; // no Intl time zones: UTC only, as before
  }
  const sameAsUtc = !local || (local.y === d.getUTCFullYear() && local.m === d.getUTCMonth() + 1 && local.d === d.getUTCDate() && local.h === d.getUTCHours() && local.min === d.getUTCMinutes());
  if (sameAsUtc) return `${utcDay} ${d.getUTCFullYear()}, ${utc}`;
  const day = `${local.d} ${MONTHS[local.m - 1]}`;
  return `${day} ${local.y}, ${clock(local.h, local.min, local.s)} ${local.zone} (${day === utcDay ? "" : `${utcDay}, `}${utc})`;
}

/**
 * fmtTime in another language than English: the day and clock as that language writes them
 * (Intl), the zone's short name, and the same instant in UTC, as the English form does.
 */
function fmtTimeIntl(d, seconds) {
  const l = lang();
  const day = (zone) => new Intl.DateTimeFormat(l, { timeZone: zone, day: "numeric", month: "short", year: "numeric" }).format(d);
  const clock = (zone) =>
    new Intl.DateTimeFormat(l, { timeZone: zone, hour: "2-digit", minute: "2-digit", ...(seconds ? { second: "2-digit" } : {}), hourCycle: "h23" }).format(d);
  let local;
  try {
    local = zoneParts(d, viewerZone);
  } catch (_) {
    local = null;
  }
  const utc = `${clock("UTC")} UTC`;
  const sameDay = local && local.y === d.getUTCFullYear() && local.m === d.getUTCMonth() + 1 && local.d === d.getUTCDate();
  if (!local || (sameDay && local.h === d.getUTCHours() && local.min === d.getUTCMinutes())) return `${day("UTC")} ${utc}`;
  return `${day(viewerZone)} ${clock(viewerZone)} ${local.zone} (${sameDay ? "" : `${day("UTC")} `}${utc})`;
}

/** The local clock part of `2026-11-02T11:14:03+02:00`: "11:14". */
function localClock(local) {
  const m = /T(\d{2}):(\d{2})/.exec(local || "");
  return m ? `${m[1]}:${m[2]}` : "";
}

/**
 * Who a provider is, in words: the name the trust list gives it, else Google, Microsoft or Apple
 * by issuer, else the issuer's host.
 */
export function providerName(issuer, trust) {
  if (!issuer) return t("provider_unknown");
  const entry = (trust?.issuers || []).find((i) => i.issuer === issuer || templateMatches(i.issuer, issuer));
  if (entry?.name) return entry.name;
  for (const [iss, name] of BIG) if (iss === issuer) return name;
  if (/^https:\/\/login\.microsoftonline\.com\//.test(issuer)) return "Microsoft";
  try {
    return new URL(issuer).host;
  } catch {
    return issuer;
  }
}

// Microsoft's multi-tenant issuer in a trust list: `https://login.microsoftonline.com/{tenantid}/v2.0`.
function templateMatches(template, issuer) {
  if (!template.includes("{tenantid}")) return false;
  const [head, tail] = template.split("{tenantid}");
  return issuer.startsWith(head) && issuer.endsWith(tail) && issuer.length > head.length + tail.length;
}

/** The short name of an email-code provider: "Sovrasign email code" -> "Sovrasign". */
function codeSender(name) {
  return name.replace(/\s+email[- ]code$/i, "") || name;
}

/** Trust rests on us: the trust list names the provider as Sovrasign's own. */
export function isOurs(issuer, trust) {
  return /^sovrasign\b/i.test(providerName(issuer, trust));
}

// Assurance levels by the evidence they rest on; never a grade: the shared word
// list's level names (l10n/words.json checks verify:level_l1 to l5 against it).
const LEVELS = ["L1", "L2", "L3", "L4", "L5"];
const levelName = (level) => (LEVELS.includes(level) ? t(`level_${level.toLowerCase()}`) : "");

// Why an identity does not count, in words (verify_<lang>.arb why_*).
const TRUST_WHY = new Set([
  "unknown-issuer",
  "unknown-key",
  "untrusted-audience",
  "no-trusted-time",
  "outside-key-window",
  "distrusted-key",
  "algorithm-not-accepted",
  "insufficient-level",
  "insecure-dev",
]);
const trustWhy = (code) => (TRUST_WHY.has(code) ? t(`why_${code.replaceAll("-", "_")}`) : t("why_other", { code }));

/**
 * One piece of identity evidence in its long form. `email` is the address the
 * provider confirmed.
 */
export function evidenceText(basis, email, trust) {
  const who = email || t("address_unknown");
  const by = providerName(basis.issuer, trust);
  switch (basis.method) {
    case "email-code":
      return t("ev_email_code", { email: who, service: codeSender(by) });
    case "account":
      return t("ev_account", { provider: by, email: who });
    case "organization":
      if (!["Google", "Microsoft", "Apple"].includes(by)) return t("ev_org", { org: by, email: who });
      return basis.organization
        ? t("ev_org_big", { provider: by, email: who, org: basis.organization })
        : t("ev_account", { provider: by, email: who });
    case "phone":
      return t("ev_phone", { provider: by });
    case "id-document":
      return t("ev_id", { provider: by });
    case "qualified":
      return t("ev_qualified", { provider: by });
    default:
      return `${basis.method} (${by})`;
  }
}

/** How a piece of evidence was made, in two or three words, for a signer's summary line. */
export function methodText(basis, trust) {
  const by = providerName(basis.issuer, trust);
  switch (basis.method) {
    case "email-code":
      return t("m_email_code");
    case "account":
    case "organization":
      return ["Google", "Microsoft", "Apple"].includes(by) ? t("m_provider", { provider: by }) : t("m_through", { provider: by });
    case "phone":
      return t("m_phone");
    case "id-document":
      return t("m_id");
    case "qualified":
      return t("m_qualified");
    default:
      return basis.method || "";
  }
}

/** The headline for a report: {kind: ok | warn | bad | info, title, line, links?}. */
export function verdict(report) {
  if (report.valid) return { kind: "ok", title: t("v_valid_title"), line: t("v_valid_line") };
  if (report.trusted_time_pending) return { kind: "warn", title: t("v_pending_title"), line: t("v_pending_line") };
  if (report.integrity_ok) return { kind: "warn", title: t("v_intact_title"), line: t("v_intact_line") };
  return { kind: "bad", title: t("v_bad_title"), line: t("v_bad_line") };
}

/** Adobe Acrobat Reader and the European Commission's DSS validation demo (spec 01 Q2). */
export const OTHER_VERIFIERS = [
  { key: "v_other_link_acrobat", href: "https://get.adobe.com/reader/" },
  { key: "v_other_link_dss", href: "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation" },
];

/**
 * How many PDF signatures a file carries, whoever made them: its signature dictionaries' byte
 * ranges (`/ByteRange [`), counted in the raw bytes. No validation and no trust judgement: only
 * whether the file has PDF signatures at all, for a file Sovrasign did not sign (spec 01 Q2).
 */
export function countPdfSignatures(bytes) {
  if (!bytes?.length) return 0;
  const text = new TextDecoder("latin1").decode(bytes);
  return (text.match(/\/ByteRange\s*\[/g) || []).length;
}

/**
 * The headline when the engine could not read the document at all. `pdfSignatures`: how many PDF
 * signatures the file carries (countPdfSignatures). A file Sovrasign did not sign gets a neutral
 * answer (`info`, not red: bf-verifier-other-vendor-message, spec 01 Q2): it is not bad, only not
 * ours. It says whether the file has PDF signatures and where to check them (`links`).
 */
export function errorVerdict(error, { pdfSignatures = 0 } = {}) {
  if (error.code === "updated") return { kind: "warn", title: t("v_updated_title"), line: t("v_updated_line") };
  if (error.code === 16) return { kind: "warn", title: t("v_newer_title"), line: t("v_newer_line") };
  if (/no embedded envelope/.test(error.message || "")) {
    const n = pdfSignatures;
    if (!n) return { kind: "info", title: t("v_other_title"), line: t("v_other_none") };
    const links = OTHER_VERIFIERS.map((l) => ({ text: t(l.key), href: l.href }));
    return { kind: "info", title: t("v_other_title"), line: t("v_other_signed", { n }), links };
  }
  return { kind: "bad", title: t("v_error_title"), line: error.message || String(error) };
}

/**
 * A certificate of completion sealed by Sovrasign (seal.js): what its seal says. The
 * certificate is a summary; the signed PDF is the proof, and each line says so. A certificate of
 * deletion (`what: "deletion"`) is the proof itself: its lines say what it records.
 */
export function sealVerdict(result) {
  if (result.statement?.what === "deletion") return deletionVerdict(result);
  if (result.statement?.what === "invoice") return invoiceVerdict(result);
  const time = sealTime(result);
  switch (result.state) {
    case "sealed":
      return { kind: "ok", title: t("s_sealed_title"), line: time ? t("s_sealed_line", { time }) : t("s_sealed_line_notime") };
    case "changed":
      return { kind: "bad", title: t("s_changed_title"), line: t("s_changed_line") };
    case "added":
      return { kind: "bad", title: t("s_added_title"), line: t("s_added_line") };
    case "unknown_key":
      return { kind: "warn", title: t("s_unknown_title"), line: t("s_unknown_line") };
    default:
      return { kind: "bad", title: t("s_invalid_title"), line: t("s_invalid_line") };
  }
}

/** When the seal says it was made, in words, or "". */
const sealTime = (result) => (result.statement?.iat ? fmtTime(new Date(result.statement.iat * 1000).toISOString()) : "");

/** An invoice or receipt sealed by Sovrasign: Stripe issued it,
 * the service sealed it when it was downloaded. */
function invoiceVerdict(result) {
  const time = sealTime(result);
  switch (result.state) {
    case "sealed":
      return { kind: "ok", title: t("inv_sealed_title"), line: time ? t("inv_sealed_line", { time }) : t("inv_sealed_line_notime") };
    case "changed":
    case "added":
      return { kind: "bad", title: t("inv_changed_title"), line: t("inv_changed_line") };
    case "unknown_key":
      return { kind: "warn", title: t("s_unknown_title"), line: t("inv_unknown_line") };
    default:
      return { kind: "bad", title: t("s_invalid_title"), line: t("inv_invalid_line") };
  }
}

/** A certificate of deletion sealed by Sovrasign. */
function deletionVerdict(result) {
  const time = sealTime(result);
  switch (result.state) {
    case "sealed":
      return { kind: "ok", title: t("del_sealed_title"), line: time ? t("del_sealed_line", { time }) : t("del_sealed_line_notime") };
    case "changed":
      return { kind: "bad", title: t("del_changed_title"), line: t("del_changed_line") };
    default:
      return { kind: "bad", title: t("s_invalid_title"), line: t("del_invalid_line") };
  }
}

/** The envelope's state in one line. */
export function statusLine(report) {
  const env = report.envelope || {};
  const slots = (env.signers || []).length;
  const signed = (report.signatures || []).filter((s) => s.kind === "signed").length;
  if (report.declined) return t("st_declined");
  if (report.complete) return slots === 1 ? t("st_completed_single") : t("st_completed_all", { n: slots });
  return t("st_waiting", { signed, total: slots });
}

/** The revisions in order: the preparer's, then each signer's. */
export function revisions(report) {
  return [report.preparer, ...(report.signatures || [])].filter(Boolean);
}

/**
 * The document's trusted time, once per document: what bounds the last
 * revision bounds every earlier one. Null when every signature has its own trusted timestamp and
 * there is nothing more to say.
 */
export function documentTimeLine(report) {
  const all = revisions(report);
  const last = all[all.length - 1];
  if (!last) return null;
  const device = all.some((s) => s.time_source !== "tsa");
  if (last.existed_before) {
    const e = last.existed_before;
    return t("dt_existed_before", { time: fmtTime(e.time), tsa: e.tsa_name || t("tsa_unknown") });
  }
  return device ? t("dt_device") : null;
}

/** Where a trusted upper bound comes from, in words. */
function boundSource(e) {
  const tsa = e.tsa_name || t("tsa_unknown");
  return e.source === "later-signature" ? t("bound_later", { tsa }) : t("bound", { tsa });
}

/**
 * Who a revision names, as the page headlines it: the email address the engine verified, and only
 * when its provider is trusted (spec; SECURITY_MODEL). The sender's names for a slot
 * or for themself are text the sender typed: never the headline, and shown marked as such.
 */
function verifiedEmail(s) {
  return s.idp_email && s.identity_trust === "trusted" ? s.idp_email : "";
}

/**
 * One revision in words, for the page to lay out:
 * {role, who, label, email, valid, tags: [{text, kind}], method, identity: [lines], why, time,
 *  bounds, consent, code, detail}. `who` is the verified email (or "Unverified identity"); `label`
 * is the sender's unverified name for the slot (or their own), in words, or "".
 */
export function revisionView(s, report, trust) {
  const env = report.envelope || {};
  const slot = (env.signers || []).find((x) => x.id === s.signer_id);
  const preparer = s.kind === "prepared";
  const act = preparer ? "sent" : s.kind === "declined" ? "declined" : "signed";
  const role = t(preparer ? "role_prepared" : s.kind === "declined" ? "role_declined" : "role_signed");
  const email = verifiedEmail(s);
  const who = email || t("who_unverified");
  const given = (preparer ? env.created_by : slot?.name) || "";
  const label = given && given !== email ? t(preparer ? "label_preparer" : "label_slot", { name: given }) : "";

  const tags = [];
  tags.push(s.valid ? { text: t("tag_valid"), kind: "ok" } : { text: t("tag_not_valid"), kind: "bad" });
  if (s.level) {
    const ours = (s.basis || []).some((b) => isOurs(b.issuer, trust));
    const via = ours ? ` · ${t("via_service", { service: "Sovrasign" })}` : "";
    tags.push({ text: `${s.level} ${levelName(s.level)}${via}`.trim(), kind: "level" });
  }

  // Identity: the evidence in its long form; without trusted evidence, who claimed it and why
  // it does not count.
  const identity = (s.basis || []).length
    ? s.basis.map((b) => evidenceText(b, s.idp_email, trust))
    : s.idp_email || s.idp_issuer
      ? [t("id_stated", { email: s.idp_email || t("id_an_address"), provider: providerName(s.idp_issuer, trust) })]
      : [];
  const method = [...new Set((s.basis || []).map((b) => methodText(b, trust)).filter(Boolean))].join(", ");
  const why = s.identity_trust && s.identity_trust !== "trusted" ? trustWhy(s.identity_trust) : "";

  // Time.
  let time;
  let bounds = "";
  if (s.time_source === "tsa") {
    const ts = s.timestamp || {};
    time = t(`t_tsa_${act}`, {
      time: fmtTime(ts.time || s.signed_at, { seconds: true }),
      tsa: ts.tsa_name || s.existed_before?.tsa_name || t("tsa_unknown"),
    });
  } else {
    const local =
      s.local_signed_at && s.utc_offset && s.utc_offset !== "+00:00" ? t("t_local", { clock: localClock(s.local_signed_at), offset: s.utc_offset }) : "";
    time = t(`t_dev_${act}`, { time: fmtTime(s.signed_at), local });
    const after = s.token_issued_at ? fmtTime(s.token_issued_at) : "";
    if (s.existed_before) {
      const before = { before: fmtTime(s.existed_before.time), source: boundSource(s.existed_before) };
      bounds = after ? t("b_window", { after, ...before }) : t("b_before", before);
    } else {
      bounds = after ? t("b_none_after", { after }) : t("b_none");
    }
  }

  // The drawing beside the caption (schema 6+): decoration, never who signed.
  const drawing = s.drawing === "typed" ? t("drawing_typed") : s.drawing === "drawn" ? t("drawing_drawn") : "";

  let consent = "";
  if (s.esign_consent) {
    const c = s.esign_consent;
    consent = t("consent_line", { version: c.version, lang: c.lang, time: fmtTime(c.at) });
  }
  return {
    role,
    who,
    label,
    email,
    valid: !!s.valid,
    tags,
    method,
    identity,
    why,
    time,
    bounds,
    drawing,
    consent,
    consentSha: s.esign_consent?.sha256 || "",
    code: s.signature_code ? `Sig ${s.signature_code}` : "",
    detail: s.detail || "",
  };
}

/**
 * A signer's or the sender's card, as the page lays it out: the summary line (who, Valid, level, method) and any warning or failure
 * always show; the evidence (proof, clock, timestamp window, drawing, consent, Sig code) sits behind
 * a "Details" button, closed by default and open in print. `view` is revisionView's result.
 * {alerts: [lines], details: [{text, muted}]}.
 */
export function revisionCard(view) {
  const alerts = [];
  if (view.why) alerts.push(view.why);
  if (view.detail && !view.valid) alerts.push(view.detail);
  const details = [];
  for (const line of view.identity) details.push({ text: line, muted: false });
  details.push({ text: view.time, muted: false });
  if (view.bounds) details.push({ text: view.bounds, muted: true });
  if (view.drawing) details.push({ text: view.drawing, muted: true });
  if (view.consent) details.push({ text: view.consent, muted: true });
  if (view.code) details.push({ text: t("sig_code_line", { code: view.code }), muted: true });
  return { alerts, details };
}

/**
 * The summary's "Sent by" line: the preparer's verified email, never the envelope's own fields
 * (which the sender typed), or "" when the preparer's identity is not verified.
 */
export function senderLine(report) {
  const prep = report.preparer;
  const email = prep ? verifiedEmail(prep) : "";
  return email ? t("sent_by", { email }) : "";
}

/** A document timestamp in words. */
export function stampView(d) {
  const ts = d.timestamp || {};
  const trusted = ts.verified && ts.signature_valid && ts.trusted;
  const values = { time: fmtTime(ts.time, { seconds: true }), tsa: ts.tsa_name || t("tsa_unknown") };
  return {
    valid: !!d.valid,
    line: t(d.added_validation_data ? "stamp_line_vd" : "stamp_line", values),
    trust: trusted ? t("stamp_trusted") : ts.detail ? t("stamp_not_trusted_why", { detail: ts.detail }) : t("stamp_not_trusted"),
    detail: d.detail || "",
  };
}

/** The trust list holds the test sign-in (anyone can sign as anyone): a development list. */
export function isDevTrust(trust) {
  return (trust?.issuers || []).some((i) => i.issuer === TEST_ISSUER);
}

/** The documents of an envelope signed together as one PDF: "Name (pages 2–3)". */
export function documentsView(report) {
  return ((report.envelope || {}).documents || []).map((d) => {
    const last = d.first_page + d.page_count;
    return {
      line: d.page_count === 1 ? t("doc_page", { name: d.name, page: last }) : t("doc_pages", { name: d.name, from: d.first_page + 1, to: last }),
      sha256: d.source_digest || "",
    };
  });
}
