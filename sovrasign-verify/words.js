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
  if (!iso || Number.isNaN(d.getTime())) return iso || "an unknown time";
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
  if (!issuer) return "an unknown provider";
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

// Assurance levels by the evidence they rest on; never a grade.
const LEVEL_NAMES = { L1: "Email", L2: "Account", L3: "Strong", L4: "ID checked", L5: "Qualified" };

// What a device signing time rests on: the shared words time_not_timestamped and
// time_no_timestamp_yet (service/api/l10n/words_en.arb; l10n/tools/words.mjs checks them).
const TIME_WORDS = { notTimestamped: "Not independently timestamped", noTimestampYet: "No trusted timestamp yet" };

// Why an identity does not count, in words.
const TRUST_WHY = {
  "unknown-issuer": "This verifier's trust list does not include this sign-in provider.",
  "unknown-key": "The sign-in was signed with a key this verifier's trust list does not hold. Fetching the providers' current keys may help.",
  "untrusted-audience": "The sign-in was made for an app this verifier's trust list does not include.",
  "no-trusted-time": "This sign-in counts once a trusted timestamp covers the signature. The service adds one when the envelope ends.",
  "outside-key-window": "The sign-in key was not valid at the time the trusted timestamp shows.",
  "distrusted-key": "The sign-in key was withdrawn from the trust list before this signature was timestamped.",
  "algorithm-not-accepted": "The sign-in relies on an algorithm this verifier no longer accepts.",
  "insufficient-level": "The identity check is weaker than the sender required for this signer.",
  "insecure-dev": "Test sign-in: anyone can sign as anyone. Development only.",
};

/**
 * One piece of identity evidence in its long form. `email` is the address the
 * provider confirmed.
 */
export function evidenceText(basis, email, trust) {
  const who = email || "an unknown address";
  const by = providerName(basis.issuer, trust);
  switch (basis.method) {
    case "email-code":
      return `Proved control of ${who} with a one-time code sent by ${codeSender(by)} (lower assurance)`;
    case "account":
      return `Signed in with ${by} as ${who}; the sign-in is sealed into this signature`;
    case "organization":
      return ["Google", "Microsoft", "Apple"].includes(by)
        ? `Signed in with ${by} as ${who}${basis.organization ? ` (organization ${basis.organization})` : ""}; the sign-in is sealed into this signature`
        : `Signed in through ${by}'s identity provider as ${who}; the sign-in is sealed into this signature`;
    case "phone":
      return `Confirmed a code sent to their phone, attested by ${by}`;
    case "id-document":
      return `Government ID checked by ${by}`;
    case "qualified":
      return `Qualified electronic signature under eIDAS, certificate from ${by}`;
    default:
      return `${basis.method} (${by})`;
  }
}

/** How a piece of evidence was made, in two or three words, for a signer's summary line. */
export function methodText(basis, trust) {
  const by = providerName(basis.issuer, trust);
  switch (basis.method) {
    case "email-code":
      return "Email code";
    case "account":
    case "organization":
      return ["Google", "Microsoft", "Apple"].includes(by) ? `${by} sign-in` : `Sign-in through ${by}`;
    case "phone":
      return "Phone code";
    case "id-document":
      return "Government ID";
    case "qualified":
      return "Qualified certificate";
    default:
      return basis.method || "";
  }
}

/** The headline for a report: {kind: ok | warn | bad, title, line}. */
export function verdict(report) {
  if (report.valid) {
    return {
      kind: "ok",
      title: "Valid",
      line: "Nothing changed since it was signed, and every signer's identity checks out.",
    };
  }
  if (report.trusted_time_pending) {
    return {
      kind: "warn",
      title: "Intact, waiting for a trusted timestamp",
      line: "Nothing changed since it was signed. Some sign-ins count only once a trusted timestamp covers them; the service adds one when the envelope ends.",
    };
  }
  if (report.integrity_ok) {
    return {
      kind: "warn",
      title: "Intact, but not every identity is confirmed",
      line: "Nothing changed since it was signed, but this verifier's trust list does not confirm every sign-in. Each signer below says why.",
    };
  }
  return {
    kind: "bad",
    title: "Not valid",
    line: "The document or its signing history failed the checks. Do not rely on it; the reasons are below.",
  };
}

/** The headline when the engine could not read the document at all. */
export function errorVerdict(error) {
  if (error.code === "updated") {
    return {
      kind: "warn",
      title: "Sovrasign Verify was updated",
      line: "Reload the page to continue, then check the file again. Your file stays on this device.",
    };
  }
  if (error.code === 16) {
    return {
      kind: "warn",
      title: "Made by a newer version",
      line: "This document was made by a newer version of the SignPDF engine than this page. Reload the page to get the current verifier, then check it again.",
    };
  }
  if (/no embedded envelope/.test(error.message || "")) {
    return {
      kind: "bad",
      title: "No Sovrasign signatures",
      line: "This PDF has no Sovrasign or SignPDF signing history to check. Other kinds of PDF signatures need another verifier.",
    };
  }
  return { kind: "bad", title: "Could not check this file", line: error.message || String(error) };
}

/**
 * A certificate of completion sealed by Sovrasign (seal.js): what its seal says. The
 * certificate is a summary; the signed PDF is the proof, and each line says so. A certificate of
 * deletion (`what: "deletion"`) is the proof itself: its lines say what it records.
 */
export function sealVerdict(result) {
  if (result.statement?.what === "deletion") return deletionVerdict(result);
  if (result.statement?.what === "invoice") return invoiceVerdict(result);
  const when = result.statement?.iat ? fmtTime(new Date(result.statement.iat * 1000).toISOString()) : "";
  const proof = "It is a summary: check the signed PDF itself for the proof.";
  switch (result.state) {
    case "sealed":
      return {
        kind: "ok",
        title: "Certificate of completion, unchanged",
        line: `Sovrasign sealed this certificate${when ? ` on ${when}` : ""}, and nothing in it has changed since. ${proof}`,
      };
    case "changed":
      return {
        kind: "bad",
        title: "Certificate changed after it was sealed",
        line: `This certificate is not what Sovrasign made: its content differs from what was sealed. Ask the sender for the original, or download it again. ${proof}`,
      };
    case "added":
      return {
        kind: "bad",
        title: "Something was added to this certificate",
        line: `Content was added after Sovrasign sealed this certificate, so what you see may not be what was sealed. ${proof}`,
      };
    case "unknown_key":
      return {
        kind: "warn",
        title: "Seal not recognized",
        line: "This certificate carries a seal from a key that is not one of Sovrasign's published keys. It may come from another environment, or be forged.",
      };
    default:
      return {
        kind: "bad",
        title: "Seal not valid",
        line: `The seal on this certificate does not verify. ${proof}`,
      };
  }
}

/** An invoice or receipt sealed by Sovrasign: Stripe issued it,
 * the service sealed it when it was downloaded. */
function invoiceVerdict(result) {
  const when = result.statement?.iat ? fmtTime(new Date(result.statement.iat * 1000).toISOString()) : "";
  switch (result.state) {
    case "sealed":
      return {
        kind: "ok",
        title: "Invoice, unchanged",
        line: `Sovrasign sealed this invoice${when ? ` on ${when}` : ""}, and nothing in it has changed since.`,
      };
    case "changed":
    case "added":
      return {
        kind: "bad",
        title: "Invoice changed after it was sealed",
        line: "This invoice is not what Sovrasign issued: its content differs from what was sealed. Download it again from your Plan and usage page.",
      };
    case "unknown_key":
      return {
        kind: "warn",
        title: "Seal not recognized",
        line: "This invoice carries a seal from a key that is not one of Sovrasign's published keys. It may come from another environment, or be forged.",
      };
    default:
      return {
        kind: "bad",
        title: "Seal not valid",
        line: "The seal on this invoice does not verify, so it is not proof of what Sovrasign billed.",
      };
  }
}

/** A certificate of deletion sealed by Sovrasign. */
function deletionVerdict(result) {
  const when = result.statement?.iat ? fmtTime(new Date(result.statement.iat * 1000).toISOString()) : "";
  switch (result.state) {
    case "sealed":
      return {
        kind: "ok",
        title: "Certificate of deletion, unchanged",
        line: `Sovrasign sealed this certificate of deletion${when ? ` on ${when}` : ""}, and nothing in it has changed since. It records what Sovrasign deleted, the keys it destroyed and when backups expire.`,
      };
    case "changed":
      return {
        kind: "bad",
        title: "Certificate of deletion changed after it was sealed",
        line: "This certificate of deletion is not what Sovrasign issued: its content differs from what was sealed. Download it again from your account or the deletion receipt's link.",
      };
    default:
      return {
        kind: "bad",
        title: "Seal not valid",
        line: "The seal on this certificate of deletion does not verify, so it is not proof of what Sovrasign deleted.",
      };
  }
}

/** The envelope's state in one line. */
export function statusLine(report) {
  const env = report.envelope || {};
  const slots = (env.signers || []).length;
  const signed = (report.signatures || []).filter((s) => s.kind === "signed").length;
  if (report.declined) return "Declined: a signer declined, so this agreement is void.";
  if (report.complete) return slots === 1 ? "Completed: the signer signed." : `Completed: all ${slots} signers signed.`;
  return `Waiting for signatures: ${signed} of ${slots} signed.`;
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
    return `All signatures in this document existed before ${fmtTime(e.time)} (trusted timestamp, ${e.tsa_name || "unknown authority"}).`;
  }
  return device ? "No trusted timestamp yet: the signing times are the signers' device clocks, which nobody independent confirms." : null;
}

/** Where a trusted upper bound comes from, in words. */
function boundSource(e) {
  const tsa = e.tsa_name || "unknown authority";
  if (e.source === "later-signature") return `trusted timestamp on a later signature, ${tsa}`;
  return `trusted timestamp, ${tsa}`;
}

/**
 * One revision in words, for the page to lay out:
 * {role, name, email, valid, tags: [{text, kind}], method, identity: [lines], why, time, bounds,
 *  consent, code, detail}.
 */
export function revisionView(s, report, trust) {
  const env = report.envelope || {};
  const slot = (env.signers || []).find((x) => x.id === s.signer_id);
  const preparer = s.kind === "prepared";
  const role = preparer ? "Prepared and sent by" : s.kind === "declined" ? "Declined by" : "Signed by";
  const name = preparer ? env.created_by || "" : slot?.name || "";
  const email = s.idp_email || (preparer ? env.created_by_email : slot?.email) || "";

  const tags = [];
  tags.push(s.valid ? { text: "Valid", kind: "ok" } : { text: "Not valid", kind: "bad" });
  if (s.level) {
    const ours = (s.basis || []).some((b) => isOurs(b.issuer, trust));
    tags.push({ text: `${s.level} ${LEVEL_NAMES[s.level] || ""}${ours ? " · via Sovrasign" : ""}`.trim(), kind: "level" });
  }

  // Identity: the evidence in its long form; without trusted evidence, who claimed it and why
  // it does not count.
  const identity = (s.basis || []).length
    ? s.basis.map((b) => evidenceText(b, s.idp_email, trust))
    : s.idp_email || s.idp_issuer
      ? [`${s.idp_email || "An address"}, as stated by ${providerName(s.idp_issuer, trust)}`]
      : [];
  const method = [...new Set((s.basis || []).map((b) => methodText(b, trust)).filter(Boolean))].join(", ");
  const why = s.identity_trust && s.identity_trust !== "trusted" ? TRUST_WHY[s.identity_trust] || `Identity: ${s.identity_trust}` : "";

  // Time.
  const verb = preparer ? "Sent" : s.kind === "declined" ? "Declined" : "Signed";
  let time;
  let bounds = "";
  if (s.time_source === "tsa") {
    const t = s.timestamp || {};
    time = `${verb} ${fmtTime(t.time || s.signed_at, { seconds: true })} (trusted timestamp, ${t.tsa_name || s.existed_before?.tsa_name || "unknown authority"})`;
  } else {
    const local = s.local_signed_at && s.utc_offset && s.utc_offset !== "+00:00" ? `, ${localClock(s.local_signed_at)} at UTC${s.utc_offset}` : "";
    time = `${verb} ${fmtTime(s.signed_at)}${local} (${preparer ? "sender" : "signer"}'s device clock, not independently confirmed)`;
    const after = s.token_issued_at ? `after ${fmtTime(s.token_issued_at)} (sign-in token issued)` : "";
    if (s.existed_before) {
      const before = `before ${fmtTime(s.existed_before.time)} (${boundSource(s.existed_before)})`;
      bounds = `${TIME_WORDS.notTimestamped}. Made ${after ? `${after} and ` : ""}${before}.`;
    } else {
      bounds = `${TIME_WORDS.noTimestampYet}.${after ? ` Made ${after}.` : ""}`;
    }
  }

  // The drawing beside the caption (schema 6+): decoration, never who signed.
  const drawing = {
    typed: "The signature box shows a typed name, which is not a claim of identity: the sign-in above says who signed.",
    drawn: "The signature box shows a hand-drawn signature; the sign-in above says who signed.",
  }[s.drawing] || "";

  let consent = "";
  if (s.esign_consent) {
    const c = s.esign_consent;
    consent = `Agreed to electronic records and signatures (disclosure ${c.version}, ${c.lang}) on ${fmtTime(c.at)}.`;
  }
  return {
    role,
    name,
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
  if (view.code) details.push({ text: `${view.code}: the code printed in this signature's box in the PDF.`, muted: true });
  return { alerts, details };
}

/** A document timestamp in words. */
export function stampView(d) {
  const t = d.timestamp || {};
  const trusted = t.verified && t.signature_valid && t.trusted;
  return {
    valid: !!d.valid,
    line: `${fmtTime(t.time, { seconds: true })} by ${t.tsa_name || "an unknown authority"}, covering every signature before it${d.added_validation_data ? " and the validation data" : ""}`,
    trust: trusted ? "Trusted" : `Not trusted${t.detail ? `: ${t.detail}` : ""}`,
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
      line: `${d.name} (${d.page_count === 1 ? `page ${last}` : `pages ${d.first_page + 1}–${last}`})`,
      sha256: d.source_digest || "",
    };
  });
}
