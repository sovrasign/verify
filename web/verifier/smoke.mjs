// CI smoke test: load the built verifier module the way the page does (no imports, fresh
// instance per call) and verify a signed PDF. Usage: node smoke.mjs <signed.pdf>
import { readFileSync } from "node:fs";
import vm from "node:vm";

const wasm = await WebAssembly.compile(readFileSync(new URL("./signpdf_wasm.wasm", import.meta.url)));
const pdf = readFileSync(process.argv[2]);
const trust = new TextEncoder().encode(JSON.stringify({ allow_insecure_dev_issuer: true }));

function call(name, ...args) {
  const ex = new WebAssembly.Instance(wasm, {}).exports;
  const ptrs = args.flatMap((b) => {
    const p = ex.signpdf_alloc(b.length);
    new Uint8Array(ex.memory.buffer, p, b.length).set(b);
    return [p, b.length];
  });
  const code = ex[name](...ptrs);
  const out = new Uint8Array(ex.memory.buffer, ex.signpdf_result_ptr(), ex.signpdf_result_len()).slice();
  return { code, out };
}

const v = call("signpdf_verify", pdf, trust);
const report = JSON.parse(new TextDecoder().decode(v.out));
if (v.code !== 0 || !report.valid) {
  console.error("verify failed", v.code, report.messages);
  process.exit(1);
}
// The demo's evidence for the page to show: the link back to the service, each signer's local
// time and their consent to electronic records.
const evidence = (report.signatures || []).every((s) => s.local_signed_at && s.esign_consent);
if (!report.service_link || !evidence) {
  console.error("the report lacks the service link, a local time or a consent", report.service_link);
  process.exit(1);
}
// From envelope schema version 6 each signer's record says what their box shows: the demo has
// Alice type her signature and Bob draw his.
const drawings = (report.signatures || []).map((s) => s.drawing || "");
if (drawings.join(",") !== "typed,drawn") {
  console.error("the report does not say which signature was typed and which drawn", drawings);
  process.exit(1);
}
// The page passes its time (for the trust list's algorithm policy); every identity has a level.
const encode = (x) => new TextEncoder().encode(typeof x === "string" ? x : JSON.stringify(x));
const now = Math.floor(Date.now() / 1000);
const verifyAt = (t, time) => {
  const r = call("signpdf_verify_at", pdf, encode(t), encode(String(time)));
  return { code: r.code, report: r.code === 0 ? JSON.parse(new TextDecoder().decode(r.out)) : null };
};
const at = verifyAt({ allow_insecure_dev_issuer: true }, now);
const identities = at.report ? [at.report.preparer, ...at.report.signatures] : [];
if (at.code !== 0 || !at.report.valid || !identities.every((s) => /^L[1-5]$/.test(s.level) && s.basis.length)) {
  console.error("verify_at failed, or an identity has no level", at.code, at.report && at.report.messages);
  process.exit(1);
}
// The page's words for each identity in a language other than English (verifier-i18n.js, the
// script the page loads before verifier.js): level, method, provider and "via".
const ctx = vm.createContext({});
vm.runInContext(readFileSync(new URL("./verifier-i18n.js", import.meta.url), "utf8"), ctx);
const I18N = ctx.SignpdfI18n;
const GERMAN_LEVELS = { L1: "E-Mail", L2: "Konto", L3: "Stark", L4: "Ausweis geprüft", L5: "Qualifiziert" };
for (const s of identities) {
  const level = I18N.levelText("de", s.level);
  if (level.badge !== `${s.level} ${GERMAN_LEVELS[s.level]}` || !level.long.startsWith("Vertrauensstufe ")) {
    console.error("German level words wrong", s.level, level);
    process.exit(1);
  }
  for (const b of s.basis) {
    const de = I18N.basisText("de", b, null);
    const en = I18N.basisText("en", b, null);
    const viaService = ["email-code", "phone", "id-document"].includes(b.method);
    if (de === en || !de.includes(b.issuer) || (viaService && !de.includes(`über ${b.issuer}`))) {
      console.error("German method/provider words wrong", b, de);
      process.exit(1);
    }
  }
}
if (I18N.t("de", "verdict_valid") === I18N.t("en", "verdict_valid")) {
  console.error("the German verdict is the English one");
  process.exit(1);
}
// An algorithm policy that ends ECDSA P-256 in a year: fine at the page's time; a module without
// a clock counts the end as passed, so nothing the demo signed holds.
const policy = {
  version: 2,
  algorithms: [
    { algorithm: "SHA-256" },
    { algorithm: "ECDSA-P256", not_after: new Date((now + 365 * 86400) * 1000).toISOString().replace(/\.\d+Z$/, "Z") },
  ],
};
const dated = { allow_insecure_dev_issuer: true, algorithm_policy: policy };
const inTime = verifyAt(dated, now);
if (inTime.code !== 0 || !inTime.report.valid || inTime.report.algorithm_policy.source !== "trust-list") {
  console.error("a dated algorithm policy refused a document in time", inTime.report && inTime.report.messages);
  process.exit(1);
}
const noClock = call("signpdf_verify", pdf, encode(dated));
if (noClock.code !== 0 || JSON.parse(new TextDecoder().decode(noClock.out)).valid) {
  console.error("without a clock, an algorithm end date did not count as passed");
  process.exit(1);
}
const c = call("signpdf_certificate", pdf, trust);
if (c.code !== 0 || new TextDecoder().decode(c.out.slice(0, 5)) !== "%PDF-") {
  console.error("certificate failed");
  process.exit(1);
}
const tampered = Uint8Array.from(pdf);
tampered[20] ^= 0xff;
const t = call("signpdf_verify", tampered, trust);
if (t.code === 0 && JSON.parse(new TextDecoder().decode(t.out)).valid) {
  console.error("tampered document verified!");
  process.exit(1);
}
console.log("browser verifier smoke test passed");
