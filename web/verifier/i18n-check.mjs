// The browser verifier's ten-language catalogue (verifier-i18n.js): every language has every
// English key, the same {placeholders}, no empty string (except English's empty draft note),
// the identity words the hosted service uses, and the page refers only to keys that exist.
// Usage: node web/verifier/i18n-check.mjs
import { readFileSync } from "node:fs";
import vm from "node:vm";

function loadI18n() {
  const ctx = vm.createContext({});
  vm.runInContext(readFileSync(new URL("./verifier-i18n.js", import.meta.url), "utf8"), ctx);
  return ctx.SignpdfI18n;
}

const I18N = loadI18n();
const problems = [];
const fail = (m) => problems.push(m);
const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");

const en = I18N.STRINGS.en;
const languages = Object.keys(I18N.LANGUAGES);
if (languages.join(",") !== "en,de,es,fr,it,ja,ko,pt,ru,zh") fail(`languages: ${languages}`);
for (const lang of languages) {
  const table = I18N.STRINGS[lang];
  if (!table) {
    fail(`${lang}: no strings`);
    continue;
  }
  for (const key of Object.keys(en)) {
    const s = table[key];
    if (typeof s !== "string") fail(`${lang}: missing ${key}`);
    else if (!s.trim() && !(lang === "en" && key === "draft_note")) fail(`${lang}: empty ${key}`);
    else if (placeholders(s) !== placeholders(en[key])) fail(`${lang}.${key}: placeholders {${placeholders(s)}} vs {${placeholders(en[key])}}`);
  }
  for (const key of Object.keys(table)) if (!(key in en)) fail(`${lang}: unknown key ${key}`);
  // A machine draft says so on the page until a reviewer signs it off.
  if (!I18N.REVIEWED.includes(lang) && !table.draft_note.trim()) fail(`${lang}: unreviewed, but no draft note`);
}

// Every key the page uses exists: data-i18n in the template, t("...")/word("...") in the script.
const template = readFileSync(new URL("./index.template.html", import.meta.url), "utf8");
const script = readFileSync(new URL("./verifier.js", import.meta.url), "utf8");
const used = new Set([
  ...[...template.matchAll(/data-i18n="([^"]+)"/g)].map((m) => m[1]),
  ...[...script.matchAll(/\bt\("([a-z_A-Z0-9-]+)"/g)].map((m) => m[1]),
]);
for (const key of used) if (!(key in en)) fail(`the page uses ${key}, which the catalogue lacks`);
// Words chosen from engine values (word("trust_", ...) and friends) cover the engine's values.
const engineValues = {
  trust_: ["trusted", "insecure-dev", "unknown-issuer", "unknown-key", "untrusted-audience", "no-trusted-time",
    "outside-key-window", "distrusted-key", "algorithm-not-accepted", "insufficient-level"],
  level_: ["L1", "L2", "L3", "L4", "L5"],
  pades_: ["B-B", "B-T", "B-LT", "B-LTA"],
  kind_: ["prepared", "signature"],
};
for (const [prefix, values] of Object.entries(engineValues)) {
  for (const v of values) if (!(`${prefix}${v}` in en)) fail(`no word for ${prefix}${v}`);
}

// The identity words match the hosted service's shared word list (level names; "via").
const SHARED = {
  en: ["Email", "Account", "Strong", "ID checked", "Qualified", "via {service}"],
  de: ["E-Mail", "Konto", "Stark", "Ausweis geprüft", "Qualifiziert", "über {service}"],
  fr: ["E-mail", "Compte", "Fort", "Identité vérifiée", "Qualifiée", "via {service}"],
  ja: ["メール", "アカウント", "強固", "本人確認書類で確認", "適格", "{service} 経由"],
  zh: ["邮箱", "账户", "强", "证件已核验", "合格", "经由 {service}"],
};
for (const [lang, words] of Object.entries(SHARED)) {
  const table = I18N.STRINGS[lang];
  const got = ["level_L1", "level_L2", "level_L3", "level_L4", "level_L5", "via"].map((k) => table[k]);
  if (got.join("|") !== words.join("|")) fail(`${lang}: identity words ${got.join("|")} differ from ${words.join("|")}`);
}

// Language choice: a saved choice, else the browser's first supported language, else English.
const pick = I18N.pickLanguage;
const cases = [
  [[null, ["de-CH", "en"]], "de"],
  [[null, ["xx", "pt-BR"]], "pt"],
  [[null, ["zh-Hans-CN"]], "zh"],
  [[null, ["nl"]], "en"],
  [["ja", ["de"]], "ja"],
  [["xx", ["ko-KR"]], "ko"],
  [[null, []], "en"],
];
for (const [[saved, preferred], want] of cases) {
  const got = pick(saved, preferred);
  if (got !== want) fail(`pickLanguage(${saved}, ${preferred}) = ${got}, want ${want}`);
}

// Placeholders are filled, unknown keys fall back to English, then to the key.
if (I18N.t("de", "level_of", { n: 2 }) !== "Vertrauensstufe 2 von 5") fail("t() does not fill placeholders");
if (I18N.t("xx", "valid") !== "valid") fail("t() does not fall back to English");

if (problems.length) {
  for (const p of problems) console.error(`i18n: ${p}`);
  process.exit(1);
}
console.log(`verifier catalogue: ${languages.length} languages × ${Object.keys(en).length} strings, consistent`);
