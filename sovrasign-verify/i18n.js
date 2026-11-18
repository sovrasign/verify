// Sovrasign Verify's languages: the ten languages of the product.
//
// The words live in l10n/verify_<lang>.arb (English the source). build.mjs turns each into a
// module of this folder, l10n-<lang>.js (`export default {key: text}`), listed in the page's
// integrity list like every other module; verify.js loads English and the visitor's language.
// This module holds no words itself, so Node tests load the ARB files (tools/verify-words.test.mjs).
//
// - `t(key, values)` fills `{name}` placeholders; with a numeric `n` it picks `key_<plural
//   category>` (Intl.PluralRules of the language), then `key_other`, then `key`. A key the
//   language lacks falls back to English, then to the key itself: a missing translation never
//   breaks the page.
// - The language: `?lang=xx` in the address, else the visitor's choice kept on this device, else
//   the browser's languages, else English.

export const LANGS = ["en", "fr", "de", "es", "it", "pt", "ja", "ko", "zh", "ru"];

/** Each language in its own name, for the language menu (never translated). */
export const NAMES = {
  en: "English",
  fr: "Français",
  de: "Deutsch",
  es: "Español",
  it: "Italiano",
  pt: "Português",
  ja: "日本語",
  ko: "한국어",
  zh: "中文",
  ru: "Русский",
};

const S = { lang: "en", cat: {}, en: {} };

/** Use `cat` (the messages of `lang`) with `en` as the fallback. */
export function useCatalogs(lang, cat, en) {
  S.lang = LANGS.includes(lang) ? lang : "en";
  S.cat = cat || {};
  S.en = en || cat || {};
}

/** The language in use. */
export const lang = () => S.lang;

/** The supported language a code names ("pt-BR" -> "pt", "zh-Hant" -> "zh"), or "". */
export function supported(code) {
  const base = String(code || "").toLowerCase().split(/[-_]/)[0];
  return LANGS.includes(base) ? base : "";
}

/** The first supported language of `candidates` (the address, the kept choice, the browser's), else "en". */
export function pickLang(...candidates) {
  for (const c of candidates.flat()) {
    const l = supported(c);
    if (l) return l;
  }
  return "en";
}

function lookup(table, key, values) {
  if (typeof values.n === "number") {
    let category = "other";
    try {
      category = new Intl.PluralRules(table === S.en ? "en" : S.lang).select(values.n);
    } catch {
      /* no Intl: "other" */
    }
    for (const k of [`${key}_${category}`, `${key}_other`]) if (typeof table[k] === "string") return table[k];
  }
  return typeof table[key] === "string" ? table[key] : undefined;
}

/** The message `key` in the language in use, its `{name}` placeholders filled from `values`. */
export function t(key, values = {}) {
  const text = lookup(S.cat, key, values) ?? lookup(S.en, key, values) ?? key;
  return text.replace(/\{(\w+)\}/g, (m, name) => (name in values ? String(values[name]) : m));
}
