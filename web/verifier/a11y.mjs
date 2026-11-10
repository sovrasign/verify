// Accessibility of the built browser verifier (axe-core, WCAG 2.0-2.2 A and AA rules) in Chromium,
// in English and one other language, in the light and the dark theme, before and after a
// document is verified. Also checks that the language switcher changes the page's words and its
// `lang`, and that the choice is remembered.
//
// Needs Playwright with its Chromium and axe-core, from this directory, NODE_PATH or a global
// install (npm install --no-save --no-package-lock playwright@1.63.0 axe-core@4.14.0;
// npx playwright install chromium). Run after scripts/build-verifier.sh:
//
//   node web/verifier/a11y.mjs <signed.pdf>
//
// axe runs inside the page. The page's CSP and Trusted Types refuse injected scripts, so the
// check opens its browser context with `bypassCSP: true`, used for nothing else.
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
let chromium, axeSource;
try {
  ({ chromium } = require("playwright"));
  axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
} catch (_) {
  console.error("needs playwright and axe-core (npm install --no-save --no-package-lock playwright@1.63.0 axe-core@4.14.0)");
  process.exit(2);
}

const dir = fileURLToPath(new URL(".", import.meta.url));
const pdf = process.argv[2];
if (!pdf || !existsSync(join(dir, "index.html"))) {
  console.error("usage: node web/verifier/a11y.mjs <signed.pdf>  (after scripts/build-verifier.sh)");
  process.exit(2);
}

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".wasm": "application/wasm", ".json": "application/json" };
const server = createServer((req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^[/\\]+/, "") || "index.html";
  const file = join(dir, path);
  if (!file.startsWith(dir) || !existsSync(file)) return res.writeHead(404).end();
  res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" }).end(readFileSync(file));
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const url = `http://127.0.0.1:${server.address().port}/`;

async function axe(page, label) {
  await page.evaluate(axeSource);
  const violations = await page.evaluate(async () => {
    const r = await window.axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] },
    });
    return r.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.map((n) => n.target.join(" ")).slice(0, 5) }));
  });
  for (const v of violations) console.log(`axe ${label}: ${v.impact} ${v.id}: ${v.help} (${v.nodes.join(", ")})`);
  return violations.filter((v) => v.impact === "critical" || v.impact === "serious").map((v) => `${label}: ${v.id}`);
}

const problems = [];
const browser = await chromium.launch();
try {
  for (const colorScheme of ["light", "dark"]) {
    const context = await browser.newContext({ bypassCSP: true, colorScheme, locale: "de-DE" });
    const page = await context.newPage();
    page.on("pageerror", (e) => problems.push(`${colorScheme}: page error ${e.message}`));
    await page.goto(url);
    await page.waitForFunction(() => document.querySelectorAll("#issuers li").length > 0);
    // A German browser gets the German page.
    const first = await page.evaluate(() => [document.documentElement.lang, document.querySelector("h1").textContent]);
    if (first[0] !== "de" || first[1] !== "Sovrasign Verify") problems.push(`${colorScheme}: a German browser got ${first}`);
    problems.push(...(await axe(page, `${colorScheme} de, empty`)));
    await page.setInputFiles("#pdf", pdf);
    await page.waitForSelector("#result:not([hidden]) #verdict:not(:empty)");
    const verdict = await page.textContent("#verdict");
    if (/^(Valid|Intact|Invalid|Could not)/.test(verdict)) problems.push(`${colorScheme}: verdict in English: ${verdict}`);
    problems.push(...(await axe(page, `${colorScheme} de, verified`)));
    // Switch to English: the words and lang follow, the report is shown again in English.
    await page.selectOption("#lang", "en");
    const after = await page.evaluate(() => [document.documentElement.lang, document.querySelector("h1").textContent, document.getElementById("verdict").textContent]);
    if (after[0] !== "en" || after[1] !== "Sovrasign Verify" || !/^(Valid|Intact|Invalid)/.test(after[2])) problems.push(`${colorScheme}: switching to English gave ${after}`);
    problems.push(...(await axe(page, `${colorScheme} en, verified`)));
    // The choice is remembered over the browser's language.
    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#issuers li").length > 0);
    const remembered = await page.evaluate(() => document.documentElement.lang);
    if (remembered !== "en") problems.push(`${colorScheme}: the chosen language was not remembered (${remembered})`);
    await context.close();
  }
} finally {
  await browser.close();
  server.close();
}

if (problems.length) {
  for (const p of problems) console.error(`a11y: ${p}`);
  process.exit(1);
}
console.log("browser verifier accessibility check passed (axe, light and dark, German and English)");
