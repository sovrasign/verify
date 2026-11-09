// Envelope schema versions in the built browser verifier (the real wasm32 module, loaded the way
// the page loads it): documents from earlier builds verify, and a document from a newer build
// returns code 16 ("reload the page"), not an "invalid" report.
//
//   scripts/build-verifier.sh && node web/verifier/versions.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ERR_UNSUPPORTED_VERSION = 16;
const corpus = new URL("../../core/signpdf-core/tests/corpus/", import.meta.url);
const wasm = await WebAssembly.compile(readFileSync(new URL("./signpdf_wasm.wasm", import.meta.url)));
const decoder = new TextDecoder();

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

let failures = 0;
const fail = (msg) => {
  console.error(`FAIL ${msg}`);
  failures++;
};

// Every fixture of every supported version, with the trust store pinned for its fixture set.
let checked = 0;
const corpusDir = fileURLToPath(corpus);
for (const version of readdirSync(corpusDir).filter((d) => /^v\d+$/.test(d))) {
  for (const set of readdirSync(join(corpusDir, version))) {
    const dir = join(corpusDir, version, set);
    if (!statSync(dir).isDirectory()) continue;
    const trust = readFileSync(join(dir, "trust.json"));
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".pdf"))) {
      const name = `${version}/${set}/${file}`;
      const v = call("signpdf_verify", readFileSync(join(dir, file)), trust);
      if (v.code !== 0) {
        fail(`${name}: code ${v.code}: ${decoder.decode(v.out)}`);
        continue;
      }
      const report = JSON.parse(decoder.decode(v.out));
      if (!report.valid || !report.identities_trusted) fail(`${name}: not valid: ${report.messages}`);
      checked++;
    }
  }
}
if (checked === 0) fail("no corpus documents found");

// The versions the module says it reads (signpdf_schema_versions, for a host that compares them
// with a document before the user starts) match what it does: every corpus version is in range,
// the newer document's version is not.
const { code: vcode, out: vout } = call("signpdf_schema_versions");
const versions = vcode === 0 ? JSON.parse(decoder.decode(vout)) : null;
if (!versions || !(versions.oldest <= versions.newest)) fail(`signpdf_schema_versions: ${decoder.decode(vout)}`);
else {
  for (const v of readdirSync(corpusDir).filter((d) => /^v\d+$/.test(d)).map((d) => Number(d.slice(1)))) {
    if (v < versions.oldest || v > versions.newest) fail(`corpus v${v} is outside ${JSON.stringify(versions)}`);
  }
  if (versions.newest >= 1000) fail("the newer-version fixture is no longer newer than this build");
}

// A document from a newer build.
const newer = readFileSync(new URL("newer/schema-v1000.pdf", corpus));
for (const op of ["signpdf_verify", "signpdf_certificate"]) {
  const r = call(op, newer, new Uint8Array());
  const msg = decoder.decode(r.out);
  if (r.code !== ERR_UNSUPPORTED_VERSION) fail(`${op} of a v1000 document: code ${r.code}: ${msg}`);
  else if (!msg.includes("reload the page")) fail(`${op}: message does not say to reload: ${msg}`);
}

if (failures) process.exit(1);
console.log(
  `browser verifier schema-version check passed (${checked} corpus documents, reads ` +
    `v${versions.oldest}–v${versions.newest}, newer version refused)`,
);
