// The trust-list vectors in the built verifier module (spec/envelope-format.md §12.4), run after
// the build:
//   node web/verifier/trust-vectors.mjs [signpdf_wasm.wasm]
// - spec/vectors/trust-list-rotation.json: the signed trust list's key-chain accept rule, through
//   the module's `signpdf_trust_list_consider` (a newer key in the pinned chain wins over any
//   sequence from an older key; older keys are then refused; keys outside the chain refused).
// - spec/vectors/tsa-distrust/: a timestamp from an authority the trust store distrusts from a
//   time counts before it and not at or after it (`signpdf_verify`).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const wasmPath = process.argv[2] || here("./signpdf_wasm.wasm");
const wasm = await WebAssembly.compile(readFileSync(wasmPath));
const enc = new TextEncoder();
const dec = new TextDecoder();

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

// --- the key-chain accept rule ---
const rot = JSON.parse(readFileSync(here("../../spec/vectors/trust-list-rotation.json"), "utf8"));
for (const c of rot.cases) {
  let pins = c.pins.map((n) => rot.keys[n]);
  let state = null;
  let sequence = null;
  const consider = (payload, jws) => {
    const r = call("signpdf_trust_list_consider", enc.encode(JSON.stringify({ pins, state })), enc.encode(payload), enc.encode(jws));
    if (r.code !== 0) throw new Error(`signpdf_trust_list_consider: code ${r.code}: ${dec.decode(r.out)}`);
    return JSON.parse(dec.decode(r.out));
  };
  c.steps.forEach((step, i) => {
    if (step.restart) return; // the state is all the module keeps: every call is a restart
    if (step.update) {
      pins = step.update.map((n) => rot.keys[n]);
      const r = consider("", "");
      state = r.state;
      sequence = r.sequence;
      return;
    }
    const list = rot.lists[step.list];
    const r = consider(list.payload, list.jws);
    if (r.outcome !== step.expect) fail(`${c.name}: step ${i} (${step.list}): ${r.outcome}, expected ${step.expect}`);
    state = r.state;
    sequence = r.sequence;
  });
  if (sequence !== c.held) fail(`${c.name}: holds ${sequence}, expected ${c.held}`);
}
console.log(`trust-list rotation: ${rot.cases.length} cases`);

// --- distrusting a timestamp authority from a time ---
const dir = "../../spec/vectors/tsa-distrust/";
const expected = JSON.parse(readFileSync(here(`${dir}expected.json`), "utf8"));
const pdf = readFileSync(here(dir + expected.pdf));
for (const c of expected.cases) {
  const trust = readFileSync(here(dir + c.trust));
  const r = call("signpdf_verify", pdf, trust);
  const report = JSON.parse(dec.decode(r.out));
  if (r.code !== 0) {
    fail(`${c.trust}: code ${r.code}`);
    continue;
  }
  const stampTrusted = (report.document_timestamps || []).every((d) => d.timestamp.trusted);
  const warned = (report.findings || []).some((f) => f.code === "tsa_distrusted");
  for (const [k, got] of [
    ["valid", Boolean(report.valid)],
    ["integrity_ok", Boolean(report.integrity_ok)],
    ["trusted_time_pending", Boolean(report.trusted_time_pending)],
    ["timestamp_trusted", stampTrusted],
    ["tsa_distrusted_warning", warned],
  ]) {
    if (got !== c[k]) fail(`${c.trust}: ${k} = ${got}, expected ${c[k]}`);
  }
}
console.log(`TSA distrust: ${expected.cases.length} cases`);

if (failures) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log("trust vectors: ok");
