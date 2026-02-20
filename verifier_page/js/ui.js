/**
 * ui.js
 * Shared DOM rendering helpers used by prover.js and verifier.js
 */

import {
  FT,
  FT_NAMES,
  opSym,
  circuitFor,
  fieldHash,
  opsFor,
} from "./constants.js";

// ── Type pill HTML ────────────────────────────────────────────────────────────
export function typePill(typeIndex) {
  return `<span class="tpill tp${typeIndex}">${FT_NAMES[typeIndex]}</span>`;
}

// ── Render a single proof result row ─────────────────────────────────────────
export function renderProofItem(rule, field, ok, errorMsg) {
  const isDoc = rule.op === "doc_hash_eq";
  const sym = opSym(rule.op);
  const conStr =
    rule.op === "range"
      ? `[${rule.min}, ${rule.max}]`
      : rule.op === "doc_hash_eq"
        ? rule.docHash
        : rule.val;
  const cFile = field ? circuitFor(field.type, rule.op) : "—";
  const fh = field ? fieldHash(field) : 0n;

  return `
    <div class="proof-item">
      <div class="pi-icon">${ok ? "✅" : "❌"}</div>
      <div class="pi-body">
        <div class="pi-rule">
          <span class="key">${rule.key}</span>
          <span class="op"> ${sym} </span>
          <span class="val ${isDoc ? "doc-hash" : ""}">${isDoc ? conStr.slice(0, 30) + "..." : conStr}</span>
          ${field ? typePill(field.type) : ""}
        </div>
        ${
          isDoc && field
            ? `
          <div class="doc-ref">📎 stores: <strong>${String(field.value || "").slice(0, 32)}...</strong></div>
        `
            : ""
        }
        <div class="pi-sub">${
          errorMsg
            ? `⚠ ${errorMsg}`
            : `fieldHash: 0x${fh.toString(16).slice(0, 20)}...  ·  ${cFile}`
        }</div>
      </div>
      <div class="pi-badge ${ok ? "badge-valid" : "badge-invalid"}">${ok ? "Valid" : "Invalid"}</div>
    </div>`;
}

// ── Render circuit inputs as syntax-highlighted code ─────────────────────────
export function renderCircuitCode(proofBundle) {
  if (!proofBundle) return "";
  let out = `<span class="cc">// ─── Credential root (predefined, public) ──────────────────────</span>\n`;
  out += `<span class="ck">const</span> credentialRoot = <span class="cn">${proofBundle.credentialRoot}</span>;\n\n`;

  for (const p of proofBundle.proofs) {
    const { rule, field, circuit, witnessInputs } = p;
    const conStr =
      rule.op === "range"
        ? `[${rule.min}, ${rule.max}]`
        : rule.op === "doc_hash_eq"
          ? rule.docHash
          : rule.val;

    out += `<span class="cc">// ── ${rule.key} ${opSym(rule.op)} ${conStr}  →  ${circuit} ──</span>\n`;
    out += `<span class="ck">const</span> inputs_${rule.key} = {\n`;

    for (const [k, v] of Object.entries(witnessInputs)) {
      const isHash = k === "expectedDocHash";
      const color = isHash
        ? "cr"
        : k === "value" || k === "key" || k === "typ"
          ? "cc"
          : "cn";
      const comment =
        k === "value"
          ? `  <span class="cc">// ${field.typeName} field — private</span>`
          : k === "typ"
            ? `  <span class="cc">// ${field.typeName} = ${field.type}</span>`
            : k === "credentialRoot"
              ? `  <span class="cc">// predefined</span>`
              : "";
      out += `  <span class="cs">${k}</span>: <span class="${color}">${v}n</span>,${comment}\n`;
    }

    out += `};\n`;
    out += `<span class="cc">// snarkjs.groth16.fullProve(inputs_${rule.key}, "${circuit.replace(".circom", ".wasm")}", "${circuit.replace(".circom", ".zkey")}")</span>\n\n`;
  }
  return out;
}

// ── Render field rows (prover page) ──────────────────────────────────────────
export function renderFieldRow(f, onInput, onTypeChange, onDelete) {
  const isFile = f.type === FT.File;
  const div = document.createElement("div");
  div.className = "field-row";
  div.dataset.id = f.id;
  div.innerHTML = `
    <input value="${esc(f.key)}" placeholder="key" />
    <select>
      ${FT_NAMES.map((n, i) => `<option value="${i}"${f.type === i ? " selected" : ""}>${n}</option>`).join("")}
    </select>
    ${
      isFile
        ? `<input class="hash-val" value="${esc(f.value)}" placeholder="0x... (referenced doc hash)" />`
        : `<input value="${esc(f.value)}" placeholder="value" />`
    }
    <button class="btn-del" title="Remove">✕</button>`;

  div
    .querySelector("input:nth-of-type(1)")
    .addEventListener("input", (e) => onInput(f.id, "key", e.target.value));
  div
    .querySelector("select")
    .addEventListener("change", (e) => onTypeChange(f.id, +e.target.value));
  div
    .querySelector("input:last-of-type")
    .addEventListener("input", (e) => onInput(f.id, "value", e.target.value));
  div.querySelector(".btn-del").addEventListener("click", () => onDelete(f.id));
  return div;
}

// ── Render rule rows (prover page) ────────────────────────────────────────────
export function renderRuleRow(r, fields, onKey, onOp, onVal, onDelete) {
  const f = fields.find((x) => x.key === r.key);
  const ft = f ? f.type : FT.Number;
  const ops = opsFor(ft);
  const isRange = r.op === "range";
  const isDocHash = r.op === "doc_hash_eq";

  const div = document.createElement("div");
  div.className = "rule-row";
  div.dataset.id = r.id;

  div.innerHTML = `
    <div class="rule-main">
      <select class="r-key">
        ${fields.map((fx) => `<option value="${esc(fx.key)}"${r.key === fx.key ? " selected" : ""}>${esc(fx.key)}</option>`).join("")}
      </select>
      <select class="r-op">
        ${ops.map((o) => `<option value="${o.v}"${r.op === o.v ? " selected" : ""}>${o.l}</option>`).join("")}
      </select>
      <div class="r-val-wrap">
        ${
          isRange
            ? `<div style="display:flex;gap:4px">
               <input class="r-min" placeholder="min"  value="${esc(r.min)}" style="width:50%"/>
               <input class="r-max" placeholder="max"  value="${esc(r.max)}" style="width:50%"/>
             </div>`
            : isDocHash
              ? `<span style="font-family:var(--mono);font-size:10px;color:var(--muted);padding:0 4px">↓ expected hash below</span>`
              : `<input class="r-val" placeholder="value" value="${esc(r.val)}"/>`
        }
      </div>
      <button class="btn-del">✕</button>
    </div>
    ${
      isDocHash
        ? `
    <div class="rule-doc-hash">
      <label>expected doc hash</label>
      <input class="r-dochash" placeholder="0xfa3c9d..." value="${esc(r.docHash)}" />
    </div>`
        : ""
    }`;

  div
    .querySelector(".r-key")
    .addEventListener("change", (e) => onKey(r.id, e.target.value));
  div
    .querySelector(".r-op")
    .addEventListener("change", (e) => onOp(r.id, e.target.value));
  div.querySelector(".btn-del").addEventListener("click", () => onDelete(r.id));

  if (isRange) {
    div
      .querySelector(".r-min")
      .addEventListener("input", (e) => onVal(r.id, "min", e.target.value));
    div
      .querySelector(".r-max")
      .addEventListener("input", (e) => onVal(r.id, "max", e.target.value));
  } else if (!isDocHash) {
    div
      .querySelector(".r-val")
      ?.addEventListener("input", (e) => onVal(r.id, "val", e.target.value));
  } else {
    div
      .querySelector(".r-dochash")
      ?.addEventListener("input", (e) =>
        onVal(r.id, "docHash", e.target.value),
      );
  }

  return div;
}

// ── Status banner ─────────────────────────────────────────────────────────────
export function statusBanner(type, icon, message) {
  return `<div class="status-banner ${type}">${icon} ${message}</div>`;
}

// ── Escape HTML ───────────────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}
