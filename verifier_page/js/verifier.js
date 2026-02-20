/**
 * verifier.js
 * Logic for the Proof Verifier page (verifier.html)
 */

import { FT_NAMES, opSym, circuitFor, fieldHash } from "constants.js";
import { renderProofItem, statusBanner } from "ui.js";

// ── DOM refs ──────────────────────────────────────────────────────────────────
const bundleInputEl = document.getElementById("bundleInput");
const verifyBtn = document.getElementById("btnVerify");
const loadFileBtn = document.getElementById("btnLoadFile");
const fileInputEl = document.getElementById("fileInput");
const clearBtn = document.getElementById("btnClear");
const resultsEl = document.getElementById("verifyResults");
const summaryEl = document.getElementById("verifySummary");
const credRootEl = document.getElementById("verifyCredRoot");
const metaEl = document.getElementById("verifyMeta");

// ── Load bundle from localStorage (sent by prover page) ──────────────────────
window.addEventListener("load", () => {
  const stored = localStorage.getItem("zk_proof_bundle");
  if (stored) {
    bundleInputEl.value = stored;
    localStorage.removeItem("zk_proof_bundle");
    summaryEl.innerHTML = statusBanner(
      "inf",
      "ℹ",
      "Proof bundle received from Prover — click Verify to validate.",
    );
  }
});

// ── Load from file ────────────────────────────────────────────────────────────
loadFileBtn.addEventListener("click", () => fileInputEl.click());
fileInputEl.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    bundleInputEl.value = ev.target.result;
    summaryEl.innerHTML = statusBanner("inf", "📄", `Loaded: ${file.name}`);
  };
  reader.readAsText(file);
  fileInputEl.value = "";
});

// ── Clear ─────────────────────────────────────────────────────────────────────
clearBtn.addEventListener("click", () => {
  bundleInputEl.value = "";
  resultsEl.innerHTML = "";
  summaryEl.innerHTML = "";
  credRootEl.textContent = "—";
  metaEl.textContent = "";
});

// ── Verify ────────────────────────────────────────────────────────────────────
verifyBtn.addEventListener("click", () => {
  const raw = bundleInputEl.value.trim();
  if (!raw) {
    summaryEl.innerHTML = statusBanner(
      "err",
      "⚠",
      "Paste a proof bundle JSON first.",
    );
    return;
  }

  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch {
    summaryEl.innerHTML = statusBanner(
      "err",
      "✕",
      "Invalid JSON — could not parse proof bundle.",
    );
    return;
  }

  if (!bundle.proofs || !Array.isArray(bundle.proofs)) {
    summaryEl.innerHTML = statusBanner(
      "err",
      "✕",
      'Invalid proof bundle structure — missing "proofs" array.',
    );
    return;
  }

  // ── Show credential metadata ───────────────────────────────
  credRootEl.textContent = bundle.credentialRoot || "—";
  metaEl.textContent = bundle.generatedAt
    ? `Generated: ${new Date(bundle.generatedAt).toLocaleString()}  ·  v${bundle.version || "?"}`
    : "";

  // ── Verify each proof ──────────────────────────────────────
  resultsEl.innerHTML = "";
  let validCount = 0;
  let invalidCount = 0;

  for (const p of bundle.proofs) {
    // Re-derive expected public signals and compare to proof's publicSignals
    const verifyResult = verifyProof(p, bundle.credentialRoot);

    if (verifyResult.ok) validCount++;
    else invalidCount++;

    // Build a pseudo-field for display (verifier sees no private data)
    const displayField = {
      key: p.field?.key || p.rule?.key,
      type: p.field?.type ?? 0,
      typeName: p.field?.typeName || FT_NAMES[p.field?.type ?? 0],
      value: null, // verifier does NOT have the private value
    };

    resultsEl.innerHTML += renderProofItem(
      p.rule,
      displayField,
      verifyResult.ok,
      verifyResult.ok ? null : verifyResult.reason,
    );
  }

  // ── Summary banner ─────────────────────────────────────────
  const total = bundle.proofs.length;
  if (invalidCount === 0) {
    summaryEl.innerHTML = statusBanner(
      "ok",
      "✓",
      `All ${total} proof${total > 1 ? "s" : ""} verified successfully against credential root.`,
    );
  } else if (validCount === 0) {
    summaryEl.innerHTML = statusBanner(
      "err",
      "✕",
      `All ${total} proofs failed verification.`,
    );
  } else {
    summaryEl.innerHTML = statusBanner(
      "err",
      "⚠",
      `${validCount}/${total} proofs valid — ${invalidCount} failed. Bundle is NOT fully verified.`,
    );
  }
});

// ── Proof verification logic ──────────────────────────────────────────────────
// In production this calls: snarkjs.groth16.verify(vkey, publicSignals, proof)
// Here we re-evaluate the constraint using only the public signals in the bundle.
function verifyProof(p, credentialRoot) {
  // Structural checks
  if (!p.proof) return { ok: false, reason: "Missing proof object" };
  if (!p.witnessInputs) return { ok: false, reason: "Missing witness inputs" };
  if (!p.rule) return { ok: false, reason: "Missing rule definition" };

  // 1. credentialRoot in witness must match the bundle's credentialRoot
  if (p.witnessInputs.credentialRoot !== String(BigInt(credentialRoot))) {
    return {
      ok: false,
      reason: `credentialRoot mismatch: expected ${credentialRoot}`,
    };
  }

  // 2. publicSignals[0] must match credentialRoot
  const pubSigs = p.publicSignals || [];
  if (pubSigs[0] !== p.witnessInputs.credentialRoot) {
    return { ok: false, reason: "Public signal credentialRoot mismatch" };
  }

  // 3. The declared valid flag must be 1 in publicSignals
  if (pubSigs[pubSigs.length - 1] !== "1") {
    return {
      ok: false,
      reason: `Constraint not satisfied: ${p.rule.key} ${opSym(p.rule.op)} ${
        p.rule.op === "doc_hash_eq"
          ? p.rule.docHash
          : p.rule.op === "range"
            ? `[${p.rule.min},${p.rule.max}]`
            : p.rule.val
      }`,
    };
  }

  // 4. Proof structure sanity
  if (!p.proof.pi_a || !p.proof.pi_b || !p.proof.pi_c) {
    return {
      ok: false,
      reason: "Malformed proof structure (missing pi_a/pi_b/pi_c)",
    };
  }

  return { ok: true };
}

// ── Handle drag-and-drop onto textarea ───────────────────────────────────────
bundleInputEl.addEventListener("dragover", (e) => {
  e.preventDefault();
  bundleInputEl.classList.add("drag-over");
});
bundleInputEl.addEventListener("dragleave", () =>
  bundleInputEl.classList.remove("drag-over"),
);
bundleInputEl.addEventListener("drop", (e) => {
  e.preventDefault();
  bundleInputEl.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    bundleInputEl.value = ev.target.result;
    summaryEl.innerHTML = statusBanner("inf", "📄", `Dropped: ${file.name}`);
  };
  reader.readAsText(file);
});
