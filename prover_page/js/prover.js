/**
 * prover.js
 * Logic for the Proof Generator page (prover.html)
 */

import {
  FT, FT_NAMES, opsFor, buildProofBundle, fieldHash, encodeValue, encodeKey,
  poseidon, circuitFor, opSym, evalConstraint,
} from './constants.js';
import {
  renderFieldRow, renderRuleRow, renderProofItem,
  renderCircuitCode, statusBanner,
} from './ui.js';

// ── State ─────────────────────────────────────────────────────────────────────
let fields = [
  { id: 1, key: 'name',    type: FT.Text,   value: 'Ardial'               },
  { id: 2, key: 'age',     type: FT.Number, value: '25'                   },
  { id: 3, key: 'email',   type: FT.Email,  value: 'ardial@example.com'   },
  { id: 4, key: 'license', type: FT.File,   value: '0xfa3c9d11b2e74a8b'   },
  { id: 5, key: 'dob',     type: FT.Date,   value: '1999-01-15'           },
];
let rules = [
  { id: 1, key: 'age',     op: 'gt',          val: '18',  min: '', max: '', docHash: '' },
  { id: 2, key: 'license', op: 'doc_hash_eq', val: '',    min: '', max: '', docHash: '0xfa3c9d11b2e74a8b' },
];
let nxt = 20;
let lastBundle = null;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const fieldListEl  = document.getElementById('fieldList');
const ruleListEl   = document.getElementById('ruleList');
const proofListEl  = document.getElementById('proofList');
const codeOutEl    = document.getElementById('codeOut');
const outSection   = document.getElementById('out');
const credHashEl   = document.getElementById('credHash');

// ── Render fields ─────────────────────────────────────────────────────────────
function renderFields() {
  fieldListEl.innerHTML = '';
  for (const f of fields) {
    fieldListEl.appendChild(
      renderFieldRow(f,
        (id, prop, val) => { updateField(id, prop, val); },
        (id, newType)   => { updateField(id, 'type', newType); rebuildRuleOps(id); renderFields(); },
        (id)            => { deleteField(id); },
      )
    );
  }
}

function updateField(id, prop, val) {
  const f = fields.find(x => x.id === id);
  if (f) f[prop] = val;
}

function deleteField(id) {
  fields = fields.filter(x => x.id !== id);
  // Remove rules that reference the deleted field
  rules = rules.filter(r => fields.some(f => f.key === r.key));
  renderFields();
  renderRules();
}

function rebuildRuleOps(fieldId) {
  const f = fields.find(x => x.id === fieldId);
  if (!f) return;
  rules.forEach(r => {
    if (r.key === f.key) r.op = opsFor(f.type)[0].v;
  });
  renderRules();
}

document.getElementById('btnAddField').addEventListener('click', () => {
  fields.push({ id: nxt++, key: '', type: FT.Text, value: '' });
  renderFields();
});

// ── Render rules ──────────────────────────────────────────────────────────────
function renderRules() {
  ruleListEl.innerHTML = '';
  if (!rules.length) {
    ruleListEl.innerHTML = '<div class="empty">No rules — click ＋ Rule</div>';
    return;
  }
  for (const r of rules) {
    ruleListEl.appendChild(
      renderRuleRow(r, fields,
        (id, key) => {
          const rule = rules.find(x => x.id === id);
          if (!rule) return;
          rule.key = key;
          const f  = fields.find(x => x.key === key);
          if (f)  rule.op = opsFor(f.type)[0].v;
          renderRules();
        },
        (id, op) => {
          const rule = rules.find(x => x.id === id);
          if (rule) rule.op = op;
          renderRules();
        },
        (id, prop, val) => {
          const rule = rules.find(x => x.id === id);
          if (rule) rule[prop] = val;
        },
        (id) => {
          rules = rules.filter(x => x.id !== id);
          renderRules();
        },
      )
    );
  }
}

document.getElementById('btnAddRule').addEventListener('click', () => {
  const f0 = fields[0];
  rules.push({
    id:      nxt++,
    key:     f0?.key || '',
    op:      f0 ? opsFor(f0.type)[0].v : 'gt',
    val:     '',
    min:     '',
    max:     '',
    docHash: '',
  });
  renderRules();
});

// ── Prove ─────────────────────────────────────────────────────────────────────
document.getElementById('btnProve').addEventListener('click', () => {
  const credHash = credHashEl.value.trim();
  if (!credHash) { alert('Enter a credential hash'); return; }
  if (!rules.length) { alert('Add at least one rule'); return; }

  const bundle = buildProofBundle(credHash, fields, rules);
  if (!bundle) { alert('Invalid credential hash'); return; }

  lastBundle = bundle;

  // Render proof results
  proofListEl.innerHTML = '';
  for (const p of bundle.proofs) {
    const f = fields.find(x => x.key === p.rule.key);
    proofListEl.innerHTML += renderProofItem(p.rule, f, p.valid);
  }

  // Render circuit code
  codeOutEl.innerHTML = renderCircuitCode(bundle);

  outSection.style.display = 'block';
  outSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

// ── Export JSON ───────────────────────────────────────────────────────────────
document.getElementById('btnExport').addEventListener('click', () => {
  if (!lastBundle) return;
  const blob = new Blob([JSON.stringify(lastBundle, null, 2)], { type: 'application/json' });
  const a    = Object.assign(document.createElement('a'), {
    href:     URL.createObjectURL(blob),
    download: 'proof-bundle.json',
  });
  a.click();
});

// ── Copy circuit inputs ───────────────────────────────────────────────────────
document.getElementById('btnCopyCode').addEventListener('click', () => {
  navigator.clipboard.writeText(codeOutEl.innerText).then(() => alert('Copied!'));
});

// ── Send to Verifier (open verifier page with bundle in localStorage) ─────────
document.getElementById('btnSendVerifier').addEventListener('click', () => {
  if (!lastBundle) { alert('Generate proofs first'); return; }
  localStorage.setItem('zk_proof_bundle', JSON.stringify(lastBundle));
  window.open('verifier.html', '_blank');
});

// ── Init ──────────────────────────────────────────────────────────────────────
renderFields();
renderRules();
