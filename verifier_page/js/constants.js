/**
 * constants.js
 * Shared field types, operations, circuit mapping, encoding utils.
 * Imported by both prover.js and verifier.js
 */

// ── Field Types ───────────────────────────────────────────────────────────────
export const FT = {
  Text:        0,
  Email:       1,
  Number:      2,
  Date:        3,
  File:        4,   // Attachment File — value IS a hash of referenced document
  LongText:    5,
};

export const FT_NAMES = [
  'Text', 'Email', 'Number', 'Date', 'Attachment File', 'Long Text',
];

// ── Operations per type ───────────────────────────────────────────────────────
export const OPS = {
  numeric: [
    { v: 'gt',    l: '> gt'       },
    { v: 'gte',   l: '>= gte'     },
    { v: 'lt',    l: '< lt'       },
    { v: 'lte',   l: '<= lte'     },
    { v: 'eq',    l: '= eq'       },
    { v: 'range', l: '↔ range'    },
  ],
  text: [
    { v: 'hash_eq', l: '# hash_eq' },
  ],
  attachment: [
    { v: 'doc_hash_eq', l: '🔗 doc hash eq' },  // compare by referenced doc hash directly
  ],
};

export function opsFor(type) {
  if (type === FT.Number || type === FT.Date) return OPS.numeric;
  if (type === FT.File)                       return OPS.attachment;
  return OPS.text;
}

// ── Op display symbol ─────────────────────────────────────────────────────────
export function opSym(op) {
  return {
    gt:          '>',
    gte:         '≥',
    lt:          '<',
    lte:         '≤',
    eq:          '=',
    range:       '∈',
    hash_eq:     '#=',
    doc_hash_eq: '🔗=',
  }[op] || op;
}

// ── Circuit file mapping ──────────────────────────────────────────────────────
export function circuitFor(type, op) {
  if (type === FT.Number) {
    if (op === 'range' || op === 'gte') return 'number_range.circom';
    if (op === 'eq')                    return 'number_eq.circom';
    return 'number_gt.circom';  // gt, lt, lte all use the same template with threshold
  }
  if (type === FT.Date) return 'date_range.circom';
  if (type === FT.File) return 'attachment_hash_eq.circom';
  return 'text_hash_eq.circom';
}

// ── Value encoding: JavaScript value → BigInt field element ──────────────────
export function encodeValue(value, type) {
  switch (type) {
    case FT.Number:
      return BigInt(Math.round(Number(value) || 0));

    case FT.Date:
      // "YYYY-MM-DD" → YYYYMMDD as integer
      return BigInt(String(value).replace(/-/g, '') || '0');

    case FT.File: {
      // Attachment value IS a hash string — parse as hex BigInt
      const clean = String(value).replace(/^0x/i, '').replace(/\.\.\./g, '').trim();
      try { return BigInt('0x' + clean); } catch { return 0n; }
    }

    case FT.Text:
    case FT.Email:
    case FT.LongText:
    default: {
      // String → felt: accumulate char codes in little-endian base-256
      // Max 31 characters before needing chunking (production: use proper felt encoding)
      let acc = 0n;
      const s = String(value);
      for (let i = 0; i < Math.min(s.length, 31); i++) {
        acc += BigInt(s.charCodeAt(i)) * (256n ** BigInt(i));
      }
      return acc;
    }
  }
}

export function encodeKey(key) {
  return encodeValue(key, FT.Text);
}

// ── Simulated Poseidon ────────────────────────────────────────────────────────
// NOTE: This is a UI-demo hash only. In production replace with:
//   import { buildPoseidon } from 'circomlibjs';
export function poseidon(...args) {
  let h = 0x9e3779b97f4a7c15n;
  for (const x of args) {
    h ^= BigInt(x);
    h = BigInt.asUintN(64, h * 6364136223846793005n + 1442695040888963407n);
  }
  return h;
}

// ── Field hash: Poseidon(key_felt, type_felt, value_felt) ─────────────────────
export function fieldHash(field) {
  return poseidon(
    encodeKey(field.key),
    BigInt(field.type),
    encodeValue(field.value, field.type),
  );
}

// ── Evaluate whether a rule constraint is satisfied (for UI preview) ──────────
export function evalConstraint(rule, field) {
  const num = Number(field.value);
  switch (rule.op) {
    case 'gt':          return num  >  Number(rule.val);
    case 'gte':         return num  >= Number(rule.val);
    case 'lt':          return num  <  Number(rule.val);
    case 'lte':         return num  <= Number(rule.val);
    case 'eq':          return String(field.value) === String(rule.val);
    case 'range':       return num  >= Number(rule.min) && num <= Number(rule.max);
    case 'hash_eq':     return field.value === rule.val;
    case 'doc_hash_eq': {
      const stored   = String(field.value).replace(/\s|\.\.\./g, '').toLowerCase();
      const expected = String(rule.docHash).replace(/\s|\.\.\./g, '').toLowerCase();
      return stored !== '' && expected !== '' && stored === expected;
    }
    default: return false;
  }
}

// ── Build snarkjs witness input object for a single rule ──────────────────────
export function buildWitnessInput(rule, field, credentialRootBig) {
  const enc   = encodeValue(field.value, field.type);
  const fh    = fieldHash(field);
  const base  = {
    value:          enc.toString(),
    key:            encodeKey(field.key).toString(),
    typ:            field.type.toString(),
    fieldHash:      fh.toString(),
    credentialRoot: credentialRootBig.toString(),
  };

  if (rule.op === 'range') {
    return { ...base, minVal: rule.min.toString(), maxVal: rule.max.toString() };
  }
  if (rule.op === 'hash_eq') {
    return { ...base, expectedValueHash: poseidon(enc).toString() };
  }
  if (rule.op === 'doc_hash_eq') {
    const clean = String(rule.docHash).replace(/^0x/i, '').replace(/\.\.\./g, '').trim();
    let expBig = 0n;
    try { expBig = BigInt('0x' + clean); } catch { /* ignore */ }
    return { ...base, expectedDocHash: expBig.toString() };
  }
  // gt, gte, lt, lte, eq
  return { ...base, threshold: rule.val.toString() };
}

// ── Build complete proof export bundle ────────────────────────────────────────
export function buildProofBundle(credentialHash, fields, rules) {
  let rootBig;
  try { rootBig = BigInt(credentialHash); } catch { return null; }

  const proofs = [];
  for (const r of rules) {
    const f = fields.find(x => x.key === r.key);
    if (!f) continue;
    const ok     = evalConstraint(r, f);
    const inputs = buildWitnessInput(r, f, rootBig);
    const cFile  = circuitFor(f.type, r.op);

    proofs.push({
      rule:    { key: r.key, op: r.op, val: r.val, min: r.min, max: r.max, docHash: r.docHash },
      field:   { key: f.key, type: f.type, typeName: FT_NAMES[f.type] },
      circuit: cFile,
      valid:   ok,
      witnessInputs: inputs,
      // Simulated proof structure (replace with real snarkjs output)
      proof: {
        pi_a: [poseidon(fieldHash(f), 1n).toString(), poseidon(rootBig, 2n).toString(), '1'],
        pi_b: [[poseidon(fieldHash(f), 3n).toString(), poseidon(rootBig, 4n).toString()],
               [poseidon(fieldHash(f), 5n).toString(), poseidon(rootBig, 6n).toString()], ['1','0']],
        pi_c: [poseidon(fieldHash(f), 7n).toString(), poseidon(rootBig, 8n).toString(), '1'],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: [inputs.credentialRoot, ...(ok ? ['1'] : ['0'])],
    });
  }

  return {
    version:        '1.0',
    credentialRoot: credentialHash,
    generatedAt:    new Date().toISOString(),
    proofs,
  };
}
