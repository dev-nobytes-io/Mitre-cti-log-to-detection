// Loads MITRE D3FEND's "ATT&CK Mitigations to D3FEND Mappings" — a small,
// vendored offline snapshot (regenerate via tools/build-d3fend-mappings.mjs)
// that maps an ATT&CK mitigation id (e.g. M1032) to the D3FEND defensive
// techniques D3FEND documents as implementing it (e.g. D3-MFA). D3FEND
// models these as more specific than the ATT&CK mitigation they hang off
// of, so this app surfaces them as "sub-mitigations". Each D3FEND
// sub-mitigation also carries D3FEND's own D3FEND -> NIST SP 800-53 Rev 5
// control mapping, chaining ATT&CK -> D3FEND -> NIST in one hop. There is
// no published D3FEND/ATT&CK -> ISM mapping, so ISM entries only ever come
// from the manual mapping editor (js/custom-mappings.js).
//
// Exposes:
//   loadD3fendMitigations() -> Map<attackId, { attackId, name, comment, d3fend: [{id, name, definition, nist: [controlId, ...]}] }>
//   attachD3fend(attack, d3fendByAttackId) -> mutates attack.mitigationById entries in place, adding `.d3fend`

const D3FEND_BUNDLE_URL = "vendor/d3fend-mitigations.json";

export async function loadD3fendMitigations() {
  const res = await fetch(D3FEND_BUNDLE_URL, { cache: "force-cache" });
  if (!res.ok) throw new Error(`Failed to load bundled D3FEND mappings: ${res.status}`);
  const data = await res.json();
  return new Map((data.mitigations || []).map(m => [m.attackId, m]));
}

// Merges D3FEND sub-mitigations onto an already-indexed AttackData (see
// attack.js indexBundle()). Mitigations the bundle doesn't know about are
// left with d3fend: [] rather than omitted, so UI code doesn't need to
// null-check.
export function attachD3fend(attack, d3fendByAttackId) {
  for (const m of attack.mitigations || []) {
    const entry = d3fendByAttackId.get(m.attackId);
    m.d3fendComment = entry?.comment || "";
    m.d3fend = entry?.d3fend || [];
  }
  return attack;
}
