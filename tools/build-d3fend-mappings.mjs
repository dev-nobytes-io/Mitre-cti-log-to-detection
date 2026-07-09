// Fetches MITRE D3FEND's official "ATT&CK Mitigations to D3FEND Mappings"
// (the same JSON-LD that backs https://d3fend.mitre.org/mappings/attack-mitigations/)
// and flattens it into a small offline lookup: ATT&CK mitigation id (M1032)
// -> the D3FEND defensive techniques D3FEND publishes as implementing it.
//
// D3FEND models these as more specific/granular than the ATT&CK mitigation
// they hang off of (e.g. M1032 Multi-factor Authentication -> D3-MFA), which
// is the "sub-mitigation" relationship this app surfaces alongside ATT&CK
// mitigations.
//
// Also fetches D3FEND's own D3FEND-technique -> NIST SP 800-53 Rev 5 control
// mapping and chains it onto each D3FEND sub-mitigation (joined by the
// ontology's local individual name, e.g. "AccountLocking"), so a mitigation
// resolves ATT&CK -> D3FEND -> NIST in one hop.
//
// There is no equivalent official ATT&CK/D3FEND -> ISM (Australian
// Information Security Manual) mapping published anywhere as of writing —
// ISM entries are expected to come from the app's manual mapping editor
// instead (see js/custom-mappings.js).
//
// Run: node tools/build-d3fend-mappings.mjs > vendor/d3fend-mitigations.json
const MITIGATIONS_URL = "https://d3fend.mitre.org/api/mappings/attack-mitigations.json";
const NIST_URL = "https://d3fend.mitre.org/api/mappings/nist.5.json";

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
  return res.json();
}

const [mitigationsRaw, nistRaw] = await Promise.all([fetchJson(MITIGATIONS_URL), fetchJson(NIST_URL)]);

const graph = mitigationsRaw["@graph"] || [];
const byId = new Map(graph.map(o => [o["@id"], o]));
const typesOf = (o) => Array.isArray(o["@type"]) ? o["@type"] : [o["@type"]];
const first = (v) => Array.isArray(v) ? v[0] : v;

// D3FEND ontology local name (e.g. "AccountLocking") -> [NIST 800-53 control ids].
// nist.5.json is a SPARQL results payload keyed by D3FEND technique name, with
// the local name in the Defensive_Technique URI fragment after '#'.
const nistByLocalName = new Map();
for (const row of nistRaw.results?.bindings || []) {
  const uri = row.Defensive_Technique?.value || "";
  const localName = uri.split("#").pop();
  const control = row.Control?.value;
  if (!localName || !control) continue;
  if (!nistByLocalName.has(localName)) nistByLocalName.set(localName, new Set());
  nistByLocalName.get(localName).add(control);
}

const mitigations = graph
  .filter(o => typesOf(o).includes("d3f:ATTACKEnterpriseMitigation") && /^d3f:M\d+$/.test(o["@id"]))
  .map(o => {
    const attackId = o["@id"].replace("d3f:", "");
    const related = (o["d3f:related"] || []).map(r => {
      const d = byId.get(r["@id"]);
      if (!d) return null;
      const localName = r["@id"].replace("d3f:", "");
      return {
        id: first(d["d3f:d3fend-id"]) || "",
        name: first(d["rdfs:label"]) || "",
        definition: first(d["d3f:definition"]) || "",
        nist: Array.from(nistByLocalName.get(localName) || []).sort(),
      };
    }).filter(Boolean);
    return {
      attackId,
      name: first(o["rdfs:label"]) || "",
      comment: first(o["d3f:d3fend-comment"]) || "",
      d3fend: related,
    };
  })
  .sort((a, b) => a.attackId.localeCompare(b.attackId));

const nistCount = mitigations.reduce((n, m) => n + m.d3fend.reduce((n2, d) => n2 + d.nist.length, 0), 0);
process.stdout.write(JSON.stringify({ source: MITIGATIONS_URL, nistSource: NIST_URL, mitigations }));
process.stderr.write(`fetched ${mitigations.length} mitigations, ${mitigations.reduce((n, m) => n + m.d3fend.length, 0)} D3FEND sub-mitigations, ${nistCount} NIST 800-53 control links\n`);
