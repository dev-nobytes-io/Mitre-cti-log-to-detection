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
// Run: node tools/build-d3fend-mappings.mjs > vendor/d3fend-mitigations.json
const SOURCE_URL = "https://d3fend.mitre.org/api/mappings/attack-mitigations.json";

const res = await fetch(SOURCE_URL);
if (!res.ok) throw new Error(`Failed to fetch ${SOURCE_URL}: ${res.status} ${res.statusText}`);
const raw = await res.json();
const graph = raw["@graph"] || [];

const byId = new Map(graph.map(o => [o["@id"], o]));
const typesOf = (o) => Array.isArray(o["@type"]) ? o["@type"] : [o["@type"]];
const first = (v) => Array.isArray(v) ? v[0] : v;

const mitigations = graph
  .filter(o => typesOf(o).includes("d3f:ATTACKEnterpriseMitigation") && /^d3f:M\d+$/.test(o["@id"]))
  .map(o => {
    const attackId = o["@id"].replace("d3f:", "");
    const related = (o["d3f:related"] || []).map(r => {
      const d = byId.get(r["@id"]);
      if (!d) return null;
      return {
        id: first(d["d3f:d3fend-id"]) || "",
        name: first(d["rdfs:label"]) || "",
        definition: first(d["d3f:definition"]) || "",
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

process.stdout.write(JSON.stringify({ source: SOURCE_URL, mitigations }));
process.stderr.write(`fetched ${mitigations.length} mitigations, ${mitigations.reduce((n, m) => n + m.d3fend.length, 0)} D3FEND sub-mitigations\n`);
