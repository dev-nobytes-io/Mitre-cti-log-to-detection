// Mermaid diagram generators.
// Each function returns a Mermaid source string. They escape labels and
// use stable, alphanumeric node IDs so re-renders don't trip the parser.

export function conceptualDiagram() {
  return `flowchart LR
    log[/"Raw log<br/>(EDR, Sysmon, firewall…)"/]:::raw
    src["ATT&CK Data Source<br/>e.g. Process"]:::ds
    cmp["ATT&CK Data Component<br/>e.g. Process Creation"]:::dc
    rel{{"detects relationship<br/>(STIX)"}}:::rel
    tech["ATT&CK Technique<br/>e.g. T1059"]:::tech
    tac["ATT&CK Tactic<br/>e.g. Execution"]:::tac
    nav[("Navigator layer<br/>score = max × ratio")]:::out

    log --> src
    src --> cmp
    cmp --> rel
    rel --> tech
    tech --> tac
    tech -. "weighted by your<br/>visibility score" .-> nav

    classDef raw fill:#1e293b,stroke:#475569,color:#cbd5e1;
    classDef ds  fill:#1c2230,stroke:#2f81f7,color:#e6edf3;
    classDef dc  fill:#1d3b32,stroke:#3fb950,color:#e6edf3;
    classDef rel fill:#3b2c1d,stroke:#d29922,color:#fef3c7;
    classDef tech fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3;
    classDef tac fill:#2b1d3b,stroke:#a78bfa,color:#e6edf3;
    classDef out fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
  `;
}

// Diagram for a single data source: source -> components -> techniques.
export function sourceDiagram({ dataSource, attack, componentScores, maxTechniquesPerComponent = 20, onlyCovered = false }) {
  if (!dataSource) return null;
  const lines = ["flowchart LR"];
  const sId = nodeId("S", dataSource.id);
  const sourceEntry = lookupSourceScore(dataSource, componentScores);
  lines.push(`  ${sId}["${escape(dataSource.name)}<br/><i>${escape(dataSource.attackId || "")}</i>"]:::ds`);

  let drawnTech = 0;
  const techIdsSeen = new Set();
  for (const dc of dataSource.components) {
    const cId = nodeId("C", dc.id);
    const eff = componentScores.get(dc.id);
    const score = eff?.score ?? 0;
    const cls = score > 0 ? "dcCov" : "dcUnc";
    lines.push(`  ${cId}["${escape(dc.name)}<br/><i>score ${score}</i>"]:::${cls}`);
    lines.push(`  ${sId} --> ${cId}`);

    const techIds = dc.techniqueIds.slice(0, maxTechniquesPerComponent);
    for (const tid of techIds) {
      const tech = attack.techniqueById.get(tid);
      if (!tech) continue;
      if (onlyCovered && score === 0) continue;
      const tNode = nodeId("T", tech.id);
      if (!techIdsSeen.has(tech.id)) {
        const tCls = score > 0 ? "techCov" : "techUnc";
        lines.push(`  ${tNode}["${escape(tech.attackId)}<br/>${escape(truncate(tech.name, 32))}"]:::${tCls}`);
        techIdsSeen.add(tech.id);
      }
      lines.push(`  ${cId} --> ${tNode}`);
      drawnTech++;
    }
    if (dc.techniqueIds.length > techIds.length) {
      const moreId = `${cId}_more`;
      lines.push(`  ${moreId}(["+${dc.techniqueIds.length - techIds.length} more"]):::more`);
      lines.push(`  ${cId} --> ${moreId}`);
    }
  }

  lines.push(classDefs());
  if (drawnTech === 0) {
    lines.push(`  empty["No techniques to display"]:::more`);
    lines.push(`  ${sId} --> empty`);
  }
  return lines.join("\n");
}

// Diagram for a single technique: components that detect it, with their parent data sources.
export function techniqueDiagram({ technique, attack, componentScores }) {
  if (!technique) return null;
  const lines = ["flowchart RL"];
  const tNode = nodeId("T", technique.id);
  lines.push(`  ${tNode}["${escape(technique.attackId)}: ${escape(truncate(technique.name, 40))}<br/><i>${escape(technique.tactics.join(", "))}</i>"]:::techMain`);

  if (!technique.componentIds.length) {
    lines.push(`  none["No detecting data components defined"]:::more`);
    lines.push(`  none --> ${tNode}`);
    lines.push(classDefs());
    return lines.join("\n");
  }

  const sourcesSeen = new Set();
  for (const cid of technique.componentIds) {
    const dc = attack.componentById.get(cid);
    if (!dc) continue;
    const ds = attack.dataSourceById.get(dc.sourceId);
    const cId = nodeId("C", dc.id);
    const sId = nodeId("S", dc.sourceId);
    const eff = componentScores.get(dc.id);
    const score = eff?.score ?? 0;
    const cCls = score > 0 ? "dcCov" : "dcUnc";
    if (!sourcesSeen.has(dc.sourceId)) {
      lines.push(`  ${sId}["${escape(ds?.name || "Unknown source")}"]:::ds`);
      sourcesSeen.add(dc.sourceId);
    }
    lines.push(`  ${cId}["${escape(dc.name)}<br/><i>score ${score}</i>"]:::${cCls}`);
    lines.push(`  ${cId} --> ${tNode}`);
    lines.push(`  ${sId} --> ${cId}`);
  }
  lines.push(classDefs());
  return lines.join("\n");
}

// Bar-chart-style overview using Mermaid's xychart-beta (covered vs total per data source).
export function overviewDiagram({ attack, componentScores, topN = 12 }) {
  const ranked = attack.dataSources
    .map(ds => {
      const totalTech = new Set();
      const coveredTech = new Set();
      for (const dc of ds.components) {
        const score = componentScores.get(dc.id)?.score ?? 0;
        for (const tid of dc.techniqueIds) {
          totalTech.add(tid);
          if (score > 0) coveredTech.add(tid);
        }
      }
      return { name: ds.name, total: totalTech.size, covered: coveredTech.size };
    })
    .filter(r => r.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, topN);

  if (!ranked.length) return null;

  // Use a flowchart with bar-like nodes — xychart-beta is finicky and not as readable for this.
  const lines = ["flowchart TB"];
  lines.push(`  title["Detection breadth: covered / total techniques per data source"]:::title`);
  for (const r of ranked) {
    const id = nodeId("OV", r.name);
    const pct = r.total ? Math.round((r.covered / r.total) * 100) : 0;
    const bar = renderBar(pct);
    const cls = r.covered === 0 ? "ovUnc" : (r.covered === r.total ? "ovFull" : "ovPart");
    lines.push(`  ${id}["${escape(r.name)} &nbsp; ${bar} &nbsp; ${r.covered}/${r.total} (${pct}%)"]:::${cls}`);
  }
  // Chain top -> bottom for vertical layout
  const ids = ranked.map(r => nodeId("OV", r.name));
  lines.push(`  title --> ${ids[0]}`);
  for (let i = 1; i < ids.length; i++) lines.push(`  ${ids[i-1]} --> ${ids[i]}`);
  lines.push(`
    classDef title fill:transparent,stroke:transparent,color:#8b949e,font-size:11px;
    classDef ovFull fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef ovPart fill:#1c2230,stroke:#2f81f7,color:#e6edf3;
    classDef ovUnc  fill:#2a2f3a,stroke:#475569,color:#cbd5e1;
  `);
  return lines.join("\n");
}

function renderBar(pct) {
  const filled = Math.round(pct / 5); // 0..20
  const empty = 20 - filled;
  return "▰".repeat(filled) + "▱".repeat(empty);
}

function classDefs() {
  return `
    classDef ds    fill:#1c2230,stroke:#2f81f7,color:#e6edf3;
    classDef dcCov fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef dcUnc fill:#2a2f3a,stroke:#475569,color:#cbd5e1;
    classDef techCov fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3;
    classDef techUnc fill:#1c1f26,stroke:#3a3f4a,color:#8b949e;
    classDef techMain fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3,stroke-width:2px;
    classDef more  fill:#161b22,stroke:#30363d,color:#8b949e;
    classDef rel   fill:#3b2c1d,stroke:#d29922,color:#fef3c7;
  `;
}

function lookupSourceScore(ds, compScores) {
  for (const dc of ds.components) {
    const v = compScores.get(dc.id);
    if (v) return v;
  }
  return null;
}

// Mermaid IDs must match /[A-Za-z][A-Za-z0-9_]*/. Hash to keep them stable & short.
function nodeId(prefix, raw) {
  let h = 0;
  const s = String(raw);
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `${prefix}_${h.toString(36)}`;
}

function escape(s) {
  // Mermaid uses double-quoted labels; escape quotes and pipe characters.
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/\|/g, "&#124;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function truncate(s, n) {
  if (!s) return "";
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}
