// Generate an ATT&CK Navigator layer (v4.5 schema-compatible) from coverage rows.
// Reference: https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md

const DOMAIN_TO_LAYER_DOMAIN = {
  "enterprise-attack": "enterprise-attack",
  "mobile-attack": "mobile-attack",
  "ics-attack": "ics-attack",
};

export function buildNavigatorLayer({ coverage, attack, name = "Data source coverage", description = "", colorMin = "#ffe0b3", colorMax = "#0066cc", includeUncovered = false } = {}) {
  const techniques = [];
  for (const row of coverage.rows) {
    if (!row.hasDetections) continue;
    if (!includeUncovered && row.weightedScore <= 0) continue;
    const tooltip = buildTooltip(row);
    techniques.push({
      techniqueID: row.attackId,
      score: round2(row.weightedScore),
      color: "",
      comment: tooltip,
      enabled: true,
      metadata: [
        { name: "Detecting components total", value: String(row.totalDetectingComponents) },
        { name: "Covered components", value: String(row.coveredComponents) },
        { name: "Coverage ratio", value: `${Math.round(row.ratio * 100)}%` },
        { name: "Max source score", value: String(row.maxScore) },
        ...row.coveringComponents.map(c => ({ name: `Source: ${c.sourceName}`, value: `${c.componentName} (${c.score})` })),
      ],
      links: [],
      showSubtechniques: row.isSubtechnique ? true : false,
    });
  }

  return {
    name,
    versions: {
      attack: attack.meta?.version && /^[0-9.]+$/.test(String(attack.meta.version)) ? String(attack.meta.version) : "16",
      navigator: "5.1.0",
      layer: "4.5",
    },
    domain: DOMAIN_TO_LAYER_DOMAIN[attack.meta?.domain] || "enterprise-attack",
    description: description || "Detection coverage from log source inventory",
    filters: {
      platforms: Array.from(new Set(techniques.flatMap(t => attack.techniqueByAttackId.get(t.techniqueID)?.platforms || []))),
    },
    sorting: 3,
    layout: { layout: "side", aggregateFunction: "average", showID: false, showName: true, showAggregateScores: true, countUnscored: false },
    hideDisabled: false,
    techniques,
    gradient: { colors: [colorMin, colorMax], minValue: 0, maxValue: 5 },
    legendItems: [
      { label: "Score 0 - no coverage", color: "#444444" },
      { label: "Score 1-2 - low", color: colorMin },
      { label: "Score 3-4 - medium/high", color: blendHex(colorMin, colorMax, 0.6) },
      { label: "Score 5 - excellent", color: colorMax },
    ],
    metadata: [
      { name: "Generated", value: new Date().toISOString() },
      { name: "Tool", value: "ATT&CK Log Source Inventory web app" },
      { name: "ATT&CK domain", value: attack.meta?.domain || "" },
      { name: "ATT&CK version", value: attack.meta?.version || "" },
    ],
    showTacticRowBackground: false,
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}

function buildTooltip(row) {
  const lines = [
    `${row.coveredComponents}/${row.totalDetectingComponents} detecting components covered`,
    `Max score ${row.maxScore}, weighted ${round2(row.weightedScore)}`,
  ];
  for (const c of row.coveringComponents) {
    lines.push(`• ${c.sourceName} → ${c.componentName} (${c.score})`);
  }
  return lines.join("\n");
}

function round2(n) { return Math.round(n * 100) / 100; }

function blendHex(a, b, t) {
  const [ar, ag, ab] = hexToRgb(a);
  const [br, bg, bb] = hexToRgb(b);
  const r = Math.round(ar + (br - ar) * t);
  const g = Math.round(ag + (bg - ag) * t);
  const bl = Math.round(ab + (bb - ab) * t);
  return `#${[r, g, bl].map(x => x.toString(16).padStart(2, "0")).join("")}`;
}

function hexToRgb(hex) {
  const s = hex.replace(/^#/, "");
  const v = s.length === 3 ? s.split("").map(c => c + c).join("") : s;
  return [parseInt(v.slice(0, 2), 16), parseInt(v.slice(2, 4), 16), parseInt(v.slice(4, 6), 16)];
}
