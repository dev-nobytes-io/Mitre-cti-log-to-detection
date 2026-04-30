// Compute detection coverage for techniques.
//
// Two engines coexist for one chunk:
//   - computeCoverage()    — legacy v1 chain: data component -> technique
//                            (via the old `detects` relationship). Only used
//                            when the loaded ATT&CK bundle has no
//                            x-mitre-detection-strategy objects.
//   - computeCoverageV2()  — v18+ chain: log source -> analytic -> detection
//                            strategy -> technique. Preferred whenever the
//                            bundle exposes detection strategies.
//
// Both engines emit the same row shape (legacy fields are aliased on V2 rows
// so navigator.js, the threats/gaps tab, and existing tests keep working
// without changes).

export function computeCoverage(attack, componentScores) {
  // componentScores: Map(componentId -> { score, ... })
  const techniqueRows = attack.techniques.map(tech => {
    const compIds = tech.componentIds;
    const total = compIds.length;
    let coveredCount = 0;
    let maxScore = 0;
    const coveringComponents = [];
    for (const cid of compIds) {
      const entry = componentScores.get(cid);
      if (entry && entry.score > 0) {
        coveredCount += 1;
        if (entry.score > maxScore) maxScore = entry.score;
        coveringComponents.push({ componentId: cid, ...entry });
      }
    }
    const ratio = total === 0 ? 0 : coveredCount / total;
    const weighted = maxScore * ratio;
    return {
      attackId: tech.attackId,
      stixId: tech.id,
      name: tech.name,
      tactics: tech.tactics,
      isSubtechnique: tech.isSubtechnique,
      platforms: tech.platforms,
      totalDetectingComponents: total,
      coveredComponents: coveredCount,
      ratio,
      maxScore,
      weightedScore: weighted,
      coveringComponents,
      hasDetections: total > 0,
    };
  });

  const detectable = techniqueRows.filter(r => r.hasDetections);
  const covered = detectable.filter(r => r.coveredComponents > 0);
  const fully = detectable.filter(r => r.ratio >= 1);
  const partial = detectable.filter(r => r.ratio > 0 && r.ratio < 1);

  return {
    rows: techniqueRows,
    summary: {
      total: techniqueRows.length,
      detectable: detectable.length,
      covered: covered.length,
      fully: fully.length,
      partial: partial.length,
      avgScore: covered.length ? covered.reduce((s, r) => s + r.weightedScore, 0) / covered.length : 0,
    },
  };
}

// V2: compute coverage along the v18+ chain.
//
// For each technique:
//   - Find every detection strategy that detects it (techniques.strategyIds).
//   - For each strategy, score every analytic it references; an analytic is
//     "lit" iff every required log source has score > 0. Analytic score is
//     the aggregator over those scores (default `min`; user can pick `avg`).
//   - A strategy is "lit" iff at least one of its analytics is lit. Strategy
//     score = max of its lit analytic scores.
//   - Technique score = max strategy score among lit strategies. Coverage
//     ratio = lit strategies / total strategies.
//
// Score aggregation default = `min` (chain-is-only-as-strong-as-the-weakest-
// log) is semantically correct but punishing; the UI exposes a toggle for
// `avg` for users who'd rather grade leniently.
export function computeCoverageV2(attack, logSourceScores, { analyticAggregation = "min" } = {}) {
  const aggregate = analyticAggregation === "avg"
    ? (vals) => vals.length ? vals.reduce((s, v) => s + v, 0) / vals.length : 0
    : (vals) => vals.length ? Math.min(...vals) : 0;

  // 1. Score each analytic.
  const analyticScores = new Map(); // analyticId -> { lit, score, name, logSources: [{id,name,channel,score}] }
  for (const an of attack.analytics || []) {
    const lsList = (an.logSourceIds || []).map(id => {
      const ls = attack.logSourceById?.get(id);
      const score = logSourceScores.get(id)?.score || 0;
      return ls ? { id, name: ls.name, channel: ls.channel, score } : null;
    }).filter(Boolean);
    const scores = lsList.map(l => l.score);
    const lit = lsList.length > 0 && scores.every(s => s > 0);
    const score = lit ? aggregate(scores) : 0;
    analyticScores.set(an.id, { lit, score, name: an.name, logSources: lsList });
  }

  // 2. Score each detection strategy.
  const strategyScores = new Map(); // strategyId -> { lit, score, name, attackId, analytics: [...] }
  for (const st of attack.detectionStrategies || []) {
    const ans = (st.analyticIds || []).map(id => {
      const a = analyticScores.get(id);
      return a ? { id, ...a } : null;
    }).filter(Boolean);
    const litAns = ans.filter(a => a.lit);
    const lit = litAns.length > 0;
    const score = lit ? Math.max(...litAns.map(a => a.score)) : 0;
    strategyScores.set(st.id, { lit, score, name: st.name, attackId: st.attackId, analytics: ans });
  }

  // 3. Score each technique via its detecting strategies.
  const rows = attack.techniques.map(tech => {
    const stratEntries = (tech.strategyIds || []).map(sid => {
      const s = strategyScores.get(sid);
      return s ? { id: sid, ...s } : null;
    }).filter(Boolean);
    const litStrats = stratEntries.filter(s => s.lit);
    const totalStrategies = stratEntries.length;
    const litStrategies = litStrats.length;
    const weightedScore = litStrategies > 0 ? Math.max(...litStrats.map(s => s.score)) : 0;
    const ratio = totalStrategies === 0 ? 0 : litStrategies / totalStrategies;

    return {
      attackId: tech.attackId,
      stixId: tech.id,
      name: tech.name,
      tactics: tech.tactics,
      isSubtechnique: tech.isSubtechnique,
      platforms: tech.platforms,
      // V2-native fields
      totalStrategies,
      litStrategies,
      weightedScore,
      ratio,
      contributing: stratEntries,
      hasDetections: totalStrategies > 0,
      // Legacy aliases so navigator.js, threats.js, and existing UI keep
      // working without changes. coveringComponents maps each lit strategy
      // into the legacy {sourceName, componentName, score} tooltip slot.
      maxScore: weightedScore,
      totalDetectingComponents: totalStrategies,
      coveredComponents: litStrategies,
      coveringComponents: litStrats.map(s => ({
        componentId: s.id,
        sourceName: s.attackId || "Detection Strategy",
        componentName: s.name,
        score: s.score,
      })),
    };
  });

  const detectable = rows.filter(r => r.hasDetections);
  const covered = detectable.filter(r => r.coveredComponents > 0);
  const fully = detectable.filter(r => r.ratio >= 1);
  const partial = detectable.filter(r => r.ratio > 0 && r.ratio < 1);

  return {
    rows,
    summary: {
      total: rows.length,
      detectable: detectable.length,
      covered: covered.length,
      fully: fully.length,
      partial: partial.length,
      avgScore: covered.length ? covered.reduce((s, r) => s + r.weightedScore, 0) / covered.length : 0,
    },
    engine: "v2",
  };
}
