// Compute detection coverage for techniques along the ATT&CK v18+ chain:
//
//   Log Source ─▶ Analytic ─▶ Detection Strategy ─▶ Technique
//
// For each technique:
//   - Find every detection strategy that detects it (technique.strategyIds).
//   - For each strategy, score every analytic it references; an analytic is
//     "lit" iff every required log source has score > 0. Analytic score is
//     the aggregator over those scores (default `min`; UI lets the user
//     pick `avg`).
//   - A strategy is "lit" iff at least one of its analytics is lit. Strategy
//     score = max of its lit analytic scores.
//   - Technique weightedScore = max strategy score among lit strategies.
//     Coverage ratio = lit strategies / total strategies.
//
// Score aggregation default = `min` (chain-is-only-as-strong-as-the-weakest-
// log) is semantically correct but punishing; the UI exposes an `avg` toggle
// for users who prefer to grade leniently.
//
// Each row exposes V2-native fields plus legacy aliases
// (totalDetectingComponents, coveredComponents, coveringComponents,
// maxScore) so navigator.js, threats.js, and existing UI keep working.
// Refactor-merge chunk 5: inclusive analytic/strategy state for the
// merged Log Inventory panel.
//
//   fullyMet  = every required log source has score > 0
//   partial   = ≥1 required log source has score > 0, but not all
//   active    = strategy contains ≥1 fullyMet analytic
//   partialSt = strategy has 0 fullyMet but ≥1 partial analytics
//
// Active strategies + (when inclusive=true) partial strategies feed
// the Detected-TTPs chip list. Used by the merged inventory panel
// for the inclusive analytic/strategy display.
export function inclusiveAnalyticStrategyState(attack, logSourceScores) {
  const analytic = new Map(); // analyticId -> { state: "fullyMet"|"partial"|"none", litCount, totalCount }
  for (const an of attack.analytics || []) {
    const total = (an.logSourceIds || []).length;
    const lit = (an.logSourceIds || []).filter(id => (logSourceScores.get(id)?.score || 0) > 0).length;
    let state;
    if (total === 0) state = "none";
    else if (lit === total) state = "fullyMet";
    else if (lit > 0) state = "partial";
    else state = "none";
    analytic.set(an.id, { state, litCount: lit, totalCount: total, name: an.name });
  }
  const strategy = new Map(); // strategyId -> { state, fullyMetIds, partialIds }
  for (const st of attack.detectionStrategies || []) {
    const ids = st.analyticIds || [];
    const fullyMet = ids.filter(id => analytic.get(id)?.state === "fullyMet");
    const partial  = ids.filter(id => analytic.get(id)?.state === "partial");
    let state;
    if (fullyMet.length > 0) state = "active";
    else if (partial.length > 0) state = "partial";
    else state = "none";
    strategy.set(st.id, { state, fullyMet, partial });
  }
  return { analytic, strategy };
}

// Detected TTPs as a Set of technique STIX ids. When inclusive=true,
// strategies whose state === "partial" also contribute their
// techniqueIds.
export function detectedTechniquesFromState(attack, state, { inclusive = false } = {}) {
  const out = new Set();
  for (const st of attack.detectionStrategies || []) {
    const stState = state.strategy.get(st.id);
    if (!stState) continue;
    if (stState.state === "active" || (inclusive && stState.state === "partial")) {
      for (const tid of (st.techniqueIds || [])) out.add(tid);
    }
  }
  return out;
}

export function computeCoverage(attack, logSourceScores, { analyticAggregation = "min", riskAccepted = null, disabledStrategies = null, manuallyCoveredStrategies = null, partialStrategiesLit = false, mitigationScores = null } = {}) {
  const isRisk = (kind, key) => !!(riskAccepted && riskAccepted[kind] && riskAccepted[kind][key]);
  const isStratDisabled = (sid) => !!(disabledStrategies && disabledStrategies[sid]);
  const isStratManual = (sid) => !!(manuallyCoveredStrategies && manuallyCoveredStrategies[sid]);
  const MANUAL_SCORE = 5; // user-claimed coverage = full credit
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

  // 2. Score each detection strategy. Disabled strategies (chunk 14)
  // are kept in the map with lit=false so the UI can still render
  // them as "parked"; they contribute 0 to coverage. Manually-covered
  // strategies (chunk 17) light up at MANUAL_SCORE regardless of the
  // chain — the user has asserted they have a detection in place even
  // if the bundle's analytic spec wouldn't validate it. partialLit
  // (refactor-merge chunk 5) treats a strategy whose analytics have
  // ≥1 partially-met log source as lit at the inclusive sentinel
  // score so the Coverage tab honours the merged tab's "Ignore
  // incomplete" toggle.
  const PARTIAL_LIT_SCORE = 1;
  const strategyScores = new Map(); // strategyId -> { lit, score, name, attackId, analytics: [...], disabled, manual }
  for (const st of attack.detectionStrategies || []) {
    const disabled = isStratDisabled(st.id);
    const manual = !disabled && isStratManual(st.id);
    const ans = (st.analyticIds || []).map(id => {
      const a = analyticScores.get(id);
      return a ? { id, ...a } : null;
    }).filter(Boolean);
    const litAns = ans.filter(a => a.lit);
    // chunk 5: a partial analytic has ≥1 of its required log sources
    // scored but not all (lit === false but ≥1 score > 0).
    const partialAns = ans.filter(a => !a.lit && (a.logSources || []).some(l => l.score > 0));
    const chainLit = !disabled && litAns.length > 0;
    const partialChain = !disabled && !chainLit && partialStrategiesLit && partialAns.length > 0;
    const lit = chainLit || manual || partialChain;
    let score = 0;
    if (chainLit && manual) score = Math.max(MANUAL_SCORE, ...litAns.map(a => a.score));
    else if (chainLit) score = Math.max(...litAns.map(a => a.score));
    else if (manual) score = MANUAL_SCORE;
    else if (partialChain) score = PARTIAL_LIT_SCORE;
    strategyScores.set(st.id, { lit, score, name: st.name, attackId: st.attackId, analytics: ans, disabled, manual, partial: partialChain });
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

    // chunk 10: classify into a single status. Priority:
    //   risk_accepted > lit > partial > uncovered > undetectable.
    // Risk-accepted is a separate bucket from "uncovered" so users see
    // explicit acknowledgement rather than red.
    const riskAcceptedFlag = isRisk("techniques", tech.attackId);
    let status;
    if (totalStrategies === 0) status = "undetectable";
    else if (riskAcceptedFlag) status = "risk_accepted";
    else if (litStrategies === totalStrategies) status = "lit";
    else if (litStrategies > 0) status = "partial";
    else status = "uncovered";

    // Preventive-control (ATT&CK mitigation) dimension — additive only.
    // Purely informational: it does not feed into `status`/`ratio`/
    // `weightedScore` above, which stay strictly about detective
    // (Log Source -> Analytic -> Strategy) coverage. `combinedScore` is
    // a "defense in depth" view — a technique you can't detect but have
    // strongly mitigated isn't undefended, and vice versa.
    const mitigationIds = tech.mitigationIds || [];
    // mitigationIds are STIX ids (course-of-action--...); mitigation_scores
    // is keyed by the ATT&CK attackId (M1032) shown in the Mitigations tab.
    const scoredMitigations = mitigationIds
      .map(id => attack.mitigationById?.get(id)?.attackId)
      .map(attackId => mitigationScores?.get(attackId)?.score || 0)
      .filter(s => s > 0);
    const mitigationScore = scoredMitigations.length ? Math.max(...scoredMitigations) : 0;
    const mitigationCoverageRatio = mitigationIds.length ? scoredMitigations.length / mitigationIds.length : 0;
    const combinedScore = Math.max(weightedScore, mitigationScore);

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
      riskAccepted: riskAcceptedFlag,
      status,
      // Preventive-control dimension (additive; see comment above).
      mitigationIds,
      mitigationScore,
      mitigationCoverageRatio,
      combinedScore,
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
  const riskAcceptedRows = rows.filter(r => r.riskAccepted);
  // Covered/fully/partial counts exclude risk-accepted so the buckets
  // are mutually exclusive.
  const covered = detectable.filter(r => r.coveredComponents > 0 && !r.riskAccepted);
  const fully = detectable.filter(r => r.ratio >= 1 && !r.riskAccepted);
  const partial = detectable.filter(r => r.ratio > 0 && r.ratio < 1 && !r.riskAccepted);
  // Preventive-control summary (additive; doesn't affect the buckets above).
  const hasMitigations = rows.filter(r => r.mitigationIds.length > 0);
  const mitigated = hasMitigations.filter(r => r.mitigationScore > 0);
  const neitherDetectedNorMitigated = rows.filter(r => r.weightedScore === 0 && r.mitigationScore === 0 && !r.riskAccepted);

  return {
    rows,
    summary: {
      total: rows.length,
      detectable: detectable.length,
      covered: covered.length,
      fully: fully.length,
      partial: partial.length,
      riskAccepted: riskAcceptedRows.length,
      avgScore: covered.length ? covered.reduce((s, r) => s + r.weightedScore, 0) / covered.length : 0,
      // Preventive-control (additive) stats.
      hasMitigations: hasMitigations.length,
      mitigated: mitigated.length,
      avgMitigationScore: mitigated.length ? mitigated.reduce((s, r) => s + r.mitigationScore, 0) / mitigated.length : 0,
      undefended: neitherDetectedNorMitigated.length,
    },
    engine: "v2",
  };
}
