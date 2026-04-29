// Compute detection coverage for techniques given an inventory.
//
// For each technique:
//   - Determines all data components that can detect it (from STIX `detects` relationships).
//   - Computes coverage ratio = covered_components / total_detecting_components (0..1; 0 if no detections defined).
//   - Computes max score across covering components (0..5).
//   - Returns a weighted score = max_score * ratio (0..5, fractional allowed).

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
