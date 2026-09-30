/* Exposure-to-remediation bridge: explicit finding-level linkage, never patch inference. */
(function (root) {
  'use strict';
  const MAX_ENDPOINTS = 100;
  const MAX_FINDINGS = 500;
  function escapeHtml(v) {
    return String(v ?? '').replace(/[&<>"']/g, c => ({
      '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;',
    }[c]));
  }
  function text(value, max = 160) { return String(value ?? '').slice(0, max); }
  function plan(hotspots, queue, maxFindings = MAX_FINDINGS) {
    if (!hotspots || !Array.isArray(hotspots.items) || !queue || !Array.isArray(queue.items) ||
      !Number.isSafeInteger(maxFindings) || maxFindings < 1 || maxFindings > MAX_FINDINGS) {
      throw new Error('Relatórios inválidos para planejamento');
    }
    const targets = hotspots.items.slice(0, MAX_ENDPOINTS);
    const targetIds = new Set(targets.map(item => String(item.agent_id || '')).filter(Boolean));
    const eligible = [];
    const orphaned = { missing_agent: 0, agent_not_in_top: 0, missing_patch_reference: 0 };
    let matchingTotal = 0;
    for (const finding of queue.items) {
      if (!finding || !finding.id) continue;
      const id = String(finding.agent_id || '');
      const recommendation = finding.recommendation || {};
      const refs = Array.isArray(recommendation.patch_refs)
        ? [...new Set(recommendation.patch_refs.map(v => String(v || '').trim()).filter(Boolean))].slice(0, 25)
        : [];
      if (!id) { orphaned.missing_agent++; continue; }
      if (!targetIds.has(id)) { orphaned.agent_not_in_top++; continue; }
      matchingTotal++;
      if (!refs.length) orphaned.missing_patch_reference++;
      eligible.push({
        id: text(finding.id, 80), agent_id: id, cve: text(finding.cve, 80),
        severity: text(finding.severity, 32), action: text(recommendation.action || 'unknown', 64),
        patch_refs: refs.map(v => text(v, 255)), has_explicit_refs: refs.length > 0,
        eligible_for_campaign: recommendation.eligible_for_campaign === true,
      });
    }
    // Preserve the server's existing remediation-queue ordering; do not recompute risk.
    const selected = eligible.slice(0, maxFindings);
    const mapped = new Map();
    for (const row of selected) {
      const aggregate = mapped.get(row.agent_id) || { total: 0, with_refs: 0, without_refs: 0, campaign_candidates: 0 };
      aggregate.total++;
      if (row.has_explicit_refs) aggregate.with_refs++; else aggregate.without_refs++;
      if (row.has_explicit_refs && row.eligible_for_campaign) aggregate.campaign_candidates++;
      mapped.set(row.agent_id, aggregate);
    }
    return {
      generated_at: hotspots.generated_at,
      queue_generated_at: queue.generated_at,
      rows: targets.map(item => ({
        agent_id: String(item.agent_id || ''), hostname: text(item.hostname, 255),
        critical: Number(item.critical) || 0, high: Number(item.high) || 0,
        ...({ total: 0, with_refs: 0, without_refs: 0, campaign_candidates: 0 }),
        ...(mapped.get(String(item.agent_id || '')) || {}),
      })),
      findings: selected,
      summary: {
        hotspots_returned: targets.length, queue_findings_total: queue.items.length,
        matched_queue_findings: matchingTotal, findings_displayed: selected.length,
        truncated_findings: Math.max(0, eligible.length - selected.length),
        missing_agent: orphaned.missing_agent, outside_hotspot_sample: orphaned.agent_not_in_top,
        missing_patch_reference: orphaned.missing_patch_reference,
        hotspots_truncated: hotspots.items.length > MAX_ENDPOINTS,
      },
      caveats: [
        'Referências são provenientes da fila de remediação; não demonstram aplicabilidade confirmada.',
        'Candidatos dependem de pré-flight, aprovações, freeze e verificações no agente.',
        'As linhas são uma amostra de até 100 hotspots e 500 findings; nenhuma campanha foi criada.',
      ],
    };
  }
  function render(result) {
    const s = result.summary;
    const rows = result.rows.map(item => '<tr><td><strong>' + escapeHtml(item.hostname || item.agent_id) +
      '</strong><br><small>' + escapeHtml(item.agent_id) + '</small></td><td>' + item.critical +
      '</td><td>' + item.high + '</td><td>' + item.total + '</td><td>' + item.with_refs +
      '</td><td>' + item.without_refs + '</td><td>' + item.campaign_candidates + '</td></tr>').join('');
    const findings = result.findings.map(f => '<tr><td>' + escapeHtml(f.id) +
      '</td><td>' + escapeHtml(f.agent_id) + '</td><td>' + escapeHtml(f.cve || 'Sem CVE') +
      '</td><td>' + escapeHtml(f.action) + '</td><td>' +
      (f.patch_refs.length ? f.patch_refs.map(escapeHtml).join(', ') : 'Sem referência') +
      '</td></tr>').join('');
    return '<div class="preflight-header"><strong>Planejamento de remediação · somente leitura</strong></div>' +
      '<p><small class="muted">Exposição: ' + escapeHtml(result.generated_at) +
      ' · fila: ' + escapeHtml(result.queue_generated_at) + '</small></p>' +
      '<div class="campaign-stats"><span>Hotspots <strong>' + s.hotspots_returned +
      '</strong></span><span>Findings correlacionados <strong>' + s.matched_queue_findings +
      '</strong></span><span>Exibidos <strong>' + s.findings_displayed +
      '</strong></span><span>Fora da amostra <strong>' + s.outside_hotspot_sample +
      '</strong></span><span>Sem agente <strong>' + s.missing_agent +
      '</strong></span><span>Sem ref. de patch <strong>' + s.missing_patch_reference +
      '</strong></span></div>' +
      (s.truncated_findings ? '<p>Limite de exibição: ' + s.truncated_findings +
       ' finding(s) correlacionado(s) omitido(s) nesta amostra.</p>' : '') +
      '<h3>Plano por endpoint</h3>' +
      (rows ? '<div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Críticos</th><th>Altos</th>' +
      '<th>Findings exibidos</th><th>Com referência</th><th>Sem referência</th><th>Candidatos*</th></tr></thead><tbody>' +
      rows + '</tbody></table></div>' : '<p>Nenhum hotspot disponível.</p>') +
      '<h3>Referências registradas por finding</h3>' +
      (findings ? '<div class="table-wrap"><table><thead><tr><th>Finding ID</th><th>Agent ID</th>' +
      '<th>CVE</th><th>Ação da fila</th><th>Referências</th></tr></thead><tbody>' + findings +
      '</tbody></table></div>' : '<p>Nenhum finding correlacionado na amostra.</p>') +
      '<p><small class="muted">*Candidato = indicação da fila + referência explícita; não é autorização de instalação. ' +
      result.caveats.map(escapeHtml).join(' ') + '</small></p>';
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { plan, render, escapeHtml };
  if (root && root.document) {
    root.showExposureRemediationPlan = async function () {
      const box = root.document.getElementById('observedExposureReport');
      if (!box) return;
      box.hidden = false;
      box.textContent = 'Preparando amostra de remediação…';
      try {
        const hotspots = await api('/api/admin/reports/vulnerability-exposure-hotspots?limit=100');
        const queue = state.remediationQueue;
        if (!queue || !Array.isArray(queue.items)) throw new Error('Atualize o console para carregar a fila');
        box.innerHTML = render(plan(hotspots, queue));
      } catch (error) {
        box.textContent = 'Falha ao preparar planejamento: ' + error.message;
        if (typeof toast === 'function') toast('Planejamento: ' + error.message, 'fail');
      }
    };
  }
})(typeof window !== 'undefined' ? window : null);
