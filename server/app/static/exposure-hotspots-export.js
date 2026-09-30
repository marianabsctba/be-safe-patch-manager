/* Be Safe Patch Manager — bounded exposure-hotspot CSV export.
 * Exports exactly the server's ranked sample, not the full vulnerability estate.
 * Spreadsheet-formula injection is neutralized for all externally sourced strings.
 */
(function (root) {
  'use strict';
  const COLUMNS = [
    'record_type', 'generated_at_utc', 'agent_id', 'hostname',
    'open_findings', 'critical', 'high', 'older_30d', 'older_90d',
    'observed_finding_hours', 'mapped_assets_with_open_findings',
    'unmapped_open_findings', 'unmapped_critical', 'unmapped_high',
    'invalid_timestamps', 'returned_assets',
  ];
  function safeCell(value) {
    let text = String(value === null || value === undefined ? '' : value);
    // Neutralize formula prefixes, including whitespace/control-character bypasses.
    if (/^[\s\u0000-\u001f]*[=+@-]/u.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  }
  function createCsv(report) {
    if (!report || !Array.isArray(report.items) || !report.summary ||
        typeof report.generated_at !== 'string') {
      throw new Error('Resposta inválida do relatório de exposição');
    }
    const summary = report.summary;
    const unmapped = summary.unmapped_open_findings || {};
    const shared = {
      generated_at_utc: report.generated_at,
      mapped_assets_with_open_findings: summary.mapped_assets_with_open_findings || 0,
      unmapped_open_findings: unmapped.findings || 0,
      unmapped_critical: unmapped.critical || 0,
      unmapped_high: unmapped.high || 0,
      invalid_timestamps: summary.invalid_timestamps || 0,
      returned_assets: summary.returned_assets || 0,
    };
    const items = report.items.length ? report.items.map(item => ({
      ...shared, record_type: 'endpoint',
      agent_id: item.agent_id, hostname: item.hostname || '',
      open_findings: item.findings || 0, critical: item.critical || 0,
      high: item.high || 0, older_30d: item.older_30d || 0,
      older_90d: item.older_90d || 0,
      observed_finding_hours: item.observed_finding_hours || 0,
    })) : [{ ...shared, record_type: 'summary' }];
    return '\uFEFF' + COLUMNS.join(',') + '\r\n' +
      items.map(item => COLUMNS.map(column => safeCell(item[column])).join(',')).join('\r\n') +
      '\r\n';
  }
  async function exportReport(apiCall, environment) {
    const report = await apiCall('/api/admin/reports/vulnerability-exposure-hotspots?limit=100');
    const csv = createCsv(report);
    const doc = environment.document;
    const url = environment.URL.createObjectURL(new environment.Blob(
      [csv], { type: 'text/csv;charset=utf-8' }
    ));
    const anchor = doc.createElement('a');
    anchor.href = url;
    const generated = report.generated_at.replace(/[^0-9]/g, '').slice(0, 14);
    anchor.download = 'be-safe-exposure-hotspots-' + generated + '.csv';
    anchor.hidden = true;
    doc.body.appendChild(anchor);
    try { anchor.click(); } finally {
      anchor.remove();
      environment.setTimeout(() => environment.URL.revokeObjectURL(url), 1000);
    }
    return report.summary;
  }
  const exported = { COLUMNS, safeCell, createCsv, exportReport };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  if (root && root.document) {
    root.exportExposureHotspotsCsv = async function () {
      try {
        await exportReport(api, root);
        if (typeof toast === 'function') toast('CSV dos hotspots exportado (até 100 endpoints).');
      } catch (error) {
        if (typeof toast === 'function') toast('Exportação: ' + error.message, 'fail');
      }
    };
  }
})(typeof window !== 'undefined' ? window : null);
