const assert = require('node:assert/strict');
const test = require('node:test');
const { safeCell, createCsv, exportReport } = require('../server/app/static/exposure-hotspots-export.js');

test('neutralizes spreadsheet formulas including whitespace bypasses', () => {
  for (const value of ['=SUM(1,2)', '+cmd', '-4+5', '@SUM(1,2)', '  =1+1', '\t=1+1', '\r-2']) {
    assert.ok(safeCell(value).startsWith('"\''), value);
  }
  assert.equal(safeCell('ordinary,"quoted"'), '"ordinary,""quoted"""');
});
test('exports ranked server data with summary and safe hostname', () => {
  const data = {
    generated_at: '2026-09-30T10:00:00+00:00',
    summary: { mapped_assets_with_open_findings: 4, returned_assets: 1,
      unmapped_open_findings: { findings: 2, critical: 1, high: 1 }, invalid_timestamps: 3 },
    items: [{ agent_id: 'agent-1', hostname: '=evil', findings: 5, critical: 2,
      high: 1, older_30d: 3, older_90d: 1, observed_finding_hours: 42.75 }],
  };
  const csv = createCsv(data);
  assert.ok(csv.startsWith('\uFEFFrecord_type,'));
  assert.ok(csv.includes('"\'=evil"'));
  assert.ok(csv.includes('"42.75"'));
  assert.ok(csv.includes('"2","1","1","3","1"'));
  assert.equal(csv.trim().split('\r\n').length, 2);
});
test('retains unmapped summary even without ranked endpoints', () => {
  const csv = createCsv({ generated_at: '2026-09-30T00:00:00Z',
    summary: { unmapped_open_findings: { findings: 7 }, returned_assets: 0 }, items: [] });
  assert.ok(csv.includes('"summary"'));
  assert.ok(csv.includes('"7"'));
});
test('rejects malformed response', () => {
  assert.throws(() => createCsv({ items: [] }), /inválida/);
});
test('uses authenticated report API, creates download, revokes URL', async () => {
  let requested, clicked = false, revoked = false;
  const anchor = { click() { clicked = true; }, remove() {}, hidden: false };
  const env = {
    Blob,
    URL: { createObjectURL() { return 'blob:test'; }, revokeObjectURL(url) {
      assert.equal(url, 'blob:test'); revoked = true;
    } },
    document: { createElement() { return anchor; }, body: { appendChild() {} } },
    setTimeout(fn) { fn(); },
  };
  await exportReport(async url => {
    requested = url;
    return { generated_at: '2026-09-30T10:00:00Z', summary: {}, items: [] };
  }, env);
  assert.match(requested, /limit=100/);
  assert.equal(anchor.download, 'be-safe-exposure-hotspots-20260930100000.csv');
  assert.ok(clicked && revoked);
});
