const assert = require('node:assert/strict');
const test = require('node:test');
const { plan, render } = require('../server/app/static/exposure-remediation-plan.js');
const hotspots = { generated_at: '2026-09-30T12:00:00Z', items: [
  { agent_id: 'agent-a', hostname: '<script>alert(1)</script>', critical: 2, high: 1 },
  { agent_id: 'agent-b', hostname: 'Second', critical: 0, high: 1 },
]};
const queue = { generated_at: '2026-09-30T12:01:00Z', items: [
  { id:'f1',agent_id:'agent-a',cve:'CVE-2026-1000',recommendation:{
    action:'schedule_patch',patch_refs:['KB123', 'KB123'],eligible_for_campaign:true }},
  { id:'f2',agent_id:'agent-a',recommendation:{action:'scan_or_manual_triage',patch_refs:[],
    eligible_for_campaign:true}},
  { id:'f3',agent_id:null,recommendation:{patch_refs:['KB123']}},
  { id:'f4',agent_id:'other',recommendation:{patch_refs:['KB777']}},
]};
test('correlates by exact ID, preserves queue order and explicit refs only', () => {
  const p = plan(hotspots, queue);
  assert.equal(p.summary.matched_queue_findings,2);
  assert.equal(p.summary.missing_agent,1);
  assert.equal(p.summary.outside_hotspot_sample,1);
  assert.equal(p.summary.missing_patch_reference,1);
  assert.deepEqual(p.findings[0].patch_refs,['KB123']);
  assert.equal(p.rows[0].campaign_candidates,1);
  assert.equal(p.rows[0].total,2);
  assert.equal(p.rows[1].total,0);
});
test('sample cap does not hide truncation or inflate totals', () => {
  const p = plan(hotspots,queue,1);
  assert.equal(p.summary.matched_queue_findings,2);
  assert.equal(p.summary.truncated_findings,1);
  assert.equal(p.rows[0].total,1);
  assert.match(render(p),/omitido/);
});
test('escapes text from queue and inventory', () => {
  const p = plan(hotspots,queue);
  assert.ok(!render(p).includes('<script>'));
  assert.match(render(p),/&lt;script&gt;/);
});
test('rejects malformed data and invalid bounds', () => {
  assert.throws(() => plan(null,queue),/inválidos/);
  assert.throws(() => plan(hotspots,queue,501),/inválidos/);
});
