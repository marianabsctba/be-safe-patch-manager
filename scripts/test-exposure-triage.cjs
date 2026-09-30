const test=require('node:test');
const assert=require('node:assert/strict');
const {triage,render}=require('../server/app/static/exposure-triage.js');
const report={generated_at:'2026-09-30T12:00:00Z',
  summary:{unmapped_open_findings:{findings:5,critical:2},invalid_timestamps:1},
  items:[{agent_id:'a',hostname:'<img src=x onerror=alert(1)>',critical:3,high:1,older_90d:2},
    {agent_id:'missing',hostname:'historical',critical:2,high:0}]};
test('triages only by exact agent ID, not hostname',()=>{
  const result=triage(report,[{id:'a',last_seen:'2026-09-30T10:00:00Z',pending_updates:8,reboot_required:true},
    {id:'unrelated',hostname:'historical'}],Date.parse('2026-09-30T12:00:00Z'));
  assert.equal(result.summary.present_in_loaded_inventory,1);
  assert.equal(result.summary.missing_from_loaded_inventory,1);
  assert.equal(result.summary.offline,1);
  assert.equal(result.summary.reboot_required,1);
  assert.equal(result.summary.unmapped_findings,5);
  assert.equal(result.rows[0].pending_updates,8);
  assert.equal(result.rows[1].pending_updates,null);
  assert.equal(result.rows[1].can_open,false);
  assert.match(result.caveat,/não equivale/);
});
test('escapes hostnames and navigation attributes',()=>{
  const html=render(triage(report,[{id:'a',last_seen:'2026-09-30T12:00:00Z'}],Date.parse('2026-09-30T12:00:00Z')));
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes('data-agent-open="a"'));
  assert.ok(!html.includes('data-agent-open="missing"'));
});
test('keeps unmapped findings without inventing assets',()=>{
  const result=triage({...report,items:[]},[]);
  assert.equal(result.summary.unmapped_findings,5);
  assert.match(render(result),/Nenhum endpoint retornado/);
});
test('rejects malformed report',()=>assert.throws(()=>triage({},[]),/inválidos/));
