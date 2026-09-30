/* Read-only hotspot triage: cross-check exposure with currently loaded inventory. */
(function(root) {
'use strict';
function integer(v) { const n=Number(v); return Number.isFinite(n)&&n>=0?Math.trunc(n):0; }
function triage(report, agents, currentMs=Date.now()) {
  if(!report||!Array.isArray(report.items)||!report.summary||!Array.isArray(agents)) throw new Error('Dados de triagem inválidos');
  const byId=new Map(agents.filter(a=>a&&a.id).map(a=>[String(a.id),a]));
  const rows=report.items.map(item=>{
    const agent=byId.get(String(item.agent_id));
    const lastSeen=agent&&agent.last_seen?Date.parse(agent.last_seen):NaN;
    const status=!agent?'not_in_loaded_inventory':!Number.isFinite(lastSeen)||lastSeen>currentMs?'heartbeat_unknown':currentMs-lastSeen>=900000?'offline':'online';
    return {agent_id:String(item.agent_id||''),hostname:String(item.hostname||agent?.hostname||''),
      critical:integer(item.critical),high:integer(item.high),older_90d:integer(item.older_90d),
      inventory_status:status,pending_updates:agent?integer(agent.pending_updates):null,
      reboot_required:agent?Boolean(agent.reboot_required):null,can_open:Boolean(agent)};
  });
  return {rows,generated_at:report.generated_at,
    summary:{returned_endpoints:rows.length,present_in_loaded_inventory:rows.filter(r=>r.can_open).length,
      missing_from_loaded_inventory:rows.filter(r=>!r.can_open).length,
      offline:rows.filter(r=>r.inventory_status==='offline').length,
      reboot_required:rows.filter(r=>r.reboot_required===true).length,
      unmapped_findings:integer(report.summary.unmapped_open_findings?.findings),
      unmapped_critical:integer(report.summary.unmapped_open_findings?.critical),
      invalid_timestamps:integer(report.summary.invalid_timestamps)},
    caveat:'Associação exclusivamente por ID do agente; não equivale a validação de patch ou comprovação de remediação.'};
}
function escapeHtml(v) {
  return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
const labels={not_in_loaded_inventory:'Sem correspondência no inventário carregado',heartbeat_unknown:'Heartbeat desconhecido',offline:'Offline (≥15 min)',online:'Online (<15 min)'};
function render(result) {
  const s=result.summary;
  const rows=result.rows.map(r=>'<tr><td><strong>'+escapeHtml(r.hostname||r.agent_id)+'</strong><br><small>'+escapeHtml(r.agent_id)+'</small></td>'+
    '<td>'+escapeHtml(labels[r.inventory_status])+'</td><td>'+r.critical+'</td><td>'+r.high+'</td><td>'+r.older_90d+'</td>'+
    '<td>'+(r.pending_updates===null?'Não disponível':r.pending_updates)+'</td>'+
    '<td>'+(r.reboot_required===null?'Não disponível':r.reboot_required?'Sim':'Não')+'</td>'+
    '<td>'+(r.can_open?'<button type="button" class="row-action" data-agent-open="'+escapeHtml(r.agent_id)+'">Abrir endpoint</button>':
      '<span class="muted">Reconciliar inventário</span>')+'</td></tr>').join('');
  return '<div class="preflight-header"><strong>Triagem operacional · Exposure Hotspots</strong></div>'+
    '<p><small class="muted">Fotografia de '+escapeHtml(result.generated_at||'horário desconhecido')+
    ' · somente os endpoints retornados (até 100).</small></p>'+
    '<div class="campaign-stats"><span>Endpoints exibidos <strong>'+s.returned_endpoints+'</strong></span>'+
    '<span>Sem inventário carregado <strong>'+s.missing_from_loaded_inventory+'</strong></span>'+
    '<span>Offline <strong>'+s.offline+'</strong></span><span>Reboot pendente <strong>'+s.reboot_required+'</strong></span>'+
    '<span>Findings sem agente <strong>'+s.unmapped_findings+'</strong></span>'+
    '<span>Datas inválidas <strong>'+s.invalid_timestamps+'</strong></span></div>'+
    (rows?'<div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Conectividade</th>'+
      '<th>Críticas</th><th>Altas</th><th>Mais de 90d</th><th>Patches pendentes*</th><th>Reboot</th>'+
      '<th>Ação</th></tr></thead><tbody>'+rows+'</tbody></table></div>':
      '<p>Nenhum endpoint retornado. Verifique os findings não correlacionados.</p>')+
    '<p><small class="muted">*Pendências de patch são inventário independente; esta tabela não comprova uma associação finding-patch. '+
    escapeHtml(result.caveat)+'</small></p>';
}
if(typeof module!=='undefined'&&module.exports)module.exports={integer,triage,render,escapeHtml};
if(root&&root.document)root.showExposureTriage=async function(){
  const box=root.document.getElementById('observedExposureReport');
  if(!box)return;
  box.hidden=false;box.textContent='Correlacionando relatório e inventário…';
  try {
    const report=await api('/api/admin/reports/vulnerability-exposure-hotspots?limit=100');
    box.innerHTML=render(triage(report,state.agents||[]));
  } catch(error) {
    box.textContent='Falha na triagem: '+error.message;
    if(typeof toast==='function')toast('Triagem: '+error.message,'fail');
  }
};
})(typeof window!=='undefined'?window:null);
