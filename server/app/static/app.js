const $ = (s) => document.querySelector(s);
const tokenInput = $('#token');
let adminToken = '';

function headers(){ return {'Content-Type':'application/json','X-Admin-Token':adminToken}; }
async function api(path, options={}){
  const r = await fetch(path,{...options,headers:{...headers(),...(options.headers||{})}});
  if(!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
function esc(v=''){ return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function badge(text, cls=''){ return `<span class="badge ${cls}">${esc(text)}</span>`; }
function when(v){ if(!v) return '-'; try{return new Date(v).toLocaleString('pt-BR')}catch{return v} }

async function load(){
  if(!adminToken) return;
  try{
    const [summary,agents,campaigns,jobs] = await Promise.all([
      api('/api/admin/summary'), api('/api/admin/agents'), api('/api/admin/campaigns'), api('/api/admin/jobs')
    ]);
    renderSummary(summary); renderAgents(agents); renderCampaigns(campaigns); renderJobs(jobs);
  }catch(e){
    if(String(e.message).startsWith('401 ')){
      adminToken='';
      $('#saveToken').textContent='Entrar';
    }
    alert(`Falha: ${e.message}`);
  }
}
function renderSummary(s){
  const entries=[['Endpoints',s.agents],['Online',s.online],['Compliance',`${s.compliance_percent}%`],['Updates pendentes',s.pending_updates],['Críticos',s.critical_updates],['Reboot pendente',s.reboot_required],['Falhas',s.failed_jobs]];
  $('#summary').innerHTML=entries.map(([k,v])=>`<article class="card"><span>${esc(k)}</span><strong>${esc(v)}</strong></article>`).join('');
}
function renderAgents(items){
  $('#agents').innerHTML=items.map(a=>`<tr>
    <td><strong>${esc(a.hostname)}</strong><br><small class="muted">${esc(a.ip_address||'')}</small></td>
    <td>${esc(a.os_name)} ${esc(a.os_version)}</td>
    <td>${(a.tags||[]).map(t=>badge(t,'info')).join('')||'-'}</td>
    <td>${when(a.last_seen)}</td>
    <td>${a.pending_updates}</td><td>${a.critical_updates}</td>
    <td>${a.reboot_required?badge('SIM','warn'):badge('não','ok')}</td>
  </tr>`).join('');
}
function renderCampaigns(items){
  $('#campaigns').innerHTML=items.map(c=>`<article class="campaign">
    <div><h3>${esc(c.name)}</h3><p>${esc(c.description||'Sem descrição')}</p>
      <p>${badge(c.status,c.status==='deployed'?'ok':'info')} ${badge(c.target_os)} ${c.target_tag?badge(c.target_tag):''} Ring ${c.ring_percent}% · Jobs ${c.jobs_total} · OK ${c.job_counts.success||0} · Falhas ${c.job_counts.failed||0}</p>
    </div>
    <div class="campaign-actions">${c.status==='draft'?`<button onclick="deploy('${c.id}')">Implantar</button>`:''}</div>
  </article>`).join('') || '<small class="muted">Nenhuma campanha.</small>';
}
function renderJobs(items){
  $('#jobs').innerHTML=items.slice(0,100).map(j=>`<tr><td>${esc(j.hostname)}</td><td>${esc(j.campaign_name)}</td><td>${esc(j.action)}</td><td>${badge(j.status,j.status==='success'?'ok':j.status==='failed'?'fail':'info')}</td><td>${esc(j.error||'')}</td></tr>`).join('');
}
window.deploy = async (id)=>{ if(!confirm('Implantar esta campanha nos endpoints selecionados?'))return; try{const r=await api(`/api/admin/campaigns/${id}/deploy`,{method:'POST'}); alert(`${r.agents_selected} endpoint(s) selecionado(s).`); load();}catch(e){alert(e.message)} };
$('#saveToken').onclick=()=>{
  const candidate=tokenInput.value.trim();
  if(!candidate){ alert('Informe o token administrativo.'); return; }
  adminToken=candidate;
  tokenInput.value='';
  $('#saveToken').textContent='Conectado';
  load();
};
$('#refresh').onclick=load;
$('#campaignForm').onsubmit=async (ev)=>{
  ev.preventDefault(); const f=new FormData(ev.target); const packs=(f.get('packages')||'').split(',').map(x=>x.trim()).filter(Boolean);
  const body={name:f.get('name'),description:f.get('description')||'',target_os:f.get('target_os'),target_tag:f.get('target_tag')||'',ring_percent:Number(f.get('ring_percent')||100),action:f.get('action'),allow_reboot:f.get('allow_reboot')==='on',not_before:f.get('not_before')?new Date(f.get('not_before')).toISOString():null,payload:{packages:packs}};
  try{await api('/api/admin/campaigns',{method:'POST',body:JSON.stringify(body)});ev.target.reset();load();}catch(e){alert(e.message)}
};
setInterval(load,30000);
