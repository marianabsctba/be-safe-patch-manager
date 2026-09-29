const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
  sessionToken: '',
  user: null,
  users: [],
  summary: null,
  agents: [],
  vulnerabilities: [],
  greenbone: null,
  threatIntel: null,
  remediationQueue: null,
  remediationHub: null,
  remediationProjects: null,
  activeThreatWatch: null,
  patchConfidence: null,
  patchCatalog: null,
  patchFeeds: null,
  freezeWindows: null,
  autoPatch: null,
  autoPatchHistory: [],
  patchBlockRules: null,
  businessContext: null,
  remediationPerformance: null,
  riskGoals: null,
  campaignTargetAgentIds: [],
  riskReduction: null,
  assetRisk: null,
  riskPolicies: [],
  agentRelease: null,
  campaigns: [],
  jobs: [],
  audit: [],
  view: 'overview',
  selectedAgentId: null,
  drawerTab: 'summary',
};

const titles = {
  overview: 'Visão geral',
  endpoints: 'Endpoints',
  vulnerabilities: 'Vulnerabilidades',
  campaigns: 'Campanhas',
  executions: 'Execuções',
  audit: 'Auditoria',
  users: 'Usuários',
};

const roleLevels = { viewer: 10, operator: 20, admin: 30 };

function roleAtLeast(role) {
  const current = state.user && state.user.role ? roleLevels[state.user.role] || 0 : 0;
  return current >= (roleLevels[role] || 999);
}

function requireRole(role, message = 'Permissão insuficiente.') {
  if (!roleAtLeast(role)) {
    toast(message, 'fail');
    return false;
  }
  return true;
}

function headers() {
  const result = { 'Content-Type': 'application/json' };
  if (state.sessionToken) result['X-Session-Token'] = state.sessionToken;
  return result;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...headers(),
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    const body = await response.text();
    const error = new Error(`${response.status} ${body}`);
    error.status = response.status;
    error.body = body;
    throw error;
  }

  return response.json();
}

function esc(value = '') {
  return String(value).replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  }[char]));
}

function badge(text, cls = '') {
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

function when(value) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString('pt-BR');
  } catch {
    return value;
  }
}

function shortWhen(value) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return value;
  }
}

function isOnline(agent) {
  if (!agent.last_seen) return false;
  const lastSeen = new Date(agent.last_seen).getTime();
  if (Number.isNaN(lastSeen)) return false;
  return (Date.now() - lastSeen) < 15 * 60 * 1000;
}

function jobClass(status) {
  if (status === 'success') return 'ok';
  if (status === 'failed' || status === 'stalled' || status === 'blocked') return 'fail';
  if (status === 'running' || status === 'claimed') return 'warn';
  return 'info';
}

function actionLabel(action) {
  if (action === 'install_updates') return 'Instalar updates';
  if (action === 'rollback_checkpoint') return 'Rollback aprovado';
  if (action === 'activate_agent_update') return 'Ativar update do agente';
  if (action === 'clear_agent_update_quarantine') return 'Liberar quarentena do agente';
  return 'Scan de updates';
}

function statusLabel(status) {
  const labels = {
    draft: 'Rascunho',
    deployed: 'Implantada',
    pending: 'Pendente',
    blocked: 'Bloqueado',
    claimed: 'Recebida',
    running: 'Executando',
    stalled: 'Travado / revisão',
    success: 'Sucesso',
    failed: 'Falha',
    skipped: 'Ignorada',
  };
  return labels[status] || status;
}

function scalar(value) {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'boolean') return value ? 'sim' : 'não';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function endpointRisk(agent) {
  const critical = Number(agent.critical_updates || 0);
  const pending = Number(agent.pending_updates || 0);
  if (critical > 0) return { label: 'Crítico', cls: 'fail' };
  if (pending > 0 || agent.reboot_required) return { label: 'Atenção', cls: 'warn' };
  return { label: 'Compliant', cls: 'ok' };
}

function selectedAgent() {
  return state.agents.find((agent) => agent.id === state.selectedAgentId) || null;
}

function toast(message, type = 'ok') {
  const el = $('#toast');
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    el.className = 'toast';
  }, 3200);
}

function showLogin(message = '') {
  state.sessionToken = '';
  state.user = null;
  state.users = [];
  $('#authUser').hidden = true;
  $('#loginGate').hidden = false;
  $('#lastUpdate').textContent = 'Aguardando autenticação';
  $('#loginError').hidden = !message;
  $('#loginError').textContent = message;
  applyPermissions();
}

function hideLogin() {
  $('#loginGate').hidden = true;
  $('#loginError').hidden = true;
  $('#authUser').hidden = false;
}

function applyPermissions() {
  $('[data-min-role]').forEach((element) => {
    const allowed = roleAtLeast(element.dataset.minRole);
    element.hidden = !allowed;
  });

  const user = state.user;
  $('#authUsername').textContent = user ? user.username : '-';
  $('#authRole').textContent = user ? String(user.role || '').toUpperCase() : '-';

  if (state.view === 'users' && !roleAtLeast('admin')) {
    setView('overview');
  }

  if ($('#drawerTags')) $('#drawerTags').disabled = !roleAtLeast('operator');
}

function userRoleBadge(role) {
  return badge(String(role || '-').toUpperCase(), role === 'admin' ? 'fail' : role === 'operator' ? 'warn' : 'info');
}

function setView(view) {
  state.view = view;
  $$('.nav-item').forEach((button) => {
    button.classList.toggle('active', button.dataset.view === view);
  });

  $$('.view').forEach((panel) => {
    panel.classList.toggle('active', panel.dataset.viewPanel === view);
  });

  $('#pageTitle').textContent = titles[view] || 'Patch Manager';
}

async function load() {
  if (!state.sessionToken) return;

  $('#refresh').classList.add('spin');

  try {
    const [summary, agents, vulnerabilities, greenbone, threatIntel, remediationQueue, remediationHub, remediationProjects, activeThreatWatch, patchConfidence, patchCatalog, patchFeeds, freezeWindows, autoPatch, autoPatchHistory, patchBlockRules, businessContext, remediationPerformance, riskGoals, riskReduction, assetRisk, riskPolicies, agentRelease, campaigns, jobs, audit, users] = await Promise.all([
      api('/api/admin/summary'),
      api('/api/admin/agents'),
      api('/api/admin/vulnerabilities'),
      api('/api/admin/integrations/greenbone'),
      api('/api/admin/integrations/threat-intel'),
      api('/api/admin/reports/remediation-queue'),
      api('/api/admin/reports/remediation-hub'),
      api('/api/admin/remediation-projects'),
      api('/api/admin/reports/active-threat-watch'),
      api('/api/admin/reports/patch-confidence'),
      api('/api/admin/reports/patch-catalog'),
      api('/api/admin/patch-feeds'),
      api('/api/admin/freeze-windows'),
      api('/api/admin/reports/auto-patch-decisions'),
      api('/api/admin/auto-patch/history?limit=20'),
      api('/api/admin/patch-block-rules'),
      api('/api/admin/reports/business-context'),
      api('/api/admin/reports/remediation-performance'),
      api('/api/admin/risk-goals'),
      api('/api/admin/reports/risk-reduction-opportunities'),
      api('/api/admin/reports/asset-risk'),
      api('/api/admin/risk-policies'),
      api('/api/admin/agent-release'),
      api('/api/admin/campaigns'),
      api('/api/admin/jobs'),
      api('/api/admin/audit'),
      roleAtLeast('admin') ? api('/api/admin/users') : Promise.resolve([]),
    ]);

    state.summary = summary;
    state.agents = agents;
    state.vulnerabilities = vulnerabilities;
    state.greenbone = greenbone;
    state.threatIntel = threatIntel;
    state.remediationQueue = remediationQueue;
    state.remediationHub = remediationHub;
    state.remediationProjects = remediationProjects;
    state.activeThreatWatch = activeThreatWatch;
    state.patchConfidence = patchConfidence;
    state.patchCatalog = patchCatalog;
    state.patchFeeds = patchFeeds;
    state.freezeWindows = freezeWindows;
    state.autoPatch = autoPatch;
    state.autoPatchHistory = autoPatchHistory;
    state.patchBlockRules = patchBlockRules;
    state.businessContext = businessContext;
    state.remediationPerformance = remediationPerformance;
    state.riskGoals = riskGoals;
    state.riskReduction = riskReduction;
    state.assetRisk = assetRisk;
    state.riskPolicies = riskPolicies;
    state.agentRelease = agentRelease;
    state.campaigns = campaigns;
    state.jobs = jobs;
    state.audit = audit;
    state.users = users;

    renderAll();
    applyPermissions();

    $('#lastUpdate').textContent = `Atualizado ${new Date().toLocaleTimeString('pt-BR', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })}`;
  } catch (error) {
    if (error.status === 401) {
      showLogin('Sua sessão expirou ou não é mais válida.');
      toast('Sessão encerrada.', 'fail');
    } else {
      toast(`Falha ao carregar: ${error.message}`, 'fail');
    }
  } finally {
    $('#refresh').classList.remove('spin');
  }
}

function renderAll() {
  renderSummary(state.summary || {});
  renderCompliance(state.summary || {});
  renderAgents();
  renderRiskEndpoints();
  renderGreenboneIntegration();
  renderThreatIntelIntegration();
  renderRemediationQueue();
  renderRemediationHub();
  renderRemediationProjects();
  renderActiveThreatWatch();
  renderPatchConfidence();
  renderPatchCatalog();
  renderPatchFeeds();
  renderAutoPatch();
  renderFreezeWindows();
  renderBusinessContext();
  renderRemediationPerformance();
  renderRiskGoals();
  renderRiskProgramOverview();
  renderRiskReductionOpportunities();
  renderAssetRisk();
  renderVulnerabilities();
  renderCampaigns();
  renderPatchBlockRules();
  renderOverviewCampaigns();
  renderAgentRolloutForm();
  renderJobs();
  renderAudit();
  renderUsers();
  if (state.selectedAgentId) renderAgentDrawer();
}

function renderSummary(summary) {
  const release = state.agentRelease || {};
  const threatSummary = (state.activeThreatWatch || {}).summary || {};
  const hubSummary = (state.remediationHub || {}).summary || {};
  const confidenceSummary = (state.patchConfidence || {}).summary || {};
  const riskSummary = (state.assetRisk || {}).summary || {};
  const goalSummary = (state.riskGoals || {}).summary || {};
  const ownerCoverage = riskSummary.assets
    ? Math.round((Number(riskSummary.assets_with_owner || 0) / Number(riskSummary.assets)) * 100)
    : 0;
  const entries = [
    { label: 'Endpoints', value: summary.agents || 0, hint: `${summary.online || 0} online`, cls: 'neutral' },
    { label: 'Compliance', value: `${summary.compliance_percent || 0}%`, hint: `${summary.compliant || 0} compliant`, cls: 'accent' },
    { label: 'Updates pendentes', value: summary.pending_updates || 0, hint: 'itens detectados', cls: summary.pending_updates ? 'warn' : 'ok' },
    { label: 'Críticos', value: summary.critical_updates || 0, hint: 'prioridade alta', cls: summary.critical_updates ? 'danger' : 'ok' },
    { label: 'Reboot pendente', value: summary.reboot_required || 0, hint: 'endpoints', cls: summary.reboot_required ? 'warn' : 'ok' },
    { label: 'Falhas', value: summary.failed_jobs || 0, hint: 'jobs acumulados', cls: summary.failed_jobs ? 'danger' : 'ok' },
    { label: 'SLA vencido', value: summary.sla_breached_vulnerabilities || 0, hint: 'vulnerabilidades abertas', cls: summary.sla_breached_vulnerabilities ? 'danger' : 'ok' },
    { label: 'SLA próximo', value: summary.sla_due_soon_vulnerabilities || 0, hint: 'vence em até 24h', cls: summary.sla_due_soon_vulnerabilities ? 'warn' : 'ok' },
    { label: 'Exceções SLA', value: summary.sla_exception_vulnerabilities || 0, hint: 'aprovadas e ainda válidas', cls: summary.sla_exception_vulnerabilities ? 'accent' : 'ok' },
    { label: 'Risco urgente', value: summary.urgent_risk_vulnerabilities || 0, hint: 'priorização contextual', cls: summary.urgent_risk_vulnerabilities ? 'danger' : 'ok' },
    { label: 'Prontas p/ remediação', value: summary.remediation_ready_vulnerabilities || 0, hint: 'campanha possível', cls: summary.remediation_ready_vulnerabilities ? 'accent' : 'ok' },
    { label: 'Ativos risco crítico', value: summary.critical_risk_assets || 0, hint: 'score 850–1000', cls: summary.critical_risk_assets ? 'danger' : 'ok' },
    { label: 'Risco médio ativos', value: summary.average_asset_risk || 0, hint: 'escala 0–1000', cls: 'neutral' },
    { label: 'Acima do apetite', value: summary.assets_above_risk_appetite || 0, hint: 'policy efetiva / global', cls: summary.assets_above_risk_appetite ? 'danger' : 'ok' },
    { label: 'Goals em risco', value: goalSummary.at_risk || 0, hint: 'fora do pace esperado', cls: goalSummary.at_risk ? 'warn' : 'ok' },
    { label: 'Goals vencidos', value: goalSummary.overdue || 0, hint: 'prazo excedido', cls: goalSummary.overdue ? 'danger' : 'ok' },
    { label: 'Risco aceito', value: summary.assets_risk_accepted || 0, hint: 'aceites ativos', cls: summary.assets_risk_accepted ? 'accent' : 'ok' },
    { label: 'Em tratamento', value: summary.assets_risk_in_treatment || 0, hint: 'planos ativos acima do appetite', cls: summary.assets_risk_in_treatment ? 'warn' : 'ok' },
    { label: 'Tratamento vencido', value: summary.assets_risk_treatment_overdue || 0, hint: 'prazo de treatment excedido', cls: summary.assets_risk_treatment_overdue ? 'danger' : 'ok' },
    { label: 'Risco sem ação', value: summary.assets_risk_untreated || 0, hint: 'acima do appetite sem aceite/plano', cls: summary.assets_risk_untreated ? 'danger' : 'ok' },
    { label: 'Threat Watch', value: threatSummary.cves || 0, hint: (threatSummary.kev || 0) + ' KEV · ' + (threatSummary.ransomware || 0) + ' ransomware', cls: threatSummary.cves ? 'danger' : 'ok' },
    { label: 'Remediation groups', value: hubSummary.remediation_groups || 0, hint: (hubSummary.assets_covered || 0) + ' ativos cobertos', cls: hubSummary.remediation_groups ? 'accent' : 'ok' },
    { label: 'Patch confidence baixa', value: confidenceSummary.low_confidence || 0, hint: (confidenceSummary.insufficient_data || 0) + ' sem amostra suficiente', cls: confidenceSummary.low_confidence ? 'danger' : 'ok' },
    { label: 'Owner coverage', value: ownerCoverage + '%', hint: (riskSummary.critical_high_without_owner || 0) + ' críticos/altos sem owner', cls: riskSummary.critical_high_without_owner ? 'warn' : 'ok' },
    { label: 'Agentes incompatíveis', value: Number(summary.agent_outdated || 0) + Number(summary.agent_unknown || 0) + Number(summary.agent_protocol_unsupported || 0), hint: summary.compatibility_enforced ? 'enforcement ativo' : 'somente observação', cls: (Number(summary.agent_outdated || 0) + Number(summary.agent_unknown || 0) + Number(summary.agent_protocol_unsupported || 0)) ? 'danger' : 'ok' },
    { label: 'Jobs bloqueados', value: summary.blocked_jobs || 0, hint: 'aguardando upgrade do agente', cls: summary.blocked_jobs ? 'danger' : 'ok' },
    { label: 'Update staged', value: summary.agent_update_staged || 0, hint: 'assinado e aguardando ativação', cls: summary.agent_update_staged ? 'accent' : 'ok' },
    { label: 'Erro update agente', value: summary.agent_update_errors || 0, hint: summary.agent_update_distribution_enabled ? 'distribuição habilitada' : 'distribuição desligada', cls: summary.agent_update_errors ? 'danger' : 'ok' },
    { label: 'Release assinada', value: release.ready ? 'v' + release.version : '-', hint: release.enabled ? (release.ready ? 'commit ' + String(release.source_commit || '').slice(0, 8) + ' · chave ' + String(release.signing_key_id || '').slice(0, 8) : 'release indisponível') : 'distribuição desligada', cls: release.ready ? 'ok' : release.enabled ? 'danger' : 'neutral' },
    { label: 'Aprovações update', value: summary.agent_update_approvals_pending || 0, hint: 'ativação com TTL curto', cls: summary.agent_update_approvals_pending ? 'warn' : 'ok' },
    { label: 'Aprovações expiradas', value: summary.agent_update_approvals_expired || 0, hint: 'não podem mais receber claim', cls: summary.agent_update_approvals_expired ? 'danger' : 'ok' },
    { label: 'Ativação pendente', value: summary.agent_activation_pending || 0, hint: 'aguardando restart/heartbeat', cls: summary.agent_activation_pending ? 'warn' : 'ok' },
    { label: 'Rollback do agente', value: summary.agent_activation_rollbacks || 0, hint: 'watchdog voltou à versão anterior', cls: summary.agent_activation_rollbacks ? 'danger' : 'ok' },
    { label: 'Release em quarentena', value: summary.agent_update_quarantined || 0, hint: 'exige liberação administrativa', cls: summary.agent_update_quarantined ? 'danger' : 'ok' },
  ];

  $('#summary').innerHTML = entries.map((item) => `
    <article class="card ${item.cls}">
      <span>${esc(item.label)}</span>
      <strong>${esc(item.value)}</strong>
      <small>${esc(item.hint)}</small>
    </article>
  `).join('');
}

function renderRiskProgramOverview() {
  const target = $('#riskProgramOverview');
  if (!target) return;

  const risk = (state.assetRisk || {}).summary || {};
  const threat = (state.activeThreatWatch || {}).summary || {};
  const hub = state.remediationHub || {};
  const hubSummary = hub.summary || {};
  const perf = (state.remediationPerformance || {}).summary || {};
  const business = (state.businessContext || {}).summary || {};
  const goals = (state.riskGoals || {}).summary || {};
  const topRemediation = Array.isArray(hub.items) && hub.items.length ? hub.items[0] : null;
  const topThreat = state.activeThreatWatch && Array.isArray(state.activeThreatWatch.items) && state.activeThreatWatch.items.length
    ? state.activeThreatWatch.items[0]
    : null;

  const metric = (label, value, hint) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong>' +
    (hint ? '<small class="muted">' + esc(hint) + '</small>' : '') + '</div>';

  const metrics = [
    metric('Acima do appetite', risk.above_risk_appetite || 0, (risk.untreated_above_appetite || 0) + ' sem ação'),
    metric('Threat-active assets', threat.affected_assets || 0, (threat.external_asset_exposures || 0) + ' exposições externas'),
    metric('Owner coverage', (business.owner_coverage_percent == null ? 0 : business.owner_coverage_percent) + '%', (business.critical_high_without_owner || 0) + ' critical/high sem owner'),
    metric('MTTR mediano', perf.median_mttr_hours == null ? '-' : perf.median_mttr_hours + 'h', 'finding first_seen → resolved_at'),
    metric('Evidência verificada', perf.verified_evidence_rate_percent == null ? '-' : perf.verified_evidence_rate_percent + '%', 'ciclos terminais'),
    metric('Patch success', perf.patch_job_success_rate_percent == null ? '-' : perf.patch_job_success_rate_percent + '%', 'jobs concluídos'),
    metric('Goals at risk', goals.at_risk || 0, (goals.overdue || 0) + ' overdue'),
    metric('Remediation groups', hubSummary.remediation_groups || 0, (hubSummary.findings_covered || 0) + ' findings cobertos'),
  ];

  let decision = '<div class="empty-state">Sem recomendação agregada disponível.</div>';
  if (topRemediation || topThreat) {
    decision = '<div class="risk-contributor"><span><strong>Próxima maior alavanca</strong><br><small class="muted">' +
      esc(topRemediation
        ? topRemediation.patch_ref + ' · ' + topRemediation.asset_count + ' ativos · ' + topRemediation.finding_count + ' findings'
        : 'sem grupo de patch disponível') +
      '</small></span><strong>' +
      esc(topRemediation ? '-' + topRemediation.risk_reduction : '-') +
      '</strong></div>' +
      '<div class="risk-contributor"><span><strong>Threat Watch prioritário</strong><br><small class="muted">' +
      esc(topThreat
        ? topThreat.cve + ' · ' + (topThreat.signals || []).join(' · ')
        : 'sem sinal ativo') +
      '</small></span><strong>' +
      esc(topThreat ? topThreat.asset_count + ' ativos' : '-') +
      '</strong></div>';
  }

  target.innerHTML =
    '<div class="integration-details">' + metrics.join('') + '</div>' +
    '<div class="panel-subsection">' + decision + '</div>';
}


function riskGoalPaceBadge(status) {
  if (status === 'achieved' || status === 'completed') return badge('ATINGIDA', 'ok');
  if (status === 'on_track') return badge('ON TRACK', 'ok');
  if (status === 'at_risk') return badge('AT RISK', 'warn');
  if (status === 'overdue') return badge('OVERDUE', 'fail');
  if (status === 'cancelled') return badge('CANCELADA', 'muted-badge');
  return badge(status || '-', 'info');
}

function renderRiskGoals() {
  const report = state.riskGoals || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items : [];
  const stats = $('#riskGoalStats');
  const table = $('#riskGoalTable');
  if (!stats || !table) return;

  stats.innerHTML = [
    ['Ativas', summary.active || 0],
    ['Atingidas', summary.achieved || 0],
    ['On track', summary.on_track || 0],
    ['At risk', summary.at_risk || 0],
    ['Overdue', summary.overdue || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  if (!items.length) {
    table.innerHTML = '<tr><td colspan="8"><div class="empty-state">Nenhuma meta de redução de risco criada.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((goal) =>
    '<tr>' +
      '<td><strong>' + esc(goal.name) + '</strong><br><small class="muted">' + esc(goal.goal_label || goal.goal_type) + '</small></td>' +
      '<td>' + esc(goal.scope_tag ? 'tag:' + goal.scope_tag : 'todos os ativos') + '<br><small class="muted">' + esc(goal.scoped_assets || 0) + ' ativos</small></td>' +
      '<td><strong>' + esc(goal.baseline_value) + ' → ' + esc(goal.current_value) + ' → ' + esc(goal.target_value) + '</strong></td>' +
      '<td><strong>' + esc(goal.progress_percent) + '%</strong><br><small class="muted">esperado agora ≤ ' + esc(goal.expected_value_now) + '</small></td>' +
      '<td>' + riskGoalPaceBadge(goal.pace_status) + '</td>' +
      '<td><strong>' + esc(goal.owner) + '</strong></td>' +
      '<td>' + esc(when(goal.due_at)) + '</td>' +
      '<td>' + (roleAtLeast('operator') ? '<button class="row-action" onclick="editRiskGoal(\'' + goal.id + '\')">Gerenciar</button>' : '') + '</td>' +
    '</tr>'
  ).join('');
}


function renderCompliance(summary) {
  const pct = Math.max(0, Math.min(100, Number(summary.compliance_percent || 0)));
  const total = Number(summary.agents || 0);
  const compliant = Number(summary.compliant || 0);
  const pendingEndpoints = state.agents.filter((agent) => Number(agent.pending_updates || 0) > 0).length;

  $('#complianceRing').style.setProperty('--pct', pct);
  $('#complianceValue').textContent = `${pct}%`;
  $('#complianceLabel').textContent = `${pct}%`;
  $('#healthCompliant').textContent = compliant;
  $('#healthPending').textContent = pendingEndpoints;
  $('#healthCritical').textContent = summary.critical_updates || 0;
  $('#healthReboot').textContent = summary.reboot_required || 0;

  if (!total) {
    $('#complianceLabel').textContent = 'Sem dados';
  }
}

function filteredAgents() {
  const query = ($('#endpointSearch').value || '').trim().toLowerCase();
  const filter = $('#endpointFilter').value;

  return state.agents.filter((agent) => {
    const searchable = [
      agent.hostname,
      agent.ip_address,
      agent.os_name,
      agent.os_version,
      ...(agent.tags || []),
    ].join(' ').toLowerCase();

    if (query && !searchable.includes(query)) return false;

    if (filter === 'critical' && Number(agent.critical_updates || 0) === 0) return false;
    if (filter === 'pending' && Number(agent.pending_updates || 0) === 0) return false;
    if (filter === 'reboot' && !agent.reboot_required) return false;
    if (filter === 'online' && !isOnline(agent)) return false;
    if (filter === 'offline' && isOnline(agent)) return false;
    if (filter === 'outdated' && (!agent.runtime || agent.runtime.status === 'supported')) return false;

    return true;
  });
}

function renderAgents() {
  const items = filteredAgents();

  if (!items.length) {
    $('#agents').innerHTML = `
      <tr>
        <td colspan="10"><div class="empty-state">Nenhum endpoint encontrado.</div></td>
      </tr>`;
    return;
  }

  $('#agents').innerHTML = items.map((agent) => `
    <tr>
      <td>
        <strong>${esc(agent.hostname)}</strong>
        <br />
        <small class="muted">${esc(agent.ip_address || 'IP não informado')}</small>
      </td>
      <td>${isOnline(agent) ? badge('online', 'ok') : badge('offline', 'muted-badge')}</td>
      <td>
        ${esc(agent.os_name || agent.os_family || '-')}
        <br />
        <small class="muted">${esc(agent.os_version || '')}</small>
      </td>
      <td>
        <strong>${esc(agent.runtime && agent.runtime.version ? 'v' + agent.runtime.version : 'desconhecido')}</strong>
        <br />
        ${agent.runtime && agent.runtime.status === 'supported'
          ? badge('compatível', 'ok')
          : badge(agent.runtime && agent.runtime.status === 'outdated' ? 'desatualizado' : 'incompatível', 'fail')}
      </td>
      <td>${(agent.tags || []).map((tag) => badge(tag, 'info')).join('') || '-'}</td>
      <td>${when(agent.last_seen)}</td>
      <td><strong class="${Number(agent.pending_updates || 0) ? 'text-warn' : ''}">${Number(agent.pending_updates || 0)}</strong></td>
      <td><strong class="${Number(agent.critical_updates || 0) ? 'text-danger' : ''}">${Number(agent.critical_updates || 0)}</strong></td>
      <td>${agent.reboot_required ? badge('SIM', 'warn') : badge('não', 'ok')}</td>
      <td><button class="row-action" data-agent-open="${esc(agent.id)}">Detalhes</button></td>
    </tr>
  `).join('');
}

function renderRiskEndpoints() {
  const risky = [...state.agents]
    .filter((agent) => Number(agent.pending_updates || 0) > 0 || agent.reboot_required)
    .sort((a, b) => {
      const criticalDiff = Number(b.critical_updates || 0) - Number(a.critical_updates || 0);
      if (criticalDiff) return criticalDiff;
      return Number(b.pending_updates || 0) - Number(a.pending_updates || 0);
    })
    .slice(0, 6);

  if (!risky.length) {
    $('#riskEndpoints').innerHTML = `
      <div class="empty-state good">
        Nenhum endpoint com pendência relevante.
      </div>`;
    return;
  }

  $('#riskEndpoints').innerHTML = risky.map((agent) => `
    <article class="risk-item clickable" data-agent-open="${esc(agent.id)}" tabindex="0" role="button">
      <div>
        <strong>${esc(agent.hostname)}</strong>
        <span>${esc(agent.os_name || agent.os_family || '')}</span>
      </div>
      <div class="risk-metrics">
        ${Number(agent.critical_updates || 0) ? badge(`${agent.critical_updates} crítica(s)`, 'fail') : ''}
        ${Number(agent.pending_updates || 0) ? badge(`${agent.pending_updates} pendente(s)`, 'warn') : ''}
        ${agent.reboot_required ? badge('reboot', 'info') : ''}
      </div>
    </article>
  `).join('');
}



function vulnerabilityRiskBadge(risk) {
  if (!risk) return badge('-', 'info');
  if (risk.level === 'urgent') return badge('URGENTE ' + risk.score, 'fail');
  if (risk.level === 'high') return badge('ALTO ' + risk.score, 'warn');
  if (risk.level === 'medium') return badge('MÉDIO ' + risk.score, 'info');
  return badge('BAIXO ' + risk.score, 'muted-badge');
}

function vulnerabilitySeverityClass(severity) {
  if (severity === 'critical') return 'fail';
  if (severity === 'high' || severity === 'medium') return 'warn';
  if (severity === 'low') return 'info';
  return 'muted-badge';
}

function vulnerabilityStatusLabel(status) {
  const labels = {
    open: 'aberta',
    not_detected: 'não detectada',
    remediated: 'remediada',
    accepted_risk: 'risco aceito',
    false_positive: 'falso positivo',
  };
  return labels[status] || status;
}

function filteredVulnerabilities() {
  const query = ($('#vulnerabilitySearch')?.value || '').trim().toLowerCase();
  const filter = $('#vulnerabilityFilter')?.value || 'open';

  return state.vulnerabilities.filter((item) => {
    const searchable = [
      item.cve,
      item.hostname,
      item.host,
      item.ip_address,
      item.title,
      item.source,
      item.external_id,
    ].join(' ').toLowerCase();

    if (query && !searchable.includes(query)) return false;
    if (filter === 'open' && item.status !== 'open') return false;
    if (filter === 'critical' && !(item.status === 'open' && item.severity === 'critical')) return false;
    if (filter === 'high' && !(item.status === 'open' && item.severity === 'high')) return false;
    if (filter === 'unmatched' && !(item.status === 'open' && !item.matched)) return false;
    if (filter === 'remediated' && item.status !== 'remediated') return false;
    return true;
  });
}


function renderGreenboneIntegration() {
  const data = state.greenbone || {};
  const config = data.config || {};
  const details = data.details || {};
  const status = data.status || (config.enabled ? 'idle' : 'disabled');
  const labels = {
    disabled: 'desativado',
    idle: config.configured ? 'pronto' : 'não configurado',
    running: 'sincronizando',
    ok: 'OK',
    error: 'erro',
  };
  const cls = status === 'ok' ? 'ok' : status === 'error' ? 'fail' : status === 'running' ? 'warn' : 'info';

  $('#greenboneStatusBadge').className = 'metric-pill ' + cls;
  $('#greenboneStatusBadge').textContent = labels[status] || status;

  const endpoint = config.transport === 'unix'
    ? (config.socket_path || '-')
    : ((config.hostname || '-') + ':' + (config.port || '-'));

  const rows = [
    ['Modo', config.enabled ? 'automático' : 'manual / desativado'],
    ['Transporte', String(config.transport || '-').toUpperCase()],
    ['Endpoint', endpoint],
    ['Último sucesso', data.last_success_at ? when(data.last_success_at) : 'nunca'],
    ['Findings no último sync', details.findings == null ? '-' : details.findings],
    ['Correlacionados', details.matched == null ? '-' : details.matched],
    ['Relatórios', details.reports == null ? '-' : details.reports],
    ['Remediações verificadas', details.remediation_verified == null ? '-' : details.remediation_verified],
    ['Ainda detectadas', details.remediation_still_detected == null ? '-' : details.remediation_still_detected],
    ['Rescans aguardando', details.remediation_waiting == null ? '-' : details.remediation_waiting],
    ['Ausentes', config.reconcile_absent ? 'marcar not_detected' : 'não reconciliar'],
  ];

  $('#greenboneDetails').innerHTML = rows.map((row) =>
    '<div><span>' + esc(row[0]) + '</span><strong>' + esc(row[1]) + '</strong></div>'
  ).join('');

  if (data.last_error) {
    $('#greenboneDetails').insertAdjacentHTML(
      'beforeend',
      '<div class="integration-error"><span>Último erro</span><strong>' + esc(data.last_error) + '</strong></div>'
    );
  }

  $('#greenboneSync').disabled = !config.configured || status === 'running';
}

function renderThreatIntelIntegration() {
  const data = state.threatIntel || {};
  const config = data.config || {};
  const details = data.details || {};
  const status = data.status || (config.enabled ? 'idle' : 'disabled');
  const labels = {
    disabled: 'desativado',
    idle: config.configured ? 'pronto' : 'não configurado',
    running: 'sincronizando',
    ok: 'OK',
    degraded: 'degradado',
    error: 'erro',
  };
  const cls = status === 'ok'
    ? 'ok'
    : status === 'error'
      ? 'fail'
      : ['running', 'degraded'].includes(status)
        ? 'warn'
        : 'info';

  $('#threatIntelStatusBadge').className = 'metric-pill ' + cls;
  $('#threatIntelStatusBadge').textContent = labels[status] || status;

  const rows = [
    ['Modo', config.enabled ? 'automático' : 'manual / desativado'],
    ['Fontes', 'FIRST EPSS + CISA KEV'],
    ['Último sucesso', data.last_success_at ? when(data.last_success_at) : 'nunca'],
    ['CVEs consideradas', details.unique_cves == null ? '-' : details.unique_cves],
    ['EPSS enriquecidas', details.epss_enriched == null ? '-' : details.epss_enriched],
    ['KEV encontradas', details.kev_enriched == null ? '-' : details.kev_enriched],
    ['Findings atualizados', details.updated == null ? '-' : details.updated],
  ];

  $('#threatIntelDetails').innerHTML = rows.map((row) =>
    '<div><span>' + esc(row[0]) + '</span><strong>' + esc(row[1]) + '</strong></div>'
  ).join('');

  const sourceErrors = details.source_errors && typeof details.source_errors === 'object'
    ? Object.entries(details.source_errors)
    : [];
  if (sourceErrors.length) {
    $('#threatIntelDetails').insertAdjacentHTML(
      'beforeend',
      '<div class="integration-error"><span>Fonte degradada</span><strong>' +
      esc(sourceErrors.map(([name, message]) => name + ': ' + message).join(' · ')) +
      '</strong></div>'
    );
  } else if (data.last_error) {
    $('#threatIntelDetails').insertAdjacentHTML(
      'beforeend',
      '<div class="integration-error"><span>Último erro</span><strong>' + esc(data.last_error) + '</strong></div>'
    );
  }

  $('#threatIntelSync').disabled = !config.configured || status === 'running';
}


function remediationActionBadge(action) {
  const labels = {
    patch_now: ['PATCH AGORA', 'fail'],
    schedule_patch: ['AGENDAR', 'warn'],
    plan_patch: ['PLANEJAR', 'info'],
    scan_or_manual_triage: ['TRIAGEM', 'warn'],
    correlate_asset: ['CORRELACIONAR', 'fail'],
    exception_active: ['EXCEÇÃO ATIVA', 'info'],
    none: ['SEM AÇÃO', 'muted-badge'],
  };
  const item = labels[action] || [action || '-', 'info'];
  return badge(item[0], item[1]);
}

function renderRemediationQueue() {
  const report = state.remediationQueue || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items.slice(0, 10) : [];

  $('#remediationQueueStats').innerHTML = [
    ['Patch agora', summary.patch_now || 0],
    ['Agendar', summary.schedule_patch || 0],
    ['Triagem', summary.scan_or_manual_triage || 0],
    ['Correlacionar', summary.correlate_asset || 0],
    ['Prontas p/ campanha', summary.eligible_for_campaign || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  if (!items.length) {
    $('#remediationQueue').innerHTML =
      '<tr><td colspan="7"><div class="empty-state good">Nenhuma vulnerabilidade aberta na fila.</div></td></tr>';
    return;
  }

  $('#remediationQueue').innerHTML = items.map((item) => {
    const rec = item.recommendation || {};
    const risk = rec.risk || {};
    const reasons = Array.isArray(rec.reasons) ? rec.reasons : [];
    return '<tr>' +
      '<td><strong>' + esc(item.cve || 'sem CVE') + '</strong><br><small class="muted">' + esc(item.hostname || 'sem endpoint') + '</small></td>' +
      '<td>' + remediationActionBadge(rec.action) + '</td>' +
      '<td><strong>' + esc(rec.priority_score == null ? '-' : rec.priority_score) + '</strong></td>' +
      '<td>' + vulnerabilityRiskBadge(risk) + '</td>' +
      '<td>' + vulnerabilitySlaBadge(rec.sla) + '</td>' +
      '<td><small>' + esc(reasons.join(' · ') || '-') + '</small></td>' +
      '<td>' + (
        rec.eligible_for_campaign && item.agent_id && roleAtLeast('operator')
          ? '<button class="row-action" onclick="prepareCampaignFromFinding(\'' + item.id + '\')">Preparar campanha</button>'
          : ''
      ) + '</td>' +
    '</tr>';
  }).join('');
}


function assetRiskBadge(risk) {
  if (!risk) return badge('-', 'info');
  if (risk.level === 'critical') return badge('CRÍTICO ' + risk.score, 'fail');
  if (risk.level === 'high') return badge('ALTO ' + risk.score, 'warn');
  if (risk.level === 'medium') return badge('MÉDIO ' + risk.score, 'info');
  return badge('BAIXO ' + risk.score, 'muted-badge');
}

function assetRiskTrend(risk) {
  const trend = risk && risk.trend ? risk.trend : {};
  if (trend.direction === 'up') return badge('↑ +' + Number(trend.delta || 0).toFixed(1), 'fail');
  if (trend.direction === 'down') return badge('↓ ' + Number(trend.delta || 0).toFixed(1), 'ok');
  if (trend.direction === 'flat') return badge('→ 0', 'info');
  return badge('novo', 'muted-badge');
}

function renderAssetRisk() {
  const report = state.assetRisk || {};
  const summary = report.summary || {};
  const assets = Array.isArray(report.assets) ? report.assets.slice(0, 10) : [];

  $('#assetRiskStats').innerHTML = [
    ['Ativos', summary.assets || 0],
    ['Críticos', summary.critical || 0],
    ['Altos', summary.high || 0],
    ['Média', summary.average_score == null ? '-' : summary.average_score],
    ['Apetite global', summary.risk_appetite == null ? 700 : summary.risk_appetite],
    ['Políticas', summary.risk_policies || 0],
    ['Acima', summary.above_risk_appetite || 0],
    ['Aceitos', summary.accepted_above_appetite || 0],
    ['Em tratamento', summary.in_treatment_above_appetite || 0],
    ['Tratamento vencido', summary.overdue_treatment_above_appetite || 0],
    ['Sem ação', summary.untreated_above_appetite || summary.unaccepted_above_appetite || 0],
    ['Com owner', summary.assets_with_owner || 0],
    ['Sem owner', summary.assets_without_owner || 0],
    ['Crít./alto sem owner', summary.critical_high_without_owner || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  const topContributors = Array.isArray(report.top_contributors) ? report.top_contributors : [];
  $('#assetRiskContributors').innerHTML = topContributors.length
    ? topContributors.map((item, index) =>
        '<div class="risk-contributor">' +
          '<span>' + esc(String(index + 1) + '. ' + item.name) +
            '<br><small class="muted">' + esc((item.assets_affected || 0) + ' ativos · ' + (item.share_percent || 0) + '%') + '</small></span>' +
          '<strong>' + esc(Number(item.raw || 0).toFixed(1)) + '</strong>' +
        '</div>'
      ).join('')
    : '<div class="empty-state">Sem contributors calculados.</div>';

  renderRiskPolicies();

  if (!assets.length) {
    $('#assetRiskTable').innerHTML =
      '<tr><td colspan="10"><div class="empty-state">Nenhum ativo calculado.</div></td></tr>';
    return;
  }

  $('#assetRiskTable').innerHTML = assets.map((item) => {
    const risk = item.risk || {};
    const crit = risk.asset_criticality || {};
    const exposure = risk.exposure || {};
    const compensating = risk.compensating || {};
    const policy = item.risk_policy || {};
    const policyData = policy.policy || {};
    const acceptance = item.risk_acceptance || null;
    const treatment = item.risk_treatment || null;
    const factors = Array.isArray(risk.top_factors) ? risk.top_factors : [];
    return '<tr>' +
      '<td><strong>' + esc(item.hostname || item.agent_id) + '</strong><br><small class="muted">' + esc(item.ip_address || '') + '</small></td>' +
      '<td>' + assetRiskBadge(risk) +
        '<br><small class="muted">apetite ' + esc(risk.risk_appetite == null ? '-' : risk.risk_appetite) +
        ' · ' + esc(policy.source === 'policy' ? (policyData.name || 'policy') : 'global') + '</small>' +
        (risk.governance_status === 'accepted'
          ? '<br>' + badge('RISCO ACEITO', 'info') + '<br><small class="muted">até ' + esc(when(acceptance && acceptance.expires_at)) + '</small>'
          : risk.governance_status === 'treatment_overdue'
            ? '<br>' + badge('TRATAMENTO VENCIDO', 'fail') +
              '<br><small class="muted">' + esc((treatment && treatment.owner) || '-') + ' · ' + esc(when(treatment && treatment.due_at)) + '</small>'
          : risk.governance_status === 'in_treatment'
            ? '<br>' + badge('EM TRATAMENTO', 'warn') +
              '<br><small class="muted">' + esc((treatment && treatment.owner) || '-') + ' · até ' + esc(when(treatment && treatment.due_at)) + '</small>'
          : risk.above_risk_appetite
            ? '<br>' + badge('acima do apetite', 'fail')
            : '') +
      '</td>' +
      '<td>' + assetRiskTrend(risk) + '</td>' +
      '<td><strong>' + esc(crit.score == null ? '-' : crit.score) + '/5</strong></td>' +
      '<td>' + (exposure.external ? badge('externo', 'fail') : badge('interno', 'ok')) + '</td>' +
      '<td><strong>' + esc(risk.open_findings == null ? 0 : risk.open_findings) + '</strong></td>' +
      '<td><small><strong>' + esc(((item.risk_profile || {}).owner) || 'sem owner') + '</strong>' +
        '<br>' + esc(((item.risk_profile || {}).business_service) || 'sem serviço') +
        '<br><span class="muted">' + esc(((item.risk_profile || {}).environment) || 'sem ambiente') + '</span></small></td>' +
      '<td><small>' + esc(factors.join(' · ') || '-') + '</small></td>' +
      '<td><small>' + esc(
        Array.isArray(risk.decomposition) && risk.decomposition.length
          ? risk.decomposition
              .slice(0, 4)
              .map((item) => item.name + ' ' + (item.raw >= 0 ? '+' : '') + Number(item.raw || 0).toFixed(1))
              .join(' · ')
          : '-'
      ) + '</small></td>' +
      '<td><small>' + esc(
        Array.isArray(compensating.controls) && compensating.controls.length
          ? compensating.controls.map((control) => control.tag).join(', ')
          : 'nenhum'
      ) + '<br><span class="muted">fonte: ' + esc(compensating.source || 'tags') + '</span></small></td>' +
      '<td>' +
        '<button class="row-action" onclick="showAssetRiskTimeline(\'' + item.agent_id + '\')">Timeline</button>' +
        ' <button class="row-action" onclick="showRiskReductionPlan(\'' + item.agent_id + '\')">Plano de redução</button>' +
        (
          roleAtLeast('admin')
            ? ' <button class="row-action" onclick="editAssetRiskProfile(\'' + item.agent_id + '\')">Perfil de risco</button>' +
              (treatment && treatment.active
                ? ' <button class="row-action" onclick="editAssetRiskTreatment(\'' + item.agent_id + '\', \'' + treatment.id + '\')">Atualizar plano</button>'
                : risk.above_risk_appetite
                  ? ' <button class="row-action" onclick="createAssetRiskTreatment(\'' + item.agent_id + '\')">Plano de tratamento</button>'
                  : '') +
              (acceptance && acceptance.active
                ? ' <button class="row-action" onclick="revokeAssetRiskAcceptance(\'' + item.agent_id + '\', \'' + acceptance.id + '\')">Revogar aceite</button>'
                : risk.above_risk_appetite
                  ? ' <button class="row-action" onclick="createAssetRiskAcceptance(\'' + item.agent_id + '\')">Aceitar risco</button>'
                  : '')
            : ''
        ) + '</td>' +
    '</tr>';
  }).join('');
}


function renderRiskPolicies() {
  const policies = Array.isArray(state.riskPolicies) ? state.riskPolicies : [];
  const target = $('#riskPolicyList');
  if (!target) return;

  target.innerHTML = policies.length
    ? policies.map((policy) =>
        '<div class="risk-contributor">' +
          '<span><strong>' + esc(policy.name) + '</strong> · tag ' + esc(policy.target_tag) +
          ' · prioridade ' + esc(policy.priority) +
          (policy.enabled ? '' : ' · desativada') + '</span>' +
          '<span><strong>apetite ' + esc(policy.risk_appetite) + '</strong>' +
          (roleAtLeast('admin')
            ? ' <button class="row-action" onclick="editRiskPolicy(\'' + policy.id + '\')">Editar</button>'
            : '') +
          '</span>' +
        '</div>'
      ).join('')
    : '<div class="empty-state">Nenhuma política por tag. Vale o appetite global.</div>';
}

window.createRiskGoal = async () => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const due = new Date(Date.now() + 30 * 86400000);
  const localDue = new Date(due.getTime() - due.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

  openGovernanceModal({
    kicker: 'RISK REDUCTION GOAL',
    title: 'Nova meta de redução',
    context: 'O baseline será congelado agora. O valor atual será recalculado continuamente sobre o escopo dinâmico.',
    submitLabel: 'Criar meta',
    fields: [
      { name: 'name', label: 'Nome', type: 'text', required: true, minLength: 3 },
      {
        name: 'goal_type',
        label: 'Métrica',
        type: 'select',
        value: 'assets_above_appetite_max',
        options: [
          { value: 'assets_above_appetite_max', label: 'Ativos acima do appetite' },
          { value: 'average_asset_risk_max', label: 'Asset Risk médio' },
          { value: 'open_findings_max', label: 'Findings abertos' },
          { value: 'critical_high_assets_max', label: 'Ativos Critical/High' },
        ],
      },
      { name: 'scope_tag', label: 'Tag de escopo', type: 'text', hint: 'Vazio = todos os ativos gerenciados.' },
      { name: 'target_value', label: 'Target máximo', type: 'number', min: 0, step: 0.1, required: true },
      { name: 'owner', label: 'Owner', type: 'text', required: true, minLength: 2 },
      { name: 'due_at', label: 'Prazo', type: 'datetime-local', value: localDue, required: true },
      { name: 'reason', label: 'Objetivo / justificativa', type: 'textarea', required: true, minLength: 5, wide: true },
    ],
    onSubmit: async (values) => {
      const target = Number(values.target_value);
      if (!Number.isFinite(target) || target < 0) throw new Error('Target inválido.');
      await api('/api/admin/risk-goals', {
        method: 'POST',
        body: JSON.stringify({
          name: String(values.name || '').trim(),
          goal_type: String(values.goal_type || ''),
          scope_tag: String(values.scope_tag || '').trim().toLowerCase(),
          target_value: target,
          owner: String(values.owner || '').trim(),
          due_at: new Date(values.due_at).toISOString(),
          reason: String(values.reason || '').trim(),
        }),
      });
      toast('Meta de redução criada com baseline congelado.');
      await load();
    },
  });
};

window.editRiskGoal = async (goalId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const goal = ((state.riskGoals || {}).items || []).find((item) => item.id === goalId);
  if (!goal) return;
  const due = new Date(goal.due_at);
  const localDue = new Date(due.getTime() - due.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

  openGovernanceModal({
    kicker: 'RISK REDUCTION GOAL',
    title: 'Gerenciar · ' + goal.name,
    context: 'Baseline ' + goal.baseline_value + ' · atual ' + goal.current_value + ' · target ' + goal.target_value + ' · ' + goal.progress_percent + '%',
    submitLabel: 'Salvar meta',
    fields: [
      { name: 'target_value', label: 'Target máximo', type: 'number', value: goal.target_value, min: 0, step: 0.1, required: true },
      { name: 'owner', label: 'Owner', type: 'text', value: goal.owner, required: true, minLength: 2 },
      { name: 'due_at', label: 'Prazo', type: 'datetime-local', value: localDue, required: true },
      {
        name: 'status',
        label: 'Status',
        type: 'select',
        value: goal.status,
        options: [
          { value: 'active', label: 'Ativa' },
          { value: 'completed', label: 'Concluída (exige target atingido)' },
          { value: 'cancelled', label: 'Cancelada' },
        ],
      },
      { name: 'reason', label: 'Motivo da alteração', type: 'textarea', required: true, minLength: 5, wide: true },
    ],
    onSubmit: async (values) => {
      await api('/api/admin/risk-goals/' + goalId, {
        method: 'PUT',
        body: JSON.stringify({
          target_value: Number(values.target_value),
          owner: String(values.owner || '').trim(),
          due_at: new Date(values.due_at).toISOString(),
          status: String(values.status || 'active'),
          reason: String(values.reason || '').trim(),
        }),
      });
      toast('Meta de redução atualizada.');
      await load();
    },
  });
};


window.createRiskPolicy = async () => {
  if (!requireRole('admin', 'Somente admin pode criar política de risco.')) return;

  openGovernanceModal({
    kicker: 'RISK APPETITE POLICY',
    title: 'Nova política de appetite',
    context: 'A política altera o limite operacional dos ativos que casam com a tag. Ela não altera o Asset Risk.',
    submitLabel: 'Criar política',
    fields: [
      { name: 'name', label: 'Nome', type: 'text', required: true, minLength: 3 },
      { name: 'target_tag', label: 'Tag alvo', type: 'text', required: true, hint: 'Ex.: tier0, prod, lab.' },
      { name: 'risk_appetite', label: 'Risk appetite', type: 'number', value: 700, min: 1, max: 1000, step: 1, required: true },
      { name: 'priority', label: 'Prioridade', type: 'number', value: 100, min: 1, max: 10000, step: 1, required: true, hint: 'Maior prioridade vence quando mais de uma policy casa.' },
      { name: 'reason', label: 'Motivo / decisão', type: 'textarea', required: true, minLength: 5, wide: true },
    ],
    onSubmit: async (values) => {
      const name = String(values.name || '').trim();
      const targetTag = String(values.target_tag || '').trim().toLowerCase();
      const appetite = Number(values.risk_appetite);
      const priority = Number(values.priority);
      const reason = String(values.reason || '').trim();
      if (name.length < 3) throw new Error('Nome precisa ter pelo menos 3 caracteres.');
      if (!targetTag) throw new Error('Informe a tag alvo.');
      if (!Number.isInteger(appetite) || appetite < 1 || appetite > 1000) throw new Error('Risk appetite deve ficar entre 1 e 1000.');
      if (!Number.isInteger(priority) || priority < 1 || priority > 10000) throw new Error('Prioridade inválida.');
      if (reason.length < 5) throw new Error('Informe um motivo com pelo menos 5 caracteres.');

      await api('/api/admin/risk-policies', {
        method: 'POST',
        body: JSON.stringify({
          name,
          target_tag: targetTag,
          risk_appetite: appetite,
          priority,
          enabled: true,
          reason,
        }),
      });
      toast('Política de risco criada.');
      await load();
    },
  });
};

window.editRiskPolicy = async (policyId) => {
  if (!requireRole('admin', 'Somente admin pode editar política de risco.')) return;
  const policy = (state.riskPolicies || []).find((item) => item.id === policyId);
  if (!policy) return;

  openGovernanceModal({
    kicker: 'RISK APPETITE POLICY',
    title: 'Editar · ' + policy.name,
    context: 'Tag ' + policy.target_tag + ' · appetite atual ' + policy.risk_appetite + ' · prioridade ' + policy.priority,
    submitLabel: 'Salvar política',
    fields: [
      { name: 'name', label: 'Nome', type: 'text', value: policy.name, required: true, minLength: 3 },
      { name: 'target_tag', label: 'Tag alvo', type: 'text', value: policy.target_tag, required: true },
      { name: 'risk_appetite', label: 'Risk appetite', type: 'number', value: policy.risk_appetite, min: 1, max: 1000, step: 1, required: true },
      { name: 'priority', label: 'Prioridade', type: 'number', value: policy.priority, min: 1, max: 10000, step: 1, required: true },
      {
        name: 'enabled',
        label: 'Status',
        type: 'select',
        value: policy.enabled ? 'on' : 'off',
        options: [
          { value: 'on', label: 'Ativa' },
          { value: 'off', label: 'Desativada' },
        ],
      },
      { name: 'reason', label: 'Motivo da alteração', type: 'textarea', required: true, minLength: 5, wide: true },
    ],
    onSubmit: async (values) => {
      const name = String(values.name || '').trim();
      const targetTag = String(values.target_tag || '').trim().toLowerCase();
      const appetite = Number(values.risk_appetite);
      const priority = Number(values.priority);
      const reason = String(values.reason || '').trim();
      if (name.length < 3) throw new Error('Nome precisa ter pelo menos 3 caracteres.');
      if (!targetTag) throw new Error('Informe a tag alvo.');
      if (!Number.isInteger(appetite) || appetite < 1 || appetite > 1000) throw new Error('Risk appetite inválido.');
      if (!Number.isInteger(priority) || priority < 1 || priority > 10000) throw new Error('Prioridade inválida.');
      if (reason.length < 5) throw new Error('Informe um motivo com pelo menos 5 caracteres.');

      await api('/api/admin/risk-policies/' + policyId, {
        method: 'PUT',
        body: JSON.stringify({
          name,
          target_tag: targetTag,
          risk_appetite: appetite,
          priority,
          enabled: String(values.enabled || 'on') === 'on',
          reason,
        }),
      });
      toast('Política de risco atualizada.');
      await load();
    },
  });
};


window.showAssetRiskTimeline = async (agentId) => {
  try {
    const result = await api('/api/admin/reports/asset-risk/history?agent_id=' + encodeURIComponent(agentId) + '&limit=50');
    const items = Array.isArray(result.items) ? result.items.slice().reverse() : [];
    const target = $('#assetRiskTimeline');
    if (!target) return;

    if (!items.length) {
      target.innerHTML = '<div class="empty-state">Sem snapshots para este ativo.</div>';
      return;
    }

    let previous = null;
    const rows = items.map((item) => {
      const delta = previous == null ? null : Number(item.score || 0) - Number(previous.score || 0);
      const direction = delta == null ? 'novo' : delta > 0 ? '↑ +' + delta.toFixed(1) : delta < 0 ? '↓ ' + delta.toFixed(1) : '→ 0';
      previous = item;
      const policy = item.risk_policy || {};
      const policyData = policy.policy || {};
      const policyName = policy.source === 'policy' ? (policyData.name || 'policy') : 'global';
      return '<tr>' +
        '<td>' + esc(shortWhen(item.captured_at)) + '</td>' +
        '<td><strong>' + esc(Number(item.score || 0).toFixed(1)) + '</strong><br><small class="muted">' + esc(item.level || '-') + '</small></td>' +
        '<td>' + esc(direction) + '</td>' +
        '<td><strong>' + esc(item.risk_appetite == null ? '-' : item.risk_appetite) + '</strong><br><small class="muted">' + esc(policyName) + '</small></td>' +
        '<td>' + esc(item.governance_status || '-') + '</td>' +
        '<td><small>' + esc(item.model_version || '-') + '</small></td>' +
        '<td><small>' + esc(item.source || '-') + '</small></td>' +
      '</tr>';
    }).join('');

    const latest = items[items.length - 1] || {};
    const calc = latest.calculation || {};
    target.innerHTML =
      '<div><span>Ativo</span><strong>' + esc(latest.hostname || agentId) + '</strong></div>' +
      '<div><span>Snapshots</span><strong>' + esc(items.length) + '</strong></div>' +
      '<div><span>Modelo atual salvo</span><strong>' + esc(latest.model_version || '-') + '</strong></div>' +
      '<div><span>Raw score</span><strong>' + esc(calc.raw_score == null ? '-' : calc.raw_score) + '</strong></div>' +
      '<div class="table-wrap"><table><thead><tr>' +
        '<th>Data</th><th>Score</th><th>Delta</th><th>Apetite / Policy</th><th>Governança</th><th>Modelo</th><th>Origem</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div>';

    toast('Timeline de Asset Risk carregada.');
  } catch (error) {
    toast('Timeline de risco: ' + error.message, 'fail');
  }
};


window.showRiskReductionPlan = async (agentId) => {
  try {
    const result = await api('/api/admin/agents/' + agentId + '/risk-reduction-plan?max_steps=25');
    const target = $('#riskReductionPlanResult');
    if (!target) return;
    const steps = Array.isArray(result.steps) ? result.steps : [];

    const header =
      '<div><span>Ativo</span><strong>' + esc((result.asset || {}).hostname || agentId) + '</strong></div>' +
      '<div><span>Score atual</span><strong>' + esc(result.initial_score) + '</strong></div>' +
      '<div><span>Score projetado</span><strong>' + esc(result.projected_score) + '</strong></div>' +
      '<div><span>Apetite</span><strong>' + esc(result.risk_appetite) + '</strong></div>' +
      '<div><span>Meta atingida</span><strong>' + esc(result.target_reached ? 'sim' : 'não') + '</strong></div>';

    const body = steps.length
      ? '<div class="table-wrap"><table><thead><tr>' +
          '<th>#</th><th>Finding</th><th>Ação</th><th>Score</th><th>Marginal</th><th>Cumulativa</th><th></th>' +
        '</tr></thead><tbody>' +
        steps.map((step) =>
          '<tr>' +
            '<td><strong>' + esc(step.step) + '</strong></td>' +
            '<td><strong>' + esc(step.cve || step.finding_id) + '</strong><br><small class="muted">' + esc(step.title || '') + '</small></td>' +
            '<td><small>' + esc(step.action || '-') + '</small></td>' +
            '<td><strong>' + esc(step.before_score) + ' → ' + esc(step.after_score) + '</strong></td>' +
            '<td><strong>-' + esc(step.marginal_reduction) + '</strong></td>' +
            '<td><strong>-' + esc(step.cumulative_reduction) + '</strong></td>' +
            '<td>' + (
              step.eligible_for_campaign && roleAtLeast('operator')
                ? '<button class="row-action" onclick="prepareCampaignFromFinding(\'' + step.finding_id + '\')">Preparar campanha</button>'
                : '<small class="muted">somente análise</small>'
            ) + '</td>' +
          '</tr>'
        ).join('') +
        '</tbody></table></div>'
      : '<div class="empty-state">Nenhuma remediação necessária para atingir o appetite ou não há findings abertos.</div>';

    target.innerHTML = header + body;
    toast('Plano de redução recalculado.');
  } catch (error) {
    toast('Plano de redução: ' + error.message, 'fail');
  }
};


window.createAssetRiskTreatment = async (agentId) => {
  if (!requireRole('admin', 'Somente admin pode criar plano de tratamento.')) return;
  const item = state.assetRisk && Array.isArray(state.assetRisk.assets)
    ? state.assetRisk.assets.find((asset) => asset.agent_id === agentId)
    : null;
  const profile = item ? (item.risk_profile || {}) : {};

  openGovernanceModal({
    kicker: 'RISK TREATMENT',
    title: 'Novo plano de tratamento',
    context:
      (item ? item.hostname : agentId) +
      ' · Asset Risk ' + (item && item.risk ? item.risk.score : '-') +
      ' · owner ' + (profile.owner || 'não definido'),
    submitLabel: 'Criar plano',
    fields: [
      { name: 'owner', label: 'Owner do plano', type: 'text', value: profile.owner || '', required: true, minLength: 2 },
      { name: 'days', label: 'Prazo (dias)', type: 'number', value: 30, min: 1, max: 3650, step: 1, required: true },
      {
        name: 'action',
        label: 'Ação planejada',
        type: 'textarea',
        required: true,
        minLength: 5,
        wide: true,
        hint: 'Descreva a ação concreta de redução do risco.',
      },
    ],
    onSubmit: async (values) => {
      const owner = String(values.owner || '').trim();
      const action = String(values.action || '').trim();
      const days = Number(values.days);
      if (owner.length < 2) throw new Error('Informe o owner do plano.');
      if (action.length < 5) throw new Error('Descreva a ação planejada.');
      if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error('Prazo inválido.');

      await api('/api/admin/agents/' + agentId + '/risk-treatments', {
        method: 'POST',
        body: JSON.stringify({
          owner,
          action,
          due_at: new Date(Date.now() + days * 86400000).toISOString(),
        }),
      });
      toast('Plano de tratamento criado.');
      await load();
    },
  });
};

window.editAssetRiskTreatment = async (agentId, treatmentId) => {
  if (!requireRole('admin', 'Somente admin pode alterar plano de tratamento.')) return;
  const item = state.assetRisk && Array.isArray(state.assetRisk.assets)
    ? state.assetRisk.assets.find((asset) => asset.agent_id === agentId)
    : null;
  const treatment = item && item.risk_treatment ? item.risk_treatment : null;
  if (!treatment || treatment.id !== treatmentId) {
    toast('Plano ativo não encontrado.', 'fail');
    return;
  }

  openGovernanceModal({
    kicker: 'RISK TREATMENT',
    title: 'Atualizar plano · ' + (item.hostname || agentId),
    context:
      'Prazo ' + when(treatment.due_at) +
      ' · status ' + treatment.status +
      (treatment.overdue ? ' · VENCIDO' : ''),
    submitLabel: 'Salvar plano',
    fields: [
      { name: 'owner', label: 'Owner', type: 'text', value: treatment.owner || '', required: true, minLength: 2 },
      {
        name: 'status',
        label: 'Status',
        type: 'select',
        value: treatment.status || 'planned',
        options: [
          { value: 'planned', label: 'Planned' },
          { value: 'in_progress', label: 'In progress' },
          { value: 'completed', label: 'Completed' },
          { value: 'cancelled', label: 'Cancelled' },
        ],
      },
      { name: 'action', label: 'Ação', type: 'textarea', value: treatment.action || '', required: true, minLength: 5, wide: true },
      {
        name: 'completion_evidence',
        label: 'Evidência de conclusão',
        type: 'textarea',
        value: treatment.completion_evidence || '',
        wide: true,
        hint: 'Obrigatória quando o status for completed.',
      },
    ],
    onSubmit: async (values) => {
      const owner = String(values.owner || '').trim();
      const action = String(values.action || '').trim();
      const status = String(values.status || '').trim();
      const evidence = String(values.completion_evidence || '').trim();
      if (owner.length < 2) throw new Error('Informe o owner.');
      if (action.length < 5) throw new Error('Descreva a ação.');
      if (!['planned', 'in_progress', 'completed', 'cancelled'].includes(status)) throw new Error('Status inválido.');
      if (status === 'completed' && evidence.length < 5) throw new Error('Informe evidência de conclusão.');

      await api('/api/admin/agents/' + agentId + '/risk-treatments/' + treatmentId, {
        method: 'PUT',
        body: JSON.stringify({
          owner,
          action,
          status,
          completion_evidence: evidence,
        }),
      });
      toast('Plano de tratamento atualizado.');
      await load();
    },
  });
};


let governanceModalSubmitHandler = null;

function closeGovernanceModal() {
  const modal = $('#governanceModal');
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute('aria-hidden', 'true');
  $('#governanceFields').innerHTML = '';
  $('#governanceError').hidden = true;
  $('#governanceError').textContent = '';
  governanceModalSubmitHandler = null;
}

function openGovernanceModal({
  kicker = 'GOVERNANÇA',
  title,
  context = '',
  submitLabel = 'Salvar',
  fields = [],
  onSubmit,
}) {
  $('#governanceKicker').textContent = kicker;
  $('#governanceTitle').textContent = title;
  $('#governanceContext').textContent = context;
  $('#governanceSubmit').textContent = submitLabel;
  $('#governanceError').hidden = true;
  $('#governanceError').textContent = '';

  $('#governanceFields').innerHTML = fields.map((field) => {
    const required = field.required ? ' required' : '';
    const minLength = field.minLength == null ? '' : ' minlength="' + esc(field.minLength) + '"';
    const min = field.min == null ? '' : ' min="' + esc(field.min) + '"';
    const max = field.max == null ? '' : ' max="' + esc(field.max) + '"';
    const step = field.step == null ? '' : ' step="' + esc(field.step) + '"';
    const wide = field.wide ? ' wide' : '';
    const hint = field.hint ? '<small class="governance-field-hint">' + esc(field.hint) + '</small>' : '';
    let control = '';

    if (field.type === 'select') {
      control = '<select name="' + esc(field.name) + '"' + required + '>' +
        (field.options || []).map((option) =>
          '<option value="' + esc(option.value) + '"' +
          (String(option.value) === String(field.value ?? '') ? ' selected' : '') +
          '>' + esc(option.label) + '</option>'
        ).join('') +
        '</select>';
    } else if (field.type === 'textarea') {
      control = '<textarea name="' + esc(field.name) + '"' + required + minLength + '>' +
        esc(field.value || '') + '</textarea>';
    } else {
      control = '<input name="' + esc(field.name) + '" type="' + esc(field.type || 'text') + '"' +
        ' value="' + esc(field.value ?? '') + '"' + required + minLength + min + max + step + ' />';
    }

    return '<label class="' + wide.trim() + '"><span>' + esc(field.label) + '</span>' + control + hint + '</label>';
  }).join('');

  governanceModalSubmitHandler = onSubmit;
  const modal = $('#governanceModal');
  modal.hidden = false;
  modal.setAttribute('aria-hidden', 'false');
  const first = $('#governanceFields input, #governanceFields select, #governanceFields textarea');
  if (first) first.focus();
}

$('#governanceModalClose').addEventListener('click', closeGovernanceModal);
$('#governanceModalBackdrop').addEventListener('click', closeGovernanceModal);
$('#governanceCancel').addEventListener('click', closeGovernanceModal);
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !$('#governanceModal').hidden) closeGovernanceModal();
});

$('#governanceForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!governanceModalSubmitHandler) return;

  const submit = $('#governanceSubmit');
  const error = $('#governanceError');
  submit.disabled = true;
  error.hidden = true;
  error.textContent = '';
  try {
    const values = Object.fromEntries(new FormData(event.target).entries());
    await governanceModalSubmitHandler(values);
    closeGovernanceModal();
  } catch (err) {
    error.textContent = err.message || String(err);
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
});

window.createAssetRiskAcceptance = async (agentId) => {
  if (!requireRole('admin', 'Somente admin pode aceitar risco.')) return;
  const item = state.assetRisk && Array.isArray(state.assetRisk.assets)
    ? state.assetRisk.assets.find((asset) => asset.agent_id === agentId)
    : null;
  const hostname = item ? item.hostname : agentId;
  const score = item && item.risk ? item.risk.score : '-';
  const appetite = item && item.risk ? item.risk.risk_appetite : '-';

  openGovernanceModal({
    kicker: 'RISK ACCEPTANCE',
    title: 'Aceitar risco temporariamente',
    context: hostname + ' · Asset Risk ' + score + ' · appetite ' + appetite + ' · o score não será reduzido',
    submitLabel: 'Aceitar risco',
    fields: [
      {
        name: 'reason',
        label: 'Motivo / decisão',
        type: 'textarea',
        required: true,
        minLength: 5,
        wide: true,
        hint: 'Registre a justificativa de negócio ou técnica. A decisão ficará auditada.',
      },
      {
        name: 'days',
        label: 'Validade (dias)',
        type: 'number',
        value: 30,
        min: 1,
        max: 365,
        step: 1,
        required: true,
        hint: 'Máximo de 365 dias. A expiração é automática.',
      },
    ],
    onSubmit: async (values) => {
      const days = Number(values.days);
      if (!Number.isInteger(days) || days < 1 || days > 365) {
        throw new Error('Validade deve ficar entre 1 e 365 dias.');
      }
      const reason = String(values.reason || '').trim();
      if (reason.length < 5) throw new Error('Informe um motivo com pelo menos 5 caracteres.');
      const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
      await api('/api/admin/agents/' + agentId + '/risk-acceptances', {
        method: 'POST',
        body: JSON.stringify({ reason, expires_at: expiresAt }),
      });
      toast('Risco aceito temporariamente. O score não foi alterado.');
      await load();
    },
  });
};

window.revokeAssetRiskAcceptance = async (agentId, acceptanceId) => {
  if (!requireRole('admin', 'Somente admin pode revogar aceitação de risco.')) return;
  const item = state.assetRisk && Array.isArray(state.assetRisk.assets)
    ? state.assetRisk.assets.find((asset) => asset.agent_id === agentId)
    : null;

  openGovernanceModal({
    kicker: 'RISK ACCEPTANCE',
    title: 'Revogar aceitação',
    context: (item ? item.hostname : agentId) + ' · a revogação volta a expor o estado de governança calculado',
    submitLabel: 'Revogar aceite',
    fields: [
      {
        name: 'reason',
        label: 'Motivo da revogação',
        type: 'textarea',
        required: true,
        minLength: 5,
        wide: true,
      },
    ],
    onSubmit: async (values) => {
      const reason = String(values.reason || '').trim();
      if (reason.length < 5) throw new Error('Informe um motivo com pelo menos 5 caracteres.');
      await api('/api/admin/agents/' + agentId + '/risk-acceptances/' + acceptanceId + '/revoke', {
        method: 'POST',
        body: JSON.stringify({ reason }),
      });
      toast('Aceitação de risco revogada.');
      await load();
    },
  });
};


window.editAssetRiskProfile = async (agentId) => {
  if (!requireRole('admin', 'Somente admin pode alterar o perfil de risco.')) return;

  const item = state.assetRisk && Array.isArray(state.assetRisk.assets)
    ? state.assetRisk.assets.find((asset) => asset.agent_id === agentId)
    : null;
  if (!item) {
    toast('Ativo não encontrado no relatório de risco.', 'fail');
    return;
  }

  let current = null;
  try {
    current = await api('/api/admin/agents/' + agentId + '/risk-profile');
  } catch (error) {
    toast('Perfil de risco: ' + error.message, 'fail');
    return;
  }

  const profile = current.profile || {};
  const effective = current.effective || {};
  const exposureDefault = profile.external === true ? 'externo' : profile.external === false ? 'interno' : 'auto';
  const controlsDefault = Array.isArray(profile.compensating_controls)
    ? profile.compensating_controls.join(', ')
    : 'auto';

  openGovernanceModal({
    kicker: 'ASSET CONTEXT',
    title: 'Perfil de risco · ' + item.hostname,
    context:
      'Criticidade efetiva ' + String((effective.criticality || {}).score || '-') + '/5' +
      ' · exposição ' + ((effective.exposure || {}).external ? 'externa' : 'interna') +
      ' · contexto explícito tem precedência sobre tags',
    submitLabel: 'Salvar perfil',
    fields: [
      {
        name: 'criticality',
        label: 'Criticidade',
        type: 'select',
        value: profile.criticality == null ? '' : String(profile.criticality),
        options: [
          { value: '', label: 'Automática por tags' },
          { value: '1', label: '1 · baixa' },
          { value: '2', label: '2' },
          { value: '3', label: '3' },
          { value: '4', label: '4' },
          { value: '5', label: '5 · crítica / Tier 0' },
        ],
      },
      {
        name: 'exposure',
        label: 'Exposição',
        type: 'select',
        value: exposureDefault,
        options: [
          { value: 'auto', label: 'Automática por tags' },
          { value: 'interno', label: 'Interno' },
          { value: 'externo', label: 'Externo' },
        ],
      },
      {
        name: 'controls',
        label: 'Controles compensatórios',
        type: 'text',
        value: controlsDefault,
        wide: true,
        hint: 'Use auto ou: segmented, edr-protected, restricted-egress',
      },
      {
        name: 'owner',
        label: 'Owner',
        type: 'text',
        value: profile.owner || '',
        hint: 'Equipe ou responsável operacional.',
      },
      {
        name: 'business_service',
        label: 'Business service / aplicação',
        type: 'text',
        value: profile.business_service || '',
      },
      {
        name: 'environment',
        label: 'Environment',
        type: 'text',
        value: profile.environment || '',
        hint: 'Ex.: prod, staging, dev, lab.',
      },
      {
        name: 'reason',
        label: 'Motivo da alteração',
        type: 'textarea',
        required: true,
        minLength: 5,
        wide: true,
        hint: 'A alteração gera audit event e snapshot de Asset Risk.',
      },
    ],
    onSubmit: async (values) => {
      const criticalityRaw = String(values.criticality || '').trim();
      const criticality = criticalityRaw === '' ? null : Number(criticalityRaw);
      if (criticality !== null && (!Number.isInteger(criticality) || criticality < 1 || criticality > 5)) {
        throw new Error('Criticidade precisa ficar entre 1 e 5.');
      }

      const exposureValue = String(values.exposure || 'auto').trim().toLowerCase();
      const external = exposureValue === 'auto' ? null : exposureValue === 'externo';

      const controlsRaw = String(values.controls || '').trim();
      let compensatingControls = null;
      if (controlsRaw.toLowerCase() !== 'auto' && controlsRaw !== '') {
        compensatingControls = controlsRaw
          .split(',')
          .map((value) => value.trim().toLowerCase())
          .filter(Boolean);
      }

      const reason = String(values.reason || '').trim();
      if (reason.length < 5) throw new Error('Informe um motivo com pelo menos 5 caracteres.');

      await api('/api/admin/agents/' + agentId + '/risk-profile', {
        method: 'PUT',
        body: JSON.stringify({
          criticality,
          external,
          compensating_controls: compensatingControls,
          owner: String(values.owner || '').trim(),
          business_service: String(values.business_service || '').trim(),
          environment: String(values.environment || '').trim().toLowerCase(),
          reason,
        }),
      });
      toast('Perfil de risco atualizado e snapshot registrado.');
      await load();
    },
  });
};


function renderBusinessContext() {
  const report = state.businessContext || {};
  const summary = report.summary || {};
  const owner = Array.isArray(report.by_owner) ? report.by_owner.slice(0, 10) : [];
  const service = Array.isArray(report.by_business_service) ? report.by_business_service.slice(0, 10) : [];
  const environment = Array.isArray(report.by_environment) ? report.by_environment.slice(0, 10) : [];

  const stats = $('#businessContextStats');
  if (stats) {
    stats.innerHTML = [
      ['Ativos', summary.assets || 0],
      ['Owner coverage', (summary.owner_coverage_percent || 0) + '%'],
      ['Crít./alto sem owner', summary.critical_high_without_owner || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const renderTable = (targetId, items) => {
    const table = $(targetId);
    if (!table) return;
    if (!items.length) {
      table.innerHTML = '<tr><td colspan="8"><div class="empty-state">Sem dados de contexto.</div></td></tr>';
      return;
    }
    table.innerHTML = items.map((item) =>
      '<tr>' +
        '<td><strong>' + esc(item.name) + '</strong></td>' +
        '<td>' + esc(item.asset_count) + '</td>' +
        '<td><strong>' + esc(item.average_risk) + '</strong><br><small class="muted">max ' + esc(item.max_risk) + '</small></td>' +
        '<td>' + esc(item.above_appetite) + '</td>' +
        '<td>' + esc(item.untreated) + '</td>' +
        '<td>' + esc(item.governance_coverage_percent) + '%</td>' +
        '<td>' + esc(item.owner_coverage_percent) + '%</td>' +
        '<td><small>' + esc(item.open_findings) + ' findings</small></td>' +
      '</tr>'
    ).join('');
  };

  renderTable('#businessContextOwner', owner);
  renderTable('#businessContextService', service);
  renderTable('#businessContextEnvironment', environment);
}


function renderRemediationPerformance() {
  const report = state.remediationPerformance || {};
  const summary = report.summary || {};
  const stats = $('#remediationPerformanceStats');
  if (stats) {
    stats.innerHTML = [
      ['Remediados', summary.remediated_findings || 0],
      ['MTTR mediano', summary.median_mttr_hours == null ? '-' : summary.median_mttr_hours + 'h'],
      ['MTTR médio', summary.average_mttr_hours == null ? '-' : summary.average_mttr_hours + 'h'],
      ['SLA target bruto', summary.raw_sla_target_met_percent == null ? '-' : summary.raw_sla_target_met_percent + '%'],
      ['Evidência verificada', summary.verified_evidence_rate_percent == null ? '-' : summary.verified_evidence_rate_percent + '%'],
      ['Patch success', summary.patch_job_success_rate_percent == null ? '-' : summary.patch_job_success_rate_percent + '%'],
      ['Job mediano', summary.median_patch_job_minutes == null ? '-' : summary.median_patch_job_minutes + ' min'],
      ['Breaches abertos', summary.open_sla_breaches || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const table = $('#remediationPerformanceBySeverity');
  if (!table) return;
  const rows = Object.entries(report.by_severity || {});
  if (!rows.length) {
    table.innerHTML = '<tr><td colspan="4"><div class="empty-state">Sem findings remediados com tempo mensurável.</div></td></tr>';
    return;
  }
  table.innerHTML = rows.map(([severity, item]) =>
    '<tr>' +
      '<td>' + badge(severity.toUpperCase(), severity === 'critical' ? 'fail' : severity === 'high' ? 'warn' : 'info') + '</td>' +
      '<td>' + esc(item.remediated) + '</td>' +
      '<td><strong>' + esc(item.median_mttr_hours == null ? '-' : item.median_mttr_hours + 'h') + '</strong></td>' +
      '<td>' + esc(item.average_mttr_hours == null ? '-' : item.average_mttr_hours + 'h') + '</td>' +
    '</tr>'
  ).join('');
}


function renderActiveThreatWatch() {
  const report = state.activeThreatWatch || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items.slice(0, 20) : [];
  const stats = $('#activeThreatStats');
  if (stats) {
    stats.innerHTML = [
      ['CVEs', summary.cves || 0],
      ['CISA KEV', summary.kev || 0],
      ['Ransomware', summary.ransomware || 0],
      ['Ativos afetados', summary.affected_assets || 0],
      ['Exposição externa', summary.external_asset_exposures || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const table = $('#activeThreatTable');
  if (!table) return;
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="8"><div class="empty-state">Nenhuma ameaça ativa pelos sinais configurados.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((item) =>
    '<tr>' +
      '<td><strong>' + esc(item.cve) + '</strong></td>' +
      '<td>' + (item.kev ? badge('KEV', 'fail') : '') + ' ' + (item.ransomware ? badge('RANSOMWARE', 'warn') : '') + '</td>' +
      '<td><strong>' + esc(item.max_risk_score) + '/100</strong><br><small class="muted">CVSS ' + esc(item.max_cvss) + '</small></td>' +
      '<td><strong>' + esc(item.max_epss == null ? '-' : (Number(item.max_epss) * 100).toFixed(1) + '%') + '</strong></td>' +
      '<td><strong>' + esc(item.asset_count) + '</strong><br><small class="muted">' + esc(item.external_asset_count) + ' externos · ' + esc(item.critical_asset_count) + ' críticos</small></td>' +
      '<td><strong>' + esc(item.finding_count) + '</strong></td>' +
      '<td><small>' + esc((item.patch_refs || []).slice(0, 4).join(', ') || 'sem patch ref') + '</small></td>' +
      '<td><small>' + esc((item.signals || []).join(' · ')) + '</small></td>' +
    '</tr>'
  ).join('');
}




window.editPatchLifecycle = async (encodedPatchRef) => {
  if (!requireRole('admin', 'Somente admin pode alterar lifecycle do catálogo.')) return;
  const patchRef = decodeURIComponent(encodedPatchRef);
  const item = ((state.patchCatalog || {}).items || []).find(x => x.patch_ref === patchRef);
  if (!item) return;
  const lifecycle = item.lifecycle || {};
  const supersedence = item.supersedence || {};

  const classification = prompt('Classificação (ex.: cumulative, security, feature, hotfix):', lifecycle.classification || '');
  if (classification === null) return;
  const releaseDate = prompt('Release date ISO (YYYY-MM-DD) ou vazio:', lifecycle.release_date ? lifecycle.release_date.slice(0, 10) : '');
  if (releaseDate === null) return;
  const eolDate = prompt('EOL date ISO (YYYY-MM-DD) ou vazio:', lifecycle.eol_date ? lifecycle.eol_date.slice(0, 10) : '');
  if (eolDate === null) return;
  const supersedes = prompt('Supersedes (separado por vírgula):', (supersedence.supersedes || []).join(', '));
  if (supersedes === null) return;
  const reason = prompt('Motivo / fonte da atualização:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe motivo/fonte com pelo menos 5 caracteres.', 'fail');
    return;
  }

  try {
    await api('/api/admin/patch-catalog/' + encodeURIComponent(patchRef) + '/lifecycle', {
      method: 'PATCH',
      body: JSON.stringify({
        classification: classification.trim(),
        release_date: releaseDate.trim() ? new Date(releaseDate.trim() + 'T00:00:00Z').toISOString() : null,
        eol_date: eolDate.trim() ? new Date(eolDate.trim() + 'T00:00:00Z').toISOString() : null,
        supersedes: supersedes.split(',').map(x => x.trim()).filter(Boolean),
        source: 'manual',
        reason: reason.trim(),
      }),
    });
    toast('Lifecycle atualizado.');
    await load();
  } catch (error) {
    toast('Patch lifecycle: ' + error.message, 'fail');
  }
};




function renderFreezeWindows() {
  const report = state.freezeWindows || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items : [];
  const stats = $('#freezeWindowStats');
  const table = $('#freezeWindowTable');
  if (!stats || !table) return;
  stats.innerHTML = [
    ['Janelas', summary.windows || 0],
    ['Ativas agora', summary.active || 0],
    ['Habilitadas', summary.enabled || 0],
  ].map(([label, value]) => '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>').join('');
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="7"><div class="empty-state">Nenhuma change freeze configurada.</div></td></tr>';
    return;
  }
  table.innerHTML = items.map((item) =>
    '<tr>' +
      '<td><strong>' + esc(item.name) + '</strong></td>' +
      '<td>' + (item.active ? badge('ATIVA', 'fail') : item.enabled ? badge('AGENDADA', 'warn') : badge('DISABLED', 'muted-badge')) + '</td>' +
      '<td>' + esc(item.target_os || 'all') + '</td>' +
      '<td>' + esc(item.target_tag || '-') + '</td>' +
      '<td><small>' + esc(when(item.starts_at)) + '<br>→ ' + esc(when(item.ends_at)) + '</small></td>' +
      '<td><small>' + esc(item.reason) + '</small></td>' +
      '<td>' + (roleAtLeast('admin') ? '<button class="row-action" onclick="toggleFreezeWindow(\'' + esc(item.id) + '\',' + (!item.enabled) + ')">' + (item.enabled ? 'Desativar' : 'Ativar') + '</button>' : '') + '</td>' +
    '</tr>'
  ).join('');
}

window.toggleFreezeWindow = async (id, enabled) => {
  if (!requireRole('admin')) return;
  const reason = prompt('Motivo da alteração:');
  if (!reason || reason.trim().length < 5) return;
  try {
    await api('/api/admin/freeze-windows/' + encodeURIComponent(id), {
      method: 'PATCH',
      body: JSON.stringify({ enabled, reason: reason.trim() }),
    });
    toast('Freeze window atualizada.');
    await load();
  } catch (error) {
    toast('Freeze window: ' + error.message, 'fail');
  }
};



function renderAutoPatch() {
  const report = state.autoPatch || {};
  const summary = report.summary || {};
  const policies = Array.isArray(report.policies) ? report.policies : [];
  const decisions = Array.isArray(report.decisions) ? report.decisions.slice(0, 100) : [];
  const stats = $('#autoPatchStats');
  const policyTable = $('#autoPatchPolicyTable');
  const decisionTable = $('#autoPatchDecisionTable');
  const historyTable = $('#autoPatchHistoryTable');
  if (!stats || !policyTable || !decisionTable || !historyTable) return;

  stats.innerHTML = [
    ['Policies', summary.policies || 0],
    ['Decisions', summary.decisions || 0],
    ['Ready', summary.ready || 0],
    ['Blocked', summary.blocked || 0],
    ['Holds', summary.holds || 0],
    ['Drafts criados', summary.drafts_created || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  policyTable.innerHTML = policies.length ? policies.map((item) => {
    const signals = [
      item.require_kev ? 'KEV' : '',
      item.require_external ? 'external' : '',
      item.require_patch_tuesday ? 'Patch Tuesday' : '',
    ].filter(Boolean).join(' + ') || 'qualquer patch compatível';
    return '<tr>' +
      '<td><strong>' + esc(item.name) + '</strong><br><small class="muted">' + esc(item.mode) + '</small></td>' +
      '<td>' + (item.enabled ? badge('ENABLED', 'ok') : badge('DISABLED', 'muted-badge')) + '</td>' +
      '<td><small>' + esc(item.target_os || 'all') + (item.target_tag ? ' · #' + esc(item.target_tag) : '') + '</small></td>' +
      '<td><small>' + esc(signals) + '</small></td>' +
      '<td><small>confidence ≥ ' + esc(item.confidence_floor) + '<br>ring ' + esc(item.ring_percent) + '%</small></td>' +
      '<td><small>' + (item.require_approval ? 'approval ' : '') + (item.require_health_gate ? 'health ' : '') + (item.require_rollback ? 'rollback' : '') + '</small></td>' +
    '</tr>';
  }).join('') : '<tr><td colspan="6"><div class="empty-state">Nenhuma Auto Patch Policy criada.</div></td></tr>';

  decisionTable.innerHTML = decisions.length ? decisions.map((item) => {
    const status = String(item.status || '');
    const cls = status.startsWith('blocked_') ? 'fail'
      : status.startsWith('hold_') || status.startsWith('review_') ? 'warn'
      : status.includes('draft') || status === 'recommend' ? 'ok'
      : 'info';
    const signals = [
      item.kev ? 'KEV' : '',
      item.patch_tuesday ? 'Patch Tuesday' : '',
      Number(item.external_assets || 0) ? item.external_assets + ' external' : '',
    ].filter(Boolean).join(' · ') || '-';
    return '<tr>' +
      '<td><strong>' + esc(item.policy_name || '-') + '</strong></td>' +
      '<td><strong>' + esc(item.patch_ref || '-') + '</strong>' +
        (item.source_patch_ref && item.source_patch_ref !== item.patch_ref ? '<br><small class="muted">de ' + esc(item.source_patch_ref) + '</small>' : '') + '</td>' +
      '<td>' + badge(status.toUpperCase(), cls) + '</td>' +
      '<td><strong>' + esc(item.assets || 0) + '</strong></td>' +
      '<td><small>' + esc(signals) + '</small></td>' +
      '<td><small>ring ' + esc(item.ring_percent || '-') + '%<br>' +
        (item.approval_required ? 'approval · ' : '') +
        (item.health_gate_required ? 'health · ' : '') +
        (item.rollback_required ? 'rollback' : '') +
      '</small></td>' +
      '<td><small>' + esc((item.reasons || []).join(' · ')) + '</small>' +
        (item.policy_id && item.patch_ref ? '<br><button class="row-action" onclick="simulateAutoPatch(\'' + esc(item.policy_id) + '\',\'' + esc(item.patch_ref) + '\')">Simular</button>' : '') +
      '</td>' +
    '</tr>';
  }).join('') : '<tr><td colspan="7"><div class="empty-state">Nenhuma decisão gerada pelas policies atuais.</div></td></tr>';

  const history = Array.isArray(state.autoPatchHistory) ? state.autoPatchHistory : [];
  historyTable.innerHTML = history.length ? history.map((item) => {
    return '<tr>' +
      '<td><small>' + esc(when(item.created_at)) + '</small></td>' +
      '<td><strong>' + esc(item.actor || '-') + '</strong></td>' +
      '<td>' + badge(item.create_drafts ? 'DRAFT RUN' : 'SIMULATION', item.create_drafts ? 'warn' : 'info') + '</td>' +
      '<td><strong>' + esc(item.decisions || 0) + '</strong></td>' +
      '<td><small>' + esc(item.ready || 0) + ' ready · ' + esc(item.blocked || 0) + ' blocked · ' + esc(item.holds || 0) + ' holds</small></td>' +
      '<td><strong>' + esc(item.drafts_created || 0) + '</strong></td>' +
      '<td><button class="row-action" onclick="showAutoPatchHistory(\'' + esc(item.id) + '\')">Detalhes</button></td>' +
    '</tr>';
  }).join('') : '<tr><td colspan="7"><div class="empty-state">Nenhuma avaliação registrada.</div></td></tr>';
}

window.showAutoPatchHistory = async (id) => {
  try {
    const item = await api('/api/admin/auto-patch/history/' + encodeURIComponent(id));
    const result = item.result || {};
    const summary = result.summary || {};
    const decisions = Array.isArray(result.decisions) ? result.decisions : [];
    const lines = decisions.slice(0, 30).map((x) =>
      (x.policy_name || '-') + ' · ' + (x.patch_ref || '-') + ' · ' + (x.status || '-') +
      ' · ' + ((x.reasons || []).join(' / ') || '-')
    );
    alert(
      'Auto Patch Evaluation\n\n' +
      'Ator: ' + (item.actor || '-') + '\n' +
      'Data: ' + (item.created_at ? when(item.created_at) : '-') + '\n' +
      'Policies: ' + (summary.policies || 0) + '\n' +
      'Decisions: ' + (summary.decisions || 0) + '\n' +
      'Drafts: ' + (summary.drafts_created || 0) + '\n\n' +
      lines.join('\n')
    );
  } catch (error) {
    toast('Decision ledger: ' + error.message, 'fail');
  }
};

window.simulateAutoPatch = async (policyId, patchRef) => {
  try {
    const result = await api('/api/admin/auto-patch/simulate', {
      method: 'POST',
      body: JSON.stringify({ policy_id: policyId, patch_ref: patchRef }),
    });
    const scope = result.scope || {};
    const p = result.preconditions || {};
    const d = result.decision || {};
    alert(
      'Auto Patch Simulation\n\n' +
      'Policy: ' + ((result.policy || {}).name || '-') + '\n' +
      'Patch: ' + ((result.patch || {}).patch_ref || '-') + '\n\n' +
      'Missing total: ' + (scope.missing_total || 0) + '\n' +
      'Excluded OS: ' + (scope.excluded_os || 0) + '\n' +
      'Excluded tag: ' + (scope.excluded_tag || 0) + '\n' +
      'Excluded external: ' + (scope.excluded_external || 0) + '\n' +
      'Selected: ' + (scope.selected || 0) + '\n\n' +
      'Confidence: ' + (((p.confidence || {}).actual) || '-') + '\n' +
      'EOL: ' + (((p.eol || {}).state) || '-') + '\n' +
      'Decision: ' + (d.status || 'not matched') + '\n' +
      'Reasons: ' + ((d.reasons || []).join(' · ') || '-')
    );
  } catch (error) {
    toast('Auto Patch Simulation: ' + error.message, 'fail');
  }
};

window.runAutoPatch = async (createDrafts) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  try {
    const result = await api('/api/admin/auto-patch/evaluate?create_drafts=' + (createDrafts ? 'true' : 'false'), { method: 'POST' });
    toast(createDrafts
      ? ('Policy engine executado: ' + Number((result.summary || {}).drafts_created || 0) + ' draft(s) criado(s).')
      : 'Policy engine avaliado em modo recomendação.');
    await load();
  } catch (error) {
    toast('Auto Patch Policy: ' + error.message, 'fail');
  }
};

function renderPatchFeeds() {
  const report = state.patchFeeds || {};
  const summary = report.summary || {};
  const providers = Array.isArray(report.providers) ? report.providers : [];
  const stats = $('#patchFeedStats');
  const table = $('#patchFeedTable');
  if (!stats || !table) return;

  stats.innerHTML = [
    ['Providers', summary.providers || 0],
    ['Enabled', summary.enabled || 0],
    ['Healthy', summary.healthy || 0],
    ['Degraded', summary.degraded || 0],
    ['Circuit open', summary.circuit_open || 0],
    ['Records', summary.records || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  if (!providers.length) {
    table.innerHTML = '<tr><td colspan="8"><div class="empty-state">Nenhum provider configurado. O core está pronto para curated/vendor adapters.</div></td></tr>';
    return;
  }

  table.innerHTML = providers.map((item) => {
    const status = item.circuit_open
      ? badge('CIRCUIT OPEN', 'fail')
      : item.last_error
        ? badge('DEGRADED', 'warn')
        : item.enabled
          ? badge('HEALTHY', 'ok')
          : badge('DISABLED', 'muted-badge');
    const actions = roleAtLeast('operator')
      ? '<button class="row-action" onclick="syncPatchFeed(\'' + esc(item.id) + '\')">Sync</button>' +
        (item.circuit_open && roleAtLeast('admin') ? ' <button class="row-action" onclick="resetPatchFeedCircuit(\'' + esc(item.id) + '\')">Reset circuit</button>' : '')
      : '';
    return '<tr>' +
      '<td><strong>' + esc(item.name) + '</strong><br><small class="muted">' + esc(item.provider_type) + '</small>' +
        (item.adapter_state && Object.keys(item.adapter_state).length ? '<br>' + badge('CACHE', 'info') : '') + '</td>' +
      '<td>' + status + '</td>' +
      '<td><strong>' + esc(item.priority) + '</strong><br><small class="muted">TTL ' + esc(item.ttl_hours) + 'h</small></td>' +
      '<td><small>' + esc(item.interval_seconds) + 's<br>' + esc(item.failure_threshold) + ' falhas → ' + esc(item.cooldown_seconds) + 's cooldown</small></td>' +
      '<td><strong>' + esc(item.record_count) + '</strong></td>' +
      '<td><small>' + esc(item.last_success_at ? when(item.last_success_at) : 'nunca') + '</small></td>' +
      '<td><small>' + esc(item.last_error || '-') + '</small></td>' +
      '<td>' + actions + '</td>' +
    '</tr>';
  }).join('');
}

window.syncPatchFeed = async (id) => {
  if (!requireRole('operator')) return;
  try {
    await api('/api/admin/patch-feeds/' + encodeURIComponent(id) + '/sync', { method: 'POST' });
    toast('Feed sincronizado.');
    await load();
  } catch (error) {
    toast('Feed sync: ' + error.message, 'fail');
  }
};

window.resetPatchFeedCircuit = async (id) => {
  if (!requireRole('admin')) return;
  try {
    await api('/api/admin/patch-feeds/' + encodeURIComponent(id) + '/circuit/reset', { method: 'POST' });
    toast('Circuit breaker resetado.');
    await load();
  } catch (error) {
    toast('Circuit reset: ' + error.message, 'fail');
  }
};


function renderPatchCatalog() {
  const report = state.patchCatalog || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items.slice(0, 100) : [];
  const stats = $('#patchCatalogStats');
  const table = $('#patchCatalogTable');
  if (!stats || !table) return;

  stats.innerHTML = [
    ['Patches', summary.patches || 0],
    ['Missing', summary.missing_observations || 0],
    ['Installed inferred', summary.installed_inferred || 0],
    ['Bloqueadas', summary.blocked || 0],
    ['Superseded', summary.superseded || 0],
    ['EOL', summary.eol || 0],
    ['Patch Tuesday', summary.patch_tuesday || 0],
    ['Metadata stale', summary.stale_metadata || 0],
    ['Conflitos', summary.metadata_conflicts || 0],
    ['Ready', summary.ready || 0],
    ['Pilot', summary.pilot || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  if (!items.length) {
    table.innerHTML = '<tr><td colspan="9"><div class="empty-state">O catálogo será populado pelos heartbeats dos agentes.</div></td></tr>';
    return;
  }

  const readinessBadge = (value) => {
    if (value === 'blocked') return badge('BLOCKED', 'fail');
    if (value === 'review') return badge('REVIEW', 'fail');
    if (value === 'superseded') return badge('SUPERSEDED', 'muted-badge');
    if (value === 'pilot') return badge('PILOT', 'warn');
    if (value === 'ready_with_controls') return badge('READY + CONTROLS', 'warn');
    if (value === 'ready') return badge('READY', 'ok');
    return badge('N/A', 'muted-badge');
  };

  table.innerHTML = items.map((item) => {
    const states = item.states || {};
    const threat = item.threat || {};
    const readiness = item.deployment_readiness || {};
    const confidence = item.patch_confidence || {};
    const guard = item.guard || {};
    const lifecycle = item.lifecycle || {};
    const supersedence = item.supersedence || {};
    const enrichment = item.enrichment || {};
    const affected = (item.affected_assets || []).slice(0, 3).map(x => esc(x.hostname)).join('<br>');
    return '<tr>' +
      '<td><strong>' + esc(item.patch_ref) + '</strong><br><small class="muted">' + esc(item.title || item.product || '-') + '</small></td>' +
      '<td><small>' + esc(item.vendor || '-') + '<br>' + esc(item.product || '-') +
        (lifecycle.classification ? '<br>' + badge(String(lifecycle.classification).toUpperCase(), 'info') : '') + '</small></td>' +
      '<td>' + badge(String(item.severity || 'unknown').toUpperCase(), ['critical','important'].includes(String(item.severity || '').toLowerCase()) ? 'fail' : 'info') +
        (lifecycle.patch_tuesday ? '<br>' + badge('PATCH TUESDAY', 'info') : '') +
        (lifecycle.eol_state === 'eol' ? '<br>' + badge('EOL', 'fail') : lifecycle.eol_state === 'eol_soon' ? '<br>' + badge('EOL SOON', 'warn') : '') + '</td>' +
      '<td><strong>' + esc(states.missing || 0) + '</strong><br><small class="muted">' + affected + '</small></td>' +
      '<td><strong>' + esc(states.installed_inferred || 0) + '</strong><br><small class="muted">' + esc(states.no_longer_reported || 0) + ' não reportado(s)</small></td>' +
      '<td><small>' + esc((threat.cves || []).slice(0, 4).join(', ') || '-') +
        (threat.kev_findings ? '<br>' + badge(threat.kev_findings + ' KEV', 'fail') : '') +
        (threat.ransomware_findings ? ' ' + badge(threat.ransomware_findings + ' ransomware', 'warn') : '') + '</small></td>' +
      '<td><strong>' + esc(confidence.confidence || 'insufficient_data') + '</strong><br><small class="muted">' + esc(confidence.success_rate == null ? '-' : confidence.success_rate + '%') + '</small></td>' +
      '<td><small>' +
        (supersedence.obsolete ? badge('OBSOLETA', 'muted-badge') : badge('LEAF', 'ok')) +
        (enrichment.stale ? ' ' + badge('STALE META', 'warn') : '') +
        ((enrichment.conflicts || []).length ? ' ' + badge((enrichment.conflicts || []).length + ' CONFLICT', 'fail') : '') +
        (supersedence.preferred_replacement ? '<br>→ ' + esc(supersedence.preferred_replacement) : '') +
        '<br>' + esc(lifecycle.release_age_days == null ? 'idade desconhecida' : lifecycle.release_age_days + 'd') +
        '</small></td>' +
      '<td>' + (guard.blocked ? badge('PATCH GUARD', 'fail') : badge('livre', 'ok')) + '</td>' +
      '<td>' + readinessBadge(readiness.status) + '<br><small class="muted">' + esc((readiness.reasons || []).join(' · ')) + '</small>' +
        (roleAtLeast('admin') ? '<br><button class="row-action" onclick="editPatchLifecycle(\'' + encodeURIComponent(item.patch_ref).replace(/'/g, '%27') + '\')">Lifecycle</button>' : '') +
      '</td>' +
    '</tr>';
  }).join('');
}


function renderPatchConfidence() {
  const report = state.patchConfidence || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items.slice(0, 25) : [];
  const stats = $('#patchConfidenceStats');
  if (stats) {
    stats.innerHTML = [
      ['Patches observados', summary.patches_observed || 0],
      ['Alta confiança', summary.high_confidence || 0],
      ['Baixa confiança', summary.low_confidence || 0],
      ['Dados insuficientes', summary.insufficient_data || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const table = $('#patchConfidenceTable');
  if (!table) return;
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="8"><div class="empty-state">Ainda não há histórico suficiente de install_updates.</div></td></tr>';
    return;
  }

  const confidenceBadge = (value) => {
    if (value === 'high') return badge('ALTA', 'ok');
    if (value === 'medium') return badge('MÉDIA', 'warn');
    if (value === 'low') return badge('BAIXA', 'fail');
    return badge('DADOS INSUFICIENTES', 'muted-badge');
  };

  table.innerHTML = items.map((item) =>
    '<tr>' +
      '<td><strong>' + esc(item.patch_ref) + '</strong></td>' +
      '<td>' + confidenceBadge(item.confidence) + '</td>' +
      '<td><strong>' + esc(item.success_rate == null ? '-' : item.success_rate + '%') + '</strong></td>' +
      '<td>' + esc(item.completed_jobs) + '</td>' +
      '<td>' + esc(item.success) + '</td>' +
      '<td>' + esc(item.failed) + '</td>' +
      '<td>' + esc(item.stalled) + ' / ' + esc(item.blocked) + '</td>' +
      '<td><small>' + esc(item.asset_count) + ' ativos · ' + esc(item.campaign_count) + ' campanhas</small></td>' +
    '</tr>'
  ).join('');
}


function renderRemediationHub() {
  const report = state.remediationHub || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items.slice(0, 25) : [];

  const stats = $('#remediationHubStats');
  if (stats) {
    stats.innerHTML = [
      ['Grupos', summary.remediation_groups || 0],
      ['Findings cobertos', summary.findings_covered || 0],
      ['Ativos cobertos', summary.assets_covered || 0],
      ['P0 / P1', String(summary.priority_p0 || 0) + ' / ' + String(summary.priority_p1 || 0)],
      ['Change risk alto', summary.high_change_risk || 0],
      ['Cruza appetite', summary.appetite_crossings || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const table = $('#remediationHubTable');
  if (!table) return;
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="10"><div class="empty-state">Sem grupos de remediação com patch reference conhecida.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((item, index) => {
    const cves = Array.isArray(item.cves) ? item.cves : [];
    const osFamilies = Array.isArray(item.os_families) ? item.os_families : [];
    const assets = Array.isArray(item.affected_assets) ? item.affected_assets : [];
    const topAssets = assets.slice(0, 3).map((asset) =>
      esc(asset.hostname) + ' (-' + esc(asset.risk_reduction) + ')'
    ).join('<br>');
    const encodedPatchRef = encodeURIComponent(item.patch_ref).replace(/'/g, '%27');
    const priority = item.priority || {};
    const changeRisk = item.change_risk || {};
    const guidance = item.deployment_guidance || {};
    const signals = item.threat_sla || {};
    const ringPlan = Array.isArray(guidance.ring_plan) ? guidance.ring_plan : [guidance.suggested_ring_percent || '-'];
    const priorityClass = priority.tier === 'P0' ? 'fail' : priority.tier === 'P1' ? 'warn' : priority.tier === 'P2' ? 'info' : 'muted-badge';
    const changeClass = changeRisk.level === 'high' ? 'fail' : changeRisk.level === 'medium' ? 'warn' : 'ok';
    const priorityDetail = [
      signals.kev_findings ? signals.kev_findings + ' KEV' : '',
      signals.ransomware_findings ? signals.ransomware_findings + ' ransomware' : '',
      signals.sla_breached ? signals.sla_breached + ' SLA vencido' : '',
      signals.external_assets ? signals.external_assets + ' externo(s)' : '',
    ].filter(Boolean).join(' · ') || 'sem sinal crítico adicional';
    const campaignButton = roleAtLeast('operator')
      ? '<button class="row-action" onclick="prepareCampaignFromRemediationGroup(\'' + encodedPatchRef + '\')">Preparar campanha</button>' +
        ' <button class="row-action" onclick="createRemediationProjectFromHub(\'' + encodedPatchRef + '\')">Criar projeto</button>'
      : '<small class="muted">somente análise</small>';

    return '<tr>' +
      '<td><strong>#' + esc(index + 1) + '</strong></td>' +
      '<td><strong>' + esc(item.patch_ref) + '</strong><br><small class="muted">' + esc(osFamilies.join(', ') || '-') + '</small>' +
        (item.patch_confidence ? '<br><small class="muted">confidence ' + esc(item.patch_confidence.confidence) + (item.patch_confidence.success_rate == null ? '' : ' · ' + esc(item.patch_confidence.success_rate) + '%') + '</small>' : '') +
      '</td>' +
      '<td><strong>' + esc(item.finding_count) + '</strong><br><small class="muted">' + esc(item.cve_count) + ' CVEs</small></td>' +
      '<td><strong>' + esc(item.asset_count) + '</strong><br><small class="muted">' + topAssets + '</small></td>' +
      '<td><strong>' + esc(item.before_risk_total) + ' → ' + esc(item.projected_risk_total) + '</strong></td>' +
      '<td><strong>-' + esc(item.risk_reduction) + '</strong><br><small class="muted">' + esc(item.reduction_percent) + '%</small></td>' +
      '<td><strong>' + esc(item.appetite_crossings) + '</strong></td>' +
      '<td>' + badge(priority.tier || 'P3', priorityClass) +
        ' ' + badge('change ' + (changeRisk.level || 'low'), changeClass) +
        '<br><small class="muted">' + esc(priorityDetail) + '</small></td>' +
      '<td><small>' + esc(cves.slice(0, 4).join(', ') || '-') + (cves.length > 4 ? ' +' + esc(cves.length - 4) : '') +
        '<br><span class="muted">' + esc(guidance.mode || '-') +
        ' · rings ' + esc(ringPlan.join(' → ')) + '%</span></small></td>' +
      '<td>' + campaignButton + '</td>' +
    '</tr>';
  }).join('');
}


function remediationProjectBadge(status) {
  if (status === 'completed' || status === 'achieved') return badge('CONCLUÍDO', 'ok');
  if (status === 'awaiting_verification') return badge('AGUARDANDO VERIFICAÇÃO', 'warn');
  if (status === 'overdue') return badge('VENCIDO', 'fail');
  if (status === 'cancelled') return badge('CANCELADO', 'muted-badge');
  return badge('EM ANDAMENTO', 'info');
}

function remediationProjectAttentionBadge(status) {
  if (status === 'critical') return badge('CRÍTICO', 'fail');
  if (status === 'needs_attention') return badge('ATENÇÃO', 'warn');
  if (status === 'watch') return badge('OBSERVAR', 'info');
  if (status === 'completed') return badge('CONCLUÍDO', 'ok');
  if (status === 'cancelled') return badge('CANCELADO', 'muted-badge');
  return badge('NO TRACK', 'ok');
}

function renderRemediationProjects() {
  const report = state.remediationProjects || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items : [];
  const stats = $('#remediationProjectStats');
  const table = $('#remediationProjectTable');
  if (!stats || !table) return;

  stats.innerHTML = [
    ['Ativos', summary.active || 0],
    ['Críticos', summary.critical_attention || 0],
    ['Precisam atenção', summary.needs_attention || 0],
    ['SLA vencido', summary.sla_breached || 0],
    ['KEV', summary.kev_findings || 0],
    ['Risco restante', Number(summary.remaining_risk_reduction || 0).toFixed(1)],
    ['Risco reduzido', Number(summary.realized_risk_reduction || 0).toFixed(1)],
    ['Findings abertos', summary.open_findings || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  if (!items.length) {
    table.innerHTML = '<tr><td colspan="10"><div class="empty-state">Nenhum Remediation Project criado.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((project) =>
    '<tr>' +
      '<td><strong>' + esc(project.name) + '</strong><br><small class="muted">' + esc(project.patch_ref) + '</small></td>' +
      '<td>' + esc(project.scope_mode) +
        (project.scope_tag ? '<br><small class="muted">tag:' + esc(project.scope_tag) + '</small>' : '') +
        ((project.scope_filter || {}).business_service ? '<br><small class="muted">service:' + esc(project.scope_filter.business_service) + '</small>' : '') +
        ((project.scope_filter || {}).environment ? '<br><small class="muted">env:' + esc(project.scope_filter.environment) + '</small>' : '') +
        ((project.scope_filter || {}).owner ? '<br><small class="muted">asset owner:' + esc(project.scope_filter.owner) + '</small>' : '') +
        ((project.scope_filter || {}).external === true ? '<br><small class="muted">external only</small>' : '') +
        ((project.scope_filter || {}).external === false ? '<br><small class="muted">internal only</small>' : '') +
        ((project.scope_filter || {}).min_criticality ? '<br><small class="muted">crit ≥ ' + esc(project.scope_filter.min_criticality) + '</small>' : '') + '</td>' +
      '<td><strong>' + esc(project.tracked_open_findings == null ? project.current_open_findings : project.tracked_open_findings) + ' / ' + esc(project.baseline_findings) + '</strong>' +
        '<br><small class="muted">' + esc(project.current_assets) + ' ativos · ' + esc(project.new_findings_since_baseline) + ' novos' +
        (project.scope_departures ? ' · ' + esc(project.scope_departures) + ' scope drift' : '') + '</small></td>' +
      '<td><strong>' + esc(project.realized_risk_reduction) + ' reduzido</strong>' +
        '<br><small class="muted">' + esc(project.remaining_risk_reduction) + ' restante · baseline ' + esc(project.baseline_risk_reduction) +
        ' · ' + esc(project.risk_reduction_progress_percent) + '%</small></td>' +
      '<td><strong>' + esc(project.progress_percent) + '%</strong>' +
        '<br><small class="muted">esperado ' + esc(project.expected_progress_percent) + '% · Δ ' + esc(project.schedule_variance_percent) + ' pp</small></td>' +
      '<td><strong>' + esc(project.kev_findings) + ' KEV · ' + esc(project.sla_breached) + ' SLA</strong>' +
        '<br><small class="muted">' + esc(project.external_assets) + ' externos · age máx ' + esc(project.oldest_age_days) + 'd' +
        (project.max_epss == null ? '' : ' · EPSS máx ' + esc(Math.round(Number(project.max_epss) * 100)) + '%') + '</small></td>' +
      '<td>' + remediationProjectAttentionBadge(project.attention_status) + '<br><small class="muted">' + remediationProjectBadge(project.pace_status) + '</small></td>' +
      '<td><strong>' + esc(project.owner) + '</strong></td>' +
      '<td>' + esc(when(project.due_at)) + '</td>' +
      '<td>' +
        (roleAtLeast('operator')
          ? '<button class="row-action" onclick="showRemediationProjectHistory(\'' + project.id + '\')">Histórico</button> ' +
            '<button class="row-action" onclick="editRemediationProject(\'' + project.id + '\')">Gerenciar</button>' +
            (project.campaign_ready && project.current_open_findings > 0
              ? ' <button class="row-action" onclick="prepareCampaignFromRemediationProject(\'' + project.id + '\')">Preparar campanha</button>'
              : '')
          : '') +
      '</td>' +
    '</tr>'
  ).join('');
}


function renderRiskReductionOpportunities() {
  const report = state.riskReduction || {};
  const summary = report.summary || {};
  const items = Array.isArray(report.items) ? report.items.slice(0, 10) : [];

  const stats = $('#riskReductionStats');
  if (stats) {
    stats.innerHTML = [
      ['Oportunidades', summary.opportunities || 0],
      ['Cruza appetite', summary.crosses_below_appetite || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const table = $('#riskReductionTable');
  if (!table) return;
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="8"><div class="empty-state">Sem oportunidades calculadas.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((item, index) =>
    '<tr>' +
      '<td><strong>#' + esc(index + 1) + '</strong></td>' +
      '<td><strong>' + esc(item.hostname || item.agent_id) + '</strong><br><small class="muted">' + esc(item.cve || item.finding_id) + '</small></td>' +
      '<td>' + vulnerabilityRiskBadge(item.finding_risk) + '</td>' +
      '<td><strong>' + esc(item.before_score) + ' → ' + esc(item.projected_score) + '</strong></td>' +
      '<td><strong>-' + esc(item.risk_reduction) + '</strong><br><small class="muted">' + esc(item.reduction_percent) + '%</small></td>' +
      '<td>' + (item.crosses_below_appetite ? badge('sim', 'ok') : badge('não', 'info')) + '</td>' +
      '<td><small>' + esc((item.recommendation || {}).action || '-') + '</small></td>' +
      '<td><button class="row-action" onclick="simulateFindingRiskImpact(\'' + item.finding_id + '\')">Detalhar</button></td>' +
    '</tr>'
  ).join('');
}


function remediationStatusLabel(status) {
  const labels = {
    waiting_validation: 'aguardando validação',
    rescan_requested: 'rescan solicitado',
    verified: 'remediação comprovada',
    still_detected: 'ainda detectada',
    error: 'erro no rescan',
    unsupported: 'rescan indisponível',
  };
  return labels[status] || status || 'sem evidência';
}

function remediationBadge(remediation) {
  if (!remediation) return badge('sem evidência', 'info');
  const status = remediation.status || '';
  const cls = status === 'verified'
    ? 'ok'
    : ['still_detected', 'error'].includes(status)
      ? 'fail'
      : ['waiting_validation', 'rescan_requested'].includes(status)
        ? 'warn'
        : 'info';

  const proof = remediation.evidence && remediation.evidence.verification
    ? remediation.evidence.verification
    : {};
  const titleParts = [];
  if (remediation.rescan_report_id) titleParts.push('report ' + remediation.rescan_report_id);
  if (proof.checked_at) titleParts.push('verificado ' + when(proof.checked_at));
  if (remediation.error) titleParts.push(remediation.error);

  const title = titleParts.length ? ' title="' + esc(titleParts.join(' · ')) + '"' : '';
  return '<span class="badge ' + cls + '"' + title + '>' +
    esc(remediationStatusLabel(status)) +
    '</span>';
}

function vulnerabilitySlaBadge(sla) {
  if (!sla || !sla.state) return badge('-', 'info');
  if (sla.state === 'breached') return badge('SLA vencido', 'fail');
  if (sla.state === 'due_soon') return badge('SLA próximo', 'warn');
  if (sla.state === 'within_sla') return badge('no SLA', 'ok');
  if (sla.state === 'exception') return badge('exceção SLA', 'info');
  return badge('fora do SLA ativo', 'info');
}

function renderVulnerabilities() {
  const open = state.vulnerabilities.filter((item) => item.status === 'open');
  const critical = open.filter((item) => item.severity === 'critical');
  const high = open.filter((item) => item.severity === 'high');
  const matched = open.filter((item) => item.matched);
  const unmatched = open.filter((item) => !item.matched);

  $('#vulnerabilitySummary').innerHTML = [
    ['Abertas', open.length, 'findings ativos', open.length ? 'warn' : 'ok'],
    ['Críticas', critical.length, 'CVSS / scanner', critical.length ? 'danger' : 'ok'],
    ['Altas', high.length, 'prioridade alta', high.length ? 'warn' : 'ok'],
    ['Correlacionadas', matched.length, 'com endpoint gerenciado', 'accent'],
    ['Sem endpoint', unmatched.length, 'exigem correlação', unmatched.length ? 'danger' : 'ok'],
    ['SLA vencido', open.filter((item) => item.sla && item.sla.state === 'breached').length, 'prazo de remediação excedido', open.some((item) => item.sla && item.sla.state === 'breached') ? 'danger' : 'ok'],
    ['SLA próximo', open.filter((item) => item.sla && item.sla.state === 'due_soon').length, 'vence em até 24h', open.some((item) => item.sla && item.sla.state === 'due_soon') ? 'warn' : 'ok'],
    ['Exceções SLA', open.filter((item) => item.sla && item.sla.state === 'exception').length, 'aprovação temporária', open.some((item) => item.sla && item.sla.state === 'exception') ? 'accent' : 'ok'],
    ['Risco urgente', open.filter((item) => item.risk && item.risk.level === 'urgent').length, 'score contextual ≥ 80', open.some((item) => item.risk && item.risk.level === 'urgent') ? 'danger' : 'ok'],
    ['Remediadas', state.vulnerabilities.filter((item) => item.status === 'remediated').length, 'status atual', 'ok'],
    ['Com evidência', state.vulnerabilities.filter((item) => item.remediation && item.remediation.status === 'verified').length, 'rescan pós-patch comprovado', 'ok'],
  ].map(([label, value, hint, cls]) => `
    <article class="card ${cls}">
      <span>${esc(label)}</span>
      <strong>${esc(value)}</strong>
      <small>${esc(hint)}</small>
    </article>
  `).join('');

  const items = filteredVulnerabilities();
  if (!items.length) {
    $('#vulnerabilities').innerHTML = '<tr><td colspan="11"><div class="empty-state">Nenhum finding encontrado.</div></td></tr>';
    return;
  }

  $('#vulnerabilities').innerHTML = items.map((item) => `
    <tr>
      <td><strong>${esc(item.cve || 'sem CVE')}</strong></td>
      <td>${badge(item.severity || 'unknown', vulnerabilitySeverityClass(item.severity))}</td>
      <td><strong>${Number(item.cvss || 0).toFixed(1)}</strong></td>
      <td>
        ${vulnerabilityRiskBadge(item.risk)}
        <br><small class="muted">${item.risk && item.risk.kev ? 'KEV · ' : ''}${item.risk && item.risk.epss !== null && item.risk.epss !== undefined ? 'EPSS ' + Math.round(item.risk.epss * 100) + '%' : ''}</small>
      </td>
      <td>
        ${item.matched
          ? '<strong>' + esc(item.hostname) + '</strong><br><small class="muted">' + esc(item.ip_address || item.host || '') + '</small>'
          : badge('não correlacionado', 'fail')}
      </td>
      <td>
        <strong>${esc(item.title || item.external_id)}</strong>
        <br><small class="muted">${esc(item.port || item.external_id || '')}</small>
      </td>
      <td>${badge(item.source || '-', 'info')}</td>
      <td>
        ${badge(vulnerabilityStatusLabel(item.status), item.status === 'remediated' ? 'ok' : item.status === 'open' ? 'warn' : 'info')}
        <br><span class="vuln-remediation">${remediationBadge(item.remediation)}</span>
      </td>
      <td>
        ${vulnerabilitySlaBadge(item.sla)}
        <br><small class="muted">${item.sla && item.sla.state === 'exception' && item.sla.exception ? 'até ' + when(item.sla.exception.expires_at) : item.sla && item.sla.active ? esc(String(item.sla.remaining_hours) + 'h restantes') : ''}</small>
      </td>
      <td>${when(item.last_seen)}</td>
      <td>
        ${item.status === 'open' && item.matched
          ? '<button class="row-action" onclick="simulateFindingRiskImpact(\'' + item.id + '\')">Simular impacto</button>'
          : ''}
        ${item.status === 'open' && item.matched && roleAtLeast('operator')
          ? '<button class="row-action" onclick="prepareCampaignFromFinding(\'' + item.id + '\')">Criar campanha</button>'
          : ''}
        ${item.status === 'open' && roleAtLeast('admin') && (!item.sla || item.sla.state !== 'exception')
          ? '<button class="row-action" onclick="createSlaException(\'' + item.id + '\')">Criar exceção SLA</button>'
          : ''}
        ${item.status === 'open' && roleAtLeast('admin') && item.sla && item.sla.state === 'exception' && item.sla.exception
          ? '<button class="row-action" onclick="revokeSlaException(\'' + item.id + '\', \'' + item.sla.exception.id + '\')">Revogar exceção</button>'
          : ''}
        ${item.remediation && ['error','still_detected'].includes(item.remediation.status) && roleAtLeast('operator')
          ? '<button class="row-action" onclick="retryRemediationRescan(\'' + item.remediation.id + '\')">Novo rescan</button>'
          : ''}
      </td>
    </tr>
  `).join('');
}

window.simulateFindingRiskImpact = async (findingId) => {
  const finding = state.vulnerabilities.find((item) => item.id === findingId);
  if (!finding || !finding.agent_id) {
    toast('Finding não correlacionado a um ativo.', 'fail');
    return;
  }

  try {
    const result = await api('/api/admin/agents/' + finding.agent_id + '/risk-simulation', {
      method: 'POST',
      body: JSON.stringify({ finding_ids: [findingId] }),
    });
    const before = result.before || {};
    const after = result.after || {};
    const impact = result.impact || {};
    const target = $('#riskSimulationResult');
    if (target) {
      target.innerHTML =
        '<div><span>Ativo</span><strong>' + esc((result.asset || {}).hostname || finding.hostname || finding.agent_id) + '</strong></div>' +
        '<div><span>Score atual</span><strong>' + esc(before.score == null ? '-' : before.score) + '</strong></div>' +
        '<div><span>Score projetado</span><strong>' + esc(after.score == null ? '-' : after.score) + '</strong></div>' +
        '<div><span>Redução</span><strong>' + esc((impact.delta || 0) + ' (' + (impact.reduction_percent || 0) + '%)') + '</strong></div>' +
        '<div><span>Apetite</span><strong>' + esc(result.risk_appetite == null ? '-' : result.risk_appetite) + '</strong></div>' +
        '<div><span>Cruza abaixo</span><strong>' + esc(impact.crosses_below_appetite ? 'sim' : 'não') + '</strong></div>';
    }
    toast('Simulação calculada. Nenhum finding foi alterado.');
  } catch (error) {
    toast('Simulação de risco: ' + error.message, 'fail');
  }
};


window.createSlaException = async (findingId) => {
  if (!requireRole('admin', 'Perfil admin necessário.')) return;
  const reason = prompt('Motivo da exceção de SLA:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }
  const daysRaw = prompt('Validade da exceção em dias:', '7');
  const days = Number(daysRaw);
  if (!Number.isFinite(days) || days <= 0 || days > 365) {
    toast('Informe uma validade entre 1 e 365 dias.', 'fail');
    return;
  }
  const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
  try {
    await api('/api/admin/vulnerabilities/' + findingId + '/sla-exceptions', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim(), expires_at: expiresAt }),
    });
    toast('Exceção de SLA aprovada.');
    await load();
  } catch (error) {
    toast('Exceção SLA: ' + error.message, 'fail');
  }
};

window.revokeSlaException = async (findingId, exceptionId) => {
  if (!requireRole('admin', 'Perfil admin necessário.')) return;
  const reason = prompt('Motivo da revogação da exceção:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }
  try {
    await api('/api/admin/vulnerabilities/' + findingId + '/sla-exceptions/' + exceptionId + '/revoke', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim() }),
    });
    toast('Exceção de SLA revogada.');
    await load();
  } catch (error) {
    toast('Revogação SLA: ' + error.message, 'fail');
  }
};

window.retryRemediationRescan = async (evidenceId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const reason = prompt('Motivo para solicitar um novo rescan Greenbone:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }

  try {
    await api('/api/admin/remediation-evidence/' + evidenceId + '/rescan', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim() }),
    });
    toast('Novo rescan solicitado ao Greenbone.');
    await load();
  } catch (error) {
    toast('Rescan: ' + error.message, 'fail');
  }
};

window.showRemediationProjectHistory = async (projectId) => {
  try {
    const result = await api('/api/admin/remediation-projects/' + projectId + '/history?limit=200');
    const target = $('#remediationProjectHistory');
    if (!target) return;
    const items = Array.isArray(result.items) ? result.items.slice().reverse() : [];
    if (!items.length) {
      target.innerHTML = '<div class="empty-state">Sem snapshots para este projeto.</div>';
      return;
    }
    target.innerHTML =
      '<div><span>Projeto</span><strong>' + esc(result.project_name || projectId) + '</strong></div>' +
      '<div><span>Snapshots</span><strong>' + esc(items.length) + '</strong></div>' +
      '<div class="table-wrap"><table><thead><tr>' +
        '<th>Data</th><th>Backlog</th><th>Progresso</th><th>Esperado</th><th>Δ schedule</th><th>Risco restante</th><th>Risco reduzido</th><th>KEV</th><th>SLA</th><th>Externos</th><th>Aging</th><th>Atenção</th><th>Pace</th><th>Origem</th>' +
      '</tr></thead><tbody>' +
      items.map((item) =>
        '<tr>' +
          '<td>' + esc(shortWhen(item.captured_at)) + '</td>' +
          '<td><strong>' + esc(item.tracked_open_findings) + '</strong><br><small class="muted">' + esc(item.current_scope_findings) + ' escopo · ' + esc(item.new_findings_since_baseline) + ' novos</small></td>' +
          '<td><strong>' + esc(item.progress_percent) + '%</strong></td>' +
          '<td>' + esc(item.expected_progress_percent) + '%</td>' +
          '<td>' + esc(item.schedule_variance_percent) + ' pp</td>' +
          '<td><strong>' + esc(item.remaining_risk_reduction) + '</strong></td>' +
          '<td><strong>' + esc(item.realized_risk_reduction) + '</strong><br><small class="muted">' + esc(item.risk_reduction_progress_percent) + '%</small></td>' +
          '<td>' + esc(item.kev_findings) + '</td>' +
          '<td>' + esc(item.sla_breached) + '</td>' +
          '<td>' + esc(item.external_assets) + '</td>' +
          '<td>' + esc(item.average_age_days) + 'd / ' + esc(item.oldest_age_days) + 'd</td>' +
          '<td>' + remediationProjectAttentionBadge(item.attention_status) + '</td>' +
          '<td>' + remediationProjectBadge(item.pace_status) + '</td>' +
          '<td><small>' + esc(item.source || '-') + '</small></td>' +
        '</tr>'
      ).join('') +
      '</tbody></table></div>';
    toast('Histórico do Remediation Project carregado.');
  } catch (error) {
    toast('Histórico do projeto: ' + error.message, 'fail');
  }
};


window.createRemediationProjectFromHub = async (encodedPatchRef) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const patchRef = decodeURIComponent(encodedPatchRef);
  const group = ((state.remediationHub || {}).items || []).find((item) => item.patch_ref === patchRef);
  if (!group) {
    toast('Grupo de remediação não encontrado.', 'fail');
    return;
  }
  const due = new Date(Date.now() + 30 * 86400000);
  const localDue = new Date(due.getTime() - due.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

  openGovernanceModal({
    kicker: 'REMEDIATION PROJECT',
    title: 'Criar projeto · ' + patchRef,
    context: String(group.finding_count || 0) + ' findings · ' + String(group.asset_count || 0) + ' ativos · redução projetada ' + String(group.risk_reduction || 0) + ' · filtros de escopo ficam congelados como regra do projeto',
    submitLabel: 'Criar projeto',
    fields: [
      { name: 'name', label: 'Nome', type: 'text', value: 'Remediação · ' + patchRef, required: true, minLength: 3 },
      {
        name: 'scope_mode',
        label: 'Escopo',
        type: 'select',
        value: 'static',
        options: [
          { value: 'static', label: 'Static · congela findings atuais' },
          { value: 'dynamic', label: 'Dynamic · inclui novos findings da mesma patch/tag' },
        ],
      },
      { name: 'scope_tag', label: 'Tag adicional', type: 'text', hint: 'Opcional. Restringe o projeto aos ativos com essa tag.' },
      { name: 'scope_business_service', label: 'Business service', type: 'text', hint: 'Opcional. Usa o contexto explícito do Asset Accountability.' },
      { name: 'scope_environment', label: 'Environment', type: 'text', hint: 'Opcional. Ex.: production, staging, lab.' },
      { name: 'scope_owner', label: 'Asset owner', type: 'text', hint: 'Opcional. Filtra pelo owner do ativo, não pelo owner do projeto.' },
      {
        name: 'scope_external',
        label: 'Exposição',
        type: 'select',
        value: '',
        options: [
          { value: '', label: 'Qualquer exposição' },
          { value: 'true', label: 'Somente externos' },
          { value: 'false', label: 'Somente internos' },
        ],
      },
      {
        name: 'scope_min_criticality',
        label: 'Criticidade mínima',
        type: 'select',
        value: '',
        options: [
          { value: '', label: 'Qualquer criticidade' },
          { value: '1', label: '1+' },
          { value: '2', label: '2+' },
          { value: '3', label: '3+' },
          { value: '4', label: '4+' },
          { value: '5', label: '5' },
        ],
      },
      { name: 'owner', label: 'Owner do projeto', type: 'text', required: true, minLength: 2 },
      { name: 'due_at', label: 'Prazo', type: 'datetime-local', value: localDue, required: true },
      { name: 'reason', label: 'Objetivo / contexto', type: 'textarea', required: true, minLength: 5, wide: true },
    ],
    onSubmit: async (values) => {
      await api('/api/admin/remediation-projects', {
        method: 'POST',
        body: JSON.stringify({
          name: String(values.name || '').trim(),
          patch_ref: patchRef,
          scope_mode: String(values.scope_mode || 'static'),
          scope_tag: String(values.scope_tag || '').trim().toLowerCase(),
          scope_business_service: String(values.scope_business_service || '').trim() || null,
          scope_environment: String(values.scope_environment || '').trim() || null,
          scope_owner: String(values.scope_owner || '').trim() || null,
          scope_external: values.scope_external === '' ? null : String(values.scope_external) === 'true',
          scope_min_criticality: values.scope_min_criticality === '' ? null : Number(values.scope_min_criticality),
          owner: String(values.owner || '').trim(),
          due_at: new Date(values.due_at).toISOString(),
          reason: String(values.reason || '').trim(),
        }),
      });
      toast('Remediation Project criado.');
      await load();
    },
  });
};

window.editRemediationProject = async (projectId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const project = ((state.remediationProjects || {}).items || []).find((item) => item.id === projectId);
  if (!project) return;
  const due = new Date(project.due_at);
  const localDue = new Date(due.getTime() - due.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

  openGovernanceModal({
    kicker: 'REMEDIATION PROJECT',
    title: 'Gerenciar · ' + project.name,
    context: project.patch_ref + ' · ' + (project.tracked_open_findings == null ? project.current_open_findings : project.tracked_open_findings) + ' findings rastreados abertos · ' + project.progress_percent + '% concluído',
    submitLabel: 'Salvar projeto',
    fields: [
      { name: 'owner', label: 'Owner', type: 'text', value: project.owner, required: true, minLength: 2 },
      { name: 'due_at', label: 'Prazo', type: 'datetime-local', value: localDue, required: true },
      {
        name: 'status',
        label: 'Status',
        type: 'select',
        value: project.status,
        options: [
          { value: 'active', label: 'Em andamento' },
          { value: 'awaiting_verification', label: 'Aguardando verificação' },
          { value: 'completed', label: 'Concluído (exige zero findings abertos)' },
          { value: 'cancelled', label: 'Cancelado' },
        ],
      },
      { name: 'reason', label: 'Motivo da alteração', type: 'textarea', required: true, minLength: 5, wide: true },
    ],
    onSubmit: async (values) => {
      await api('/api/admin/remediation-projects/' + projectId, {
        method: 'PUT',
        body: JSON.stringify({
          owner: String(values.owner || '').trim(),
          due_at: new Date(values.due_at).toISOString(),
          status: String(values.status || 'active'),
          reason: String(values.reason || '').trim(),
        }),
      });
      toast('Remediation Project atualizado.');
      await load();
    },
  });
};

window.prepareCampaignFromRemediationProject = (projectId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const project = ((state.remediationProjects || {}).items || []).find((item) => item.id === projectId);
  if (!project || !project.campaign_ready) {
    toast('Projeto sem população elegível para campanha.', 'fail');
    return;
  }
  const agentIds = Array.isArray(project.current_agent_ids) ? project.current_agent_ids : [];
  if (!agentIds.length || agentIds.length > 500) {
    toast('Projeto sem snapshot de até 500 endpoints elegíveis.', 'fail');
    return;
  }

  const form = $('#campaignForm');
  state.campaignTargetAgentIds = [...agentIds];
  form.elements.target_agent_id.value = '';
  form.elements.target_finding_id.value = '';
  form.elements.name.value = project.name + ' · campanha';
  const families = [...new Set(agentIds.map((id) => {
    const agent = state.agents.find((item) => item.id === id);
    return agent ? agent.os_family : null;
  }).filter(Boolean))];
  form.elements.target_os.value = families.length === 1 ? families[0] : 'all';
  form.elements.target_tag.value = '';
  const group = ((state.remediationHub || {}).items || []).find((item) => item.patch_ref === project.patch_ref);
  const guidance = group ? (group.deployment_guidance || {}) : {};
  form.elements.ring_percent.value = Number(guidance.suggested_ring_percent || (agentIds.length > 10 ? 10 : 100));
  form.elements.action.value = 'install_updates';
  form.elements.packages.value = project.patch_ref;
  form.elements.description.value =
    'Remediation Project ' + project.name +
    ' · ' + project.scope_mode + ' scope' +
    ' · ' + String(project.current_open_findings || 0) + ' findings abertos' +
    ' · ' + String(agentIds.length) + ' endpoints exatos' +
    ' · owner ' + project.owner +
    ' · revisão humana obrigatória antes do deploy';

  const context = $('#campaignSourceContext');
  context.hidden = false;
  context.innerHTML =
    '<strong>Origem da campanha</strong>' +
    '<span>Remediation Project · ' + esc(project.name) +
    ' · ' + esc(agentIds.length) + ' endpoints exatos · patch ' + esc(project.patch_ref) + '</span>';

  setView('campaigns');
  form.scrollIntoView({ behavior: 'smooth', block: 'start' });
  toast('Draft pré-preenchido a partir do projeto. Revise ring, janela e health gate.');
};


window.prepareCampaignFromRemediationGroup = (encodedPatchRef) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const patchRef = decodeURIComponent(encodedPatchRef);
  const items = state.remediationHub && Array.isArray(state.remediationHub.items)
    ? state.remediationHub.items
    : [];
  const group = items.find((item) => item.patch_ref === patchRef);
  if (!group) {
    toast('Grupo de remediação não encontrado.', 'fail');
    return;
  }

  const assets = Array.isArray(group.affected_assets) ? group.affected_assets : [];
  const agentIds = [...new Set(assets.map((item) => item.agent_id).filter(Boolean))];
  if (!agentIds.length) {
    toast('O grupo não possui endpoints gerenciados.', 'fail');
    return;
  }
  if (agentIds.length > 500) {
    toast('O grupo excede o limite de 500 endpoints por snapshot de campanha.', 'fail');
    return;
  }

  const form = $('#campaignForm');
  state.campaignTargetAgentIds = agentIds;
  form.elements.target_agent_id.value = '';
  form.elements.target_finding_id.value = '';
  form.elements.name.value = 'Remediation Hub · ' + patchRef;
  const families = Array.isArray(group.os_families) ? group.os_families : [];
  form.elements.target_os.value = families.length === 1 ? families[0] : 'all';
  form.elements.target_tag.value = '';
  const guidance = group.deployment_guidance || {};
  form.elements.ring_percent.value = Number(guidance.suggested_ring_percent || (agentIds.length > 10 ? 10 : 100));
  form.elements.health_gate_enabled.checked = guidance.health_gate_required !== false;
  form.elements.health_gate_require_telemetry.checked = guidance.health_gate_required !== false;
  form.elements.prepare_rollback.checked = guidance.rollback_checkpoint_recommended !== false;
  form.elements.rollback_required.checked = guidance.rollback_checkpoint_required === true;
  form.elements.approval_required.checked = guidance.approval_required === true;
  form.elements.approval_reason.value = guidance.approval_required
    ? 'Remediação ' + String((group.priority || {}).tier || 'P0') + ' / change-risk ' + String((group.change_risk || {}).level || 'high')
    : '';
  form.elements.action.value = 'install_updates';
  form.elements.packages.value = patchRef;
  form.elements.description.value =
    'Remediação agrupada por patch ' + patchRef +
    ' · ' + String(group.finding_count || 0) + ' findings' +
    ' · ' + String(group.cve_count || 0) + ' CVEs' +
    ' · ' + String(agentIds.length) + ' ativos' +
    ' · redução projetada ' + String(group.risk_reduction || 0) +
    ' · prioridade ' + String((group.priority || {}).tier || 'P3') +
    ' · change-risk ' + String((group.change_risk || {}).level || 'low') +
    ' · guidance ' + String((group.deployment_guidance || {}).mode || 'manual_review') +
    ' · rings ' + String(((group.deployment_guidance || {}).ring_plan || []).join('→') || (group.deployment_guidance || {}).suggested_ring_percent || '-') +
    ' · população congelada no momento da criação';

  const context = $('#campaignSourceContext');
  context.hidden = false;
  context.innerHTML =
    '<strong>Origem da campanha</strong>' +
    '<span>Remediation Hub · ' + esc(patchRef) +
    ' · ' + esc((group.priority || {}).tier || 'P3') +
    ' · change ' + esc((group.change_risk || {}).level || 'low') +
    ' · ' + esc(agentIds.length) + ' endpoints exatos' +
    ' · ' + esc(group.finding_count || 0) + ' findings' +
    ' · rollout ' + esc(((group.deployment_guidance || {}).ring_plan || []).join(' → ') || (group.deployment_guidance || {}).suggested_ring_percent || '-') + '%</span>';

  setView('campaigns');
  form.scrollIntoView({ behavior: 'smooth', block: 'start' });
  toast('Draft multi-asset pré-preenchido. Revise ring, janela e health gate antes de criar.');
};


window.prepareCampaignFromFinding = (findingId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  state.campaignTargetAgentIds = [];
  const finding = state.vulnerabilities.find((item) => item.id === findingId);
  if (!finding || !finding.matched || !finding.agent_id) {
    toast('O finding precisa estar correlacionado a um endpoint gerenciado.', 'fail');
    return;
  }

  const agent = state.agents.find((item) => item.id === finding.agent_id);
  if (!agent) {
    toast('Endpoint correlacionado não encontrado no inventário.', 'fail');
    return;
  }

  const form = $('#campaignForm');
  form.elements.target_agent_id.value = finding.agent_id;
  form.elements.target_finding_id.value = finding.id;
  form.elements.name.value = (finding.cve || 'Vulnerabilidade') + ' · ' + (finding.hostname || agent.hostname);
  form.elements.target_os.value = agent.os_family || 'all';
  form.elements.target_tag.value = '';
  form.elements.ring_percent.value = 100;
  form.elements.action.value = (finding.patch_refs || []).length ? 'install_updates' : 'scan_updates';
  form.elements.packages.value = (finding.patch_refs || []).join(', ');
  const recommendation = state.remediationQueue && Array.isArray(state.remediationQueue.items)
    ? state.remediationQueue.items.find((item) => item.id === finding.id)
    : null;
  const rec = recommendation ? recommendation.recommendation || {} : {};
  form.elements.description.value =
    'Remediação de ' + (finding.cve || finding.external_id) +
    ' detectada por ' + finding.source +
    ' · CVSS ' + Number(finding.cvss || 0).toFixed(1) +
    (finding.risk ? ' · risco ' + finding.risk.score + '/100' : '') +
    (rec.action ? ' · recomendação ' + rec.action : '') +
    (finding.title ? ' · ' + finding.title : '');

  const context = $('#campaignSourceContext');
  context.hidden = false;
  context.innerHTML =
    '<strong>Origem da campanha</strong>' +
    '<span>' + esc(finding.cve || finding.external_id) + ' · ' + esc(finding.hostname || finding.host) + ' · ' + esc(finding.source) + '</span>';

  setView('campaigns');
  form.scrollIntoView({ behavior: 'smooth', block: 'start' });
  toast('Campanha pré-preenchida. Revise os pacotes/KBs antes de criar.');
};

function setDrawerTab(tab) {
  state.drawerTab = tab;
  $('.drawer-tab').forEach((button) => {
    button.classList.toggle('active', button.dataset.drawerTab === tab);
  });
  $('.drawer-panel').forEach((panel) => {
    panel.classList.toggle('active', panel.dataset.drawerPanel === tab);
  });
}

function closeAgent() {
  $('#agentDrawer').classList.remove('open');
  $('#agentDrawer').setAttribute('aria-hidden', 'true');
  $('#drawerBackdrop').hidden = true;
  document.body.classList.remove('drawer-open');
}

function openAgent(id) {
  state.selectedAgentId = id;
  const agent = selectedAgent();
  if (!agent) return;
  renderAgentDrawer(agent);
  $('#drawerBackdrop').hidden = false;
  $('#agentDrawer').classList.add('open');
  $('#agentDrawer').setAttribute('aria-hidden', 'false');
  document.body.classList.add('drawer-open');
  setDrawerTab('summary');
}

function renderAgentDrawer(agent = selectedAgent()) {
  if (!agent) return;

  const risk = endpointRisk(agent);
  const patches = Array.isArray(agent.patch_scan) ? agent.patch_scan : [];
  const jobs = state.jobs.filter((job) => job.agent_id === agent.id).slice(0, 50);
  const healthSnapshot = agent.inventory && agent.inventory.health && typeof agent.inventory.health === 'object'
    ? agent.inventory.health
    : {};
  const healthServices = healthSnapshot.services && typeof healthSnapshot.services === 'object'
    ? Object.values(healthSnapshot.services)
    : [];
  const healthApps = healthSnapshot.applications && typeof healthSnapshot.applications === 'object'
    ? Object.values(healthSnapshot.applications)
    : [];
  const unhealthyChecks = [...healthServices, ...healthApps].filter((item) => item && item.healthy === false).length;
  const agentUpdate = agent.inventory && agent.inventory.update && typeof agent.inventory.update === 'object'
    ? agent.inventory.update
    : {};
  const activationState = agent.inventory && agent.inventory.activation && typeof agent.inventory.activation === 'object'
    ? agent.inventory.activation
    : {};
  const activationCapable = Boolean(
    agent.runtime
    && Array.isArray(agent.runtime.capabilities)
    && agent.runtime.capabilities.includes('signed_update_activation_v1')
  );

  $('#drawerHostname').textContent = agent.hostname || '-';
  $('#drawerSubtitle').textContent = ((agent.os_name || agent.os_family || '-') + ' ' + (agent.os_version || '')).trim();

  $('#drawerBadges').innerHTML = [
    isOnline(agent) ? badge('online', 'ok') : badge('offline', 'muted-badge'),
    badge(risk.label, risk.cls),
    agent.runtime && agent.runtime.status === 'supported'
      ? badge('agente compatível', 'ok')
      : badge('agente ' + esc(agent.runtime && agent.runtime.status ? agent.runtime.status : 'unknown'), 'fail'),
    agent.reboot_required ? badge('reboot pendente', 'warn') : '',
    agent.mtls && agent.mtls.bound
      ? badge('mTLS vinculado', 'ok')
      : agent.mtls && agent.mtls.required
        ? badge('mTLS pendente', 'fail')
        : badge('mTLS opcional', 'info'),
    ...(agent.tags || []).map((tag) => badge(tag, 'info')),
  ].join('');

  const metrics = [
    ['Updates pendentes', Number(agent.pending_updates || 0), Number(agent.pending_updates || 0) ? 'warn' : 'ok'],
    ['Críticas', Number(agent.critical_updates || 0), Number(agent.critical_updates || 0) ? 'danger' : 'ok'],
    ['Reboot', agent.reboot_required ? 'SIM' : 'não', agent.reboot_required ? 'warn' : 'ok'],
    ['Último contato', shortWhen(agent.last_seen), isOnline(agent) ? 'ok' : 'neutral'],
    ['Rollback', agent.inventory && agent.inventory.rollback && agent.inventory.rollback.checkpoint_supported ? 'disponível' : 'indisponível', agent.inventory && agent.inventory.rollback && agent.inventory.rollback.checkpoint_supported ? 'ok' : 'neutral'],
    ['CPU', healthSnapshot.cpu_percent == null ? '-' : Number(healthSnapshot.cpu_percent).toFixed(1) + '%', 'neutral'],
    ['Memória', healthSnapshot.memory_percent == null ? '-' : Number(healthSnapshot.memory_percent).toFixed(1) + '%', 'neutral'],
    ['Disco livre', healthSnapshot.disk && healthSnapshot.disk.free_percent != null ? Number(healthSnapshot.disk.free_percent).toFixed(1) + '%' : '-', 'neutral'],
    ['Checks críticos', (healthServices.length + healthApps.length) ? (unhealthyChecks ? unhealthyChecks + ' falhando' : 'OK') : '-', unhealthyChecks ? 'danger' : 'ok'],
    ['Versão agente', agent.runtime && agent.runtime.version ? agent.runtime.version : '-', agent.runtime && agent.runtime.status === 'supported' ? 'ok' : 'danger'],
    ['Protocolo', agent.runtime && agent.runtime.protocol ? agent.runtime.protocol : '-', agent.runtime && agent.runtime.protocol_supported ? 'ok' : 'danger'],
    ['Capabilities', agent.runtime && agent.runtime.capabilities ? agent.runtime.capabilities.length : 0, 'neutral'],
    ['Update agente', agentUpdate.status === 'staged' ? 'staged ' + (agentUpdate.staged_version || '') : (agentUpdate.status || '-'), agentUpdate.status === 'error' ? 'danger' : agentUpdate.status === 'staged' ? 'warn' : 'neutral'],
    ['Ativação', activationState.status || '-', activationState.status === 'committed' ? 'ok' : activationState.status === 'rolled_back' ? 'danger' : ['pending','switching'].includes(activationState.status) ? 'warn' : 'neutral'],
  ];

  $('#drawerMetrics').innerHTML = metrics.map((item) =>
    '<article class="drawer-metric ' + item[2] + '">' +
      '<span>' + esc(item[0]) + '</span>' +
      '<strong>' + esc(item[1]) + '</strong>' +
    '</article>'
  ).join('');

  $('#drawerTags').value = (agent.tags || []).join(', ');

  const activateButton = $('#activateAgentUpdate');
  if (activateButton) {
    const eligibleActivation = roleAtLeast('admin')
      && String(agent.os_family || '').toLowerCase() === 'linux'
      && agentUpdate.status === 'staged'
      && Boolean(agentUpdate.staged_version)
      && activationCapable
      && !['pending','switching','rolled_back'].includes(activationState.status);
    activateButton.hidden = !eligibleActivation;
    activateButton.disabled = !eligibleActivation;
    activateButton.textContent = eligibleActivation
      ? 'Ativar v' + agentUpdate.staged_version
      : 'Ativar update staged';
  }

  const quarantineButton = $('#clearAgentUpdateQuarantine');
  if (quarantineButton) {
    const quarantineCapable = Boolean(
      agent.runtime
      && Array.isArray(agent.runtime.capabilities)
      && agent.runtime.capabilities.includes('signed_update_quarantine_v1')
    );
    const eligibleClear = roleAtLeast('admin')
      && String(agent.os_family || '').toLowerCase() === 'linux'
      && agentUpdate.status === 'quarantined'
      && activationState.status === 'rolled_back'
      && quarantineCapable;
    quarantineButton.hidden = !eligibleClear;
    quarantineButton.disabled = !eligibleClear;
    quarantineButton.textContent = eligibleClear
      ? 'Liberar v' + (agentUpdate.quarantined_version || agentUpdate.staged_version || '')
      : 'Liberar release em quarentena';
  }

  const identity = [
    ['Agent ID', agent.id],
    ['IP', agent.ip_address || '-'],
    ['Família', agent.os_family || '-'],
    ['Arquitetura', agent.arch || '-'],
    ['mTLS', agent.mtls && agent.mtls.bound ? 'vinculado' : 'não vinculado'],
    ['Agente', agent.runtime && agent.runtime.version ? 'v' + agent.runtime.version : 'desconhecido'],
    ['Protocolo', agent.runtime && agent.runtime.protocol ? String(agent.runtime.protocol) : '-'],
    ['Capabilities', agent.runtime && agent.runtime.capabilities ? agent.runtime.capabilities.join(', ') : '-'],
    ['Fingerprint', agent.mtls && agent.mtls.fingerprint ? agent.mtls.fingerprint : '-'],
    ['Criado em', when(agent.created_at)],
    ['Último contato', when(agent.last_seen)],
  ];

  $('#drawerIdentity').innerHTML = identity.map((item) =>
    '<div><span>' + esc(item[0]) + '</span><strong>' + esc(item[1]) + '</strong></div>'
  ).join('');

  $('#drawerPatchCount').textContent = patches.length + ' item' + (patches.length === 1 ? '' : 's');

  $('#drawerPatches').innerHTML = patches.length ? patches.map((patch, index) => {
    const severity = String(patch.severity || patch.classification || '').toLowerCase();
    const severityClass = ['critical', 'important', 'security', 'high'].includes(severity) ? 'fail' : (severity ? 'warn' : 'info');
    const title = patch.title || patch.name || patch.package || patch.kb || patch.id || ('Patch ' + (index + 1));
    const details = Object.entries(patch)
      .filter(([key]) => !['title', 'name', 'severity'].includes(key))
      .slice(0, 7);

    return '<article class="patch-item">' +
      '<div class="patch-title"><strong>' + esc(title) + '</strong>' +
      (severity ? badge(severity, severityClass) : '') + '</div>' +
      '<div class="patch-details">' +
      details.map(([key, value]) => '<span><b>' + esc(key) + '</b> ' + esc(scalar(value)) + '</span>').join('') +
      '</div></article>';
  }).join('') : '<div class="empty-state good">Nenhum patch pendente reportado.</div>';

  const inventory = agent.inventory && typeof agent.inventory === 'object' ? agent.inventory : {};
  const inventoryEntries = Object.entries(inventory);

  $('#drawerInventory').innerHTML = inventoryEntries.length ? inventoryEntries.map(([key, value]) =>
    '<article class="inventory-item"><span>' + esc(key) + '</span><code>' + esc(scalar(value)) + '</code></article>'
  ).join('') : '<div class="empty-state">O agente ainda não reportou inventário.</div>';

  $('#drawerHistory').innerHTML = jobs.length ? jobs.map((job) =>
    '<article class="history-item"><div><strong>' + esc(job.campaign_name || actionLabel(job.action)) + '</strong>' +
    '<span>' + esc(actionLabel(job.action)) + ' · ' + esc(shortWhen(job.started_at || job.claimed_at || job.not_before)) +
    '</span></div>' + badge(statusLabel(job.status), jobClass(job.status)) + '</article>'
  ).join('') : '<div class="empty-state">Nenhum job registrado para este endpoint.</div>';
}

async function saveAgentTags() {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  const agent = selectedAgent();
  if (!agent) return;

  const tags = $('#drawerTags').value
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);

  try {
    const updated = await api('/api/admin/agents/' + agent.id + '/tags', {
      method: 'PUT',
      body: JSON.stringify({ tags }),
    });

    const index = state.agents.findIndex((item) => item.id === agent.id);
    if (index >= 0) state.agents[index] = updated;

    renderAgents();
    renderRiskEndpoints();
    renderAgentDrawer(updated);
    toast('Tags atualizadas.');
  } catch (error) {
    toast('Falha ao salvar tags: ' + error.message, 'fail');
  }
}



function rebootPolicyLabel(policy) {
  return policy === 'if_required' ? 'reboot se necessário' : 'sem reboot automático';
}

function maintenanceDaysLabel(days) {
  const normalized = Array.isArray(days) ? [...days].sort().join(',') : '';
  if (normalized === '0,1,2,3,4,5,6') return 'todos os dias';
  if (normalized === '0,1,2,3,4') return 'seg-sex';
  if (normalized === '5,6') return 'fim de semana';
  if (normalized === '6') return 'domingo';
  return 'dias customizados';
}


function rollbackBadge(rollback) {
  const state = rollback || {};
  const labels = {
    eligible: 'aprovação disponível',
    manual_only: 'checkpoint manual',
    requested: 'rollback solicitado',
    completed: 'rollback concluído',
    rollback_failed: 'rollback falhou',
    unavailable: 'indisponível',
    not_ready: 'aguardando',
    rollback_job: 'job de rollback',
  };
  const cls = state.status === 'eligible' || state.status === 'completed'
    ? 'ok'
    : state.status === 'rollback_failed'
      ? 'fail'
      : ['manual_only','requested','not_ready'].includes(state.status)
        ? 'warn'
        : 'info';
  return badge(labels[state.status] || state.status || 'indisponível', cls);
}

function rollbackControl(job) {
  const state = job.rollback || {};
  if (state.status === 'eligible') {
    if (roleAtLeast('admin')) {
      return '<button class="row-action danger-action" onclick="approveRollback(\'' + job.id + '\')">Aprovar rollback</button>';
    }
    return badge('admin necessário', 'warn');
  }
  return rollbackBadge(state);
}

function validationBadge(validation) {
  const status = validation && validation.status ? validation.status : 'waiting';
  const labels = {
    passed: 'validado',
    waiting: 'aguardando',
    failed: 'falhou',
    disabled: 'desativada',
  };
  const cls = status === 'passed' ? 'ok' : status === 'failed' ? 'fail' : status === 'waiting' ? 'warn' : 'info';
  const issues = validation && validation.health_validation && Array.isArray(validation.health_validation.issues)
    ? validation.health_validation.issues
    : [];
  const title = issues.length ? ' title="' + esc(issues.join('; ')) + '"' : '';
  return '<span class="badge ' + cls + '"' + title + '>' + esc(labels[status] || status) + '</span>';
}

function healthReasonLabel(reason) {
  const labels = {
    'no jobs in current ring': 'sem jobs no ring',
    'current ring has stalled jobs': 'há job travado exigindo revisão',
    'current ring has compatibility-blocked jobs': 'há job bloqueado por compatibilidade do agente',
    'current ring still has active jobs': 'jobs ainda em execução',
    'current ring has non-terminal jobs': 'jobs ainda não finalizados',
    'success rate below 90%': 'sucesso abaixo de 90%',
    'success rate below required threshold': 'sucesso abaixo do mínimo exigido',
    'agent activation confirmation timed out': 'timeout aguardando confirmação do agente',
    'post-patch validation failed': 'validação pós-patch falhou',
    'waiting for post-patch validation': 'aguardando validação pós-patch',
    'post-patch health regression or unhealthy critical check': 'regressão de saúde pós-patch',
    'waiting for post-patch health telemetry': 'aguardando telemetria de saúde',
    'agent release entered quarantine after watchdog rollback': 'release entrou em quarentena após rollback',
    'agent update was rolled back by watchdog': 'watchdog voltou para a versão anterior',
    'agent update activation failed': 'ativação do agente falhou',
    'waiting for agent activation heartbeat confirmation': 'aguardando confirmação da nova versão',
    'waiting for fresh heartbeat from activated agent': 'aguardando heartbeat novo da versão ativada',
    'healthy': 'saudável',
  };
  return labels[reason] || reason || '';
}

function nextRingPercent(current) {
  const presets = [5, 10, 30, 100];
  return presets.find((value) => value > Number(current || 0)) || null;
}


function campaignCard(campaign, compact = false) {
  const counts = campaign.job_counts || {};
  const total = Number(campaign.jobs_total || 0);
  const success = Number(counts.success || 0);
  const failed = Number(counts.failed || 0);
  const finished = success + failed + Number(counts.skipped || 0);
  const progress = total ? Math.round((finished / total) * 100) : 0;
  const health = campaign.health || {};
  const validation = health.validation || {};
  const rollout = campaign.rollout_governance || {};
  const regression = rollout.regression || {};
  const recommendation = rollout.recommendation || {};
  const nextRing = rollout.next_ring || nextRingPercent(campaign.ring_percent);
  const ringReady = rollout.state ? rollout.state === 'PROMOTE' : Boolean(health.ready);
  const healthRate = Number(health.success_rate || 0);
  const payload = campaign.payload || {};
  const healthPolicy = payload.health_policy || {};
  const isAgentRollout = payload.rollout_type === 'agent_update' || campaign.action === 'activate_agent_update';
  const approval = campaign.approval || { required: false, status: 'not_required' };
  const healthIssues = (health.validation_details || [])
    .flatMap((item) => item && item.health_validation && Array.isArray(item.health_validation.issues)
      ? item.health_validation.issues
      : [])
    .slice(0, 3);
  const windowEnabled = Boolean(payload.maintenance_start && payload.maintenance_end);
  const windowText = windowEnabled
    ? payload.maintenance_start + '–' + payload.maintenance_end + ' · ' +
      maintenanceDaysLabel(payload.maintenance_days) + ' · ' + (payload.maintenance_timezone || 'UTC')
    : 'sem janela restritiva';

  let action = '';
  const canControlCampaign = isAgentRollout ? roleAtLeast('admin') : roleAtLeast('operator');
  if (canControlCampaign && campaign.status === 'draft') {
    if (approval.required && approval.status !== 'approved') {
      if (roleAtLeast('admin') && approval.status === 'pending') {
        action = '<button onclick="decideCampaignApproval(\'' + campaign.id + '\',\'approve\')">Aprovar</button>' +
          ' <button class="secondary" onclick="decideCampaignApproval(\'' + campaign.id + '\',\'reject\')">Rejeitar</button>';
      } else {
        action = '<button disabled>Aprovação ' + esc(approval.status || 'pendente') + '</button>';
      }
    } else {
      action = '<button onclick="deploy(\'' + campaign.id + '\')">Implantar ' + esc(campaign.ring_percent) + '%</button>';
    }
  } else if (canControlCampaign && campaign.status === 'deployed' && nextRing) {
    action = ringReady
      ? '<button onclick="advanceCampaign(\'' + campaign.id + '\',' + nextRing + ')">Promover para ' + nextRing + '%</button>'
      : '<button disabled title="' + esc(rollout.reason || healthReasonLabel(health.reason)) + '">' +
        (rollout.state === 'SOAK' ? 'Soak em andamento' : rollout.state === 'PAUSE' ? 'Rollout pausado' : 'Gate aguardando') +
        '</button>';
  }

  return `
    <article class="campaign ${compact ? 'compact-card' : ''}">
      <div class="campaign-main">
        <div class="campaign-title-row">
          <h3>${esc(campaign.name)}</h3>
          ${badge(statusLabel(campaign.status), campaign.status === 'deployed' ? 'ok' : 'info')}
          ${campaign.rollout_complete ? badge('100% liberado', 'ok') : ''}
          ${campaign.status === 'deployed' && rollout.state ? badge('ROLLOUT ' + String(rollout.state).toUpperCase(), rollout.state === 'PROMOTE' || rollout.state === 'COMPLETE' ? 'ok' : rollout.state === 'PAUSE' ? 'fail' : 'warn') : ''}
          ${campaign.status === 'deployed' && regression.status ? badge('REGRESSION ' + String(regression.status).toUpperCase(), regression.status === 'REGRESSION' ? 'fail' : regression.status === 'STABLE' ? 'ok' : 'info') : ''}
        </div>

        ${compact ? '' : `<p>${esc(campaign.description || 'Sem descrição')}</p>`}

        <div class="campaign-meta">
          ${badge((campaign.target_os || 'all').toUpperCase())}
          ${campaign.target_tag ? badge(campaign.target_tag, 'info') : ''}
          ${payload.target_agent_hostname ? badge('endpoint: ' + payload.target_agent_hostname, 'info') : ''}
          ${payload.source_cve ? badge(payload.source_cve, 'warn') : ''}
          ${isAgentRollout ? badge('AGENT v' + (payload.expected_version || '?'), 'info') : ''}
          ${approval.required ? badge('APPROVAL ' + String(approval.status || 'pending').toUpperCase(), approval.status === 'approved' ? 'ok' : approval.status === 'rejected' ? 'fail' : 'warn') : ''}
          <span>Ring atual <strong>${esc(campaign.ring_percent)}%</strong></span>
          <span>${esc(actionLabel(campaign.action))}</span>
          ${campaign.not_before ? `<span>Após ${esc(shortWhen(campaign.not_before))}</span>` : ''}
        </div>

        <div class="campaign-policy">
          ${isAgentRollout ? `
            <span>Versão alvo: <strong>v${esc(payload.expected_version || '-')}</strong></span>
            <span>Snapshot: <strong>${Array.isArray(payload.target_agent_ids) ? payload.target_agent_ids.length : 0} endpoint(s)</strong></span>
            <span>Confirmação: <strong>heartbeat da nova versão</strong></span>
            <span>Gate: <strong>obrigatório, sem override</strong></span>
            <span>Falha: <strong>watchdog + quarentena</strong></span>
          ` : `
            <span>Janela: <strong>${esc(windowText)}</strong></span>
            <span>Reboot: <strong>${esc(rebootPolicyLabel(payload.reboot_policy))}</strong></span>
            <span>Pós-patch: <strong>${payload.post_patch_validation === false ? 'desativado' : 'obrigatório'}</strong></span>
            <span>Saúde: <strong>${healthPolicy.enabled
              ? 'CPU Δ' + esc(healthPolicy.cpu_max_delta) + ' · MEM Δ' + esc(healthPolicy.memory_max_delta) + ' · disco Δ' + esc(healthPolicy.disk_max_free_drop)
              : 'desativada'}</strong></span>
            ${healthPolicy.enabled && (healthPolicy.critical_services || []).length
              ? '<span>Serviços: <strong>' + esc((healthPolicy.critical_services || []).length) + '</strong></span>'
              : ''}
            ${healthPolicy.enabled && (healthPolicy.application_checks || []).length
              ? '<span>Apps: <strong>' + esc((healthPolicy.application_checks || []).length) + '</strong></span>'
              : ''}
            <span>Rollback: <strong>${payload.prepare_rollback === false ? 'desativado' : payload.rollback_required ? 'checkpoint obrigatório' : 'checkpoint best effort'}</strong></span>
            <span>Rollout: <strong>${esc((rollout.plan || [campaign.ring_percent]).join(' → '))}%</strong></span>
            <span>Soak: <strong>${esc(rollout.soak_minutes || 0)} min</strong></span>
            <span>Promoção: <strong>${esc(rollout.promotion_min_success_rate || health.required_success_rate || 90)}% sucesso mínimo</strong></span>
            <span>Regressão: <strong>queda máx. ${esc(rollout.promotion_max_success_drop || 10)} p.p.</strong></span>
          `}
        </div>

        <div class="campaign-meta">
          ${campaign.status === 'deployed'
            ? badge(ringReady ? 'health gate OK' : 'health gate bloqueado', ringReady ? 'ok' : 'warn')
            : ''}
          ${campaign.status === 'deployed' ? `<span>Ring: ${Number(health.jobs || 0)} job(s)</span>` : ''}
          ${campaign.status === 'deployed' ? `<span>Sucesso: ${healthRate}% / mínimo ${Number(health.required_success_rate || 90)}%</span>` : ''}
          ${campaign.status === 'deployed' && Number(health.active || 0) ? `<span>Ativos: ${health.active}</span>` : ''}
          ${campaign.status === 'deployed' && Number(validation.waiting || 0) ? `<span>Validação aguardando: ${validation.waiting}</span>` : ''}
          ${campaign.status === 'deployed' && Number(validation.failed || 0) ? `<span class="text-danger">Validação falhou: ${validation.failed}</span>` : ''}
          ${campaign.status === 'deployed' && health.reason ? `<span>${esc(healthReasonLabel(health.reason))}</span>` : ''}
          ${regression.status === 'REGRESSION' ? `<span class="text-danger">${esc((regression.reasons || []).join(' · '))}</span>` : ''}
          ${campaign.status === 'deployed' && recommendation.action ? `<span>Recomendação: <strong>${esc(recommendation.action)}</strong></span>` : ''}
          ${healthIssues.length ? `<span class="text-danger health-issue">${esc(healthIssues.join(' · '))}</span>` : ''}
        </div>

        <div class="progress">
          <span style="width:${progress}%"></span>
        </div>

        <div class="campaign-stats">
          <span>Jobs <strong>${total}</strong></span>
          <span>OK <strong>${success}</strong></span>
          <span>Falhas <strong class="${failed ? 'text-danger' : ''}">${failed}</strong></span>
        </div>
      </div>

      <div class="campaign-actions">
        ${action || ''}
        <button class="secondary" onclick="showCampaignPreflight('${campaign.id}')">Preflight</button>
        <button class="secondary" onclick="showCampaignRingPlan('${campaign.id}')">Smart Canary</button>
        <button class="secondary" onclick="showCampaignCollisions('${campaign.id}')">Collision Guard</button>
        <button class="secondary" onclick="showPatchApplicability('${campaign.id}')">Applicability</button>
        <button class="secondary" onclick="showCampaignBlastRadius('${campaign.id}')">Impact Preview</button>
        <button class="secondary" onclick="downloadCampaignEvidencePack('${campaign.id}')">Evidence Pack</button>
        <button class="secondary" onclick="showCampaignFailureIntel('${campaign.id}')">Failure Intel</button>
        <button class="secondary" onclick="showPromotionAnalysis('${campaign.id}')">Safe Promotion</button>
        <button class="secondary" onclick="showRingHistory('${campaign.id}')">Histórico de rings</button>
      </div>
      <div id="preflight-${campaign.id}" class="preflight-box" hidden></div>
    </article>
  `;
}

function renderAgentRolloutForm() {
  const versionInput = $('#agentRolloutVersion');
  if (!versionInput) return;
  if (!versionInput.value && state.agentRelease && state.agentRelease.ready && state.agentRelease.version) {
    versionInput.value = state.agentRelease.version;
  }
}


function renderPatchBlockRules() {
  const report = state.patchBlockRules || {};
  const items = Array.isArray(report.items) ? report.items : [];
  const stats = $('#patchGuardStats');
  const table = $('#patchGuardTable');
  if (!stats || !table) return;

  const summary = report.summary || {};
  stats.innerHTML = [
    ['Ativas', summary.active || 0],
    ['Desativadas', summary.disabled || 0],
    ['Expiradas', summary.expired || 0],
  ].map(([label, value]) =>
    '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
  ).join('');

  if (!items.length) {
    table.innerHTML = '<tr><td colspan="7"><div class="empty-state">Nenhuma regra de bloqueio cadastrada.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((rule) => {
    const status = rule.active
      ? badge('ATIVA', 'fail')
      : rule.expired
        ? badge('EXPIRADA', 'muted-badge')
        : badge('DESATIVADA', 'muted-badge');
    const scope = [
      rule.target_os && rule.target_os !== 'all' ? rule.target_os : 'todos SOs',
      rule.target_tag ? 'tag ' + rule.target_tag : 'todas tags',
    ].join(' · ');
    const action = roleAtLeast('admin')
      ? '<button class="row-action" onclick="togglePatchBlockRule(\'' + rule.id + '\',' + (rule.enabled ? 'false' : 'true') + ')">' +
        (rule.enabled ? 'Desativar' : 'Reativar') + '</button>'
      : '<small class="muted">somente leitura</small>';
    return '<tr>' +
      '<td><strong>' + esc(rule.name) + '</strong><br><small class="muted">' + esc(rule.reason) + '</small></td>' +
      '<td><strong>' + esc(rule.patch_ref) + '</strong></td>' +
      '<td><small>' + esc(scope) + '</small></td>' +
      '<td>' + status + '</td>' +
      '<td><small>' + esc(rule.expires_at ? shortWhen(rule.expires_at) : 'sem expiração') + '</small></td>' +
      '<td><small>' + esc(rule.updated_by || rule.created_by || '-') + '</small></td>' +
      '<td>' + action + '</td>' +
    '</tr>';
  }).join('');
}


window.togglePatchBlockRule = async (ruleId, enabled) => {
  if (!requireRole('admin', 'Somente admin pode alterar o Patch Guard.')) return;
  if (!confirm((enabled ? 'Reativar' : 'Desativar') + ' esta regra do Patch Guard?')) return;
  try {
    await api('/api/admin/patch-block-rules/' + ruleId, {
      method: 'PATCH',
      body: JSON.stringify({
        enabled,
        reason: enabled ? 'Regra reativada pela console' : 'Regra desativada pela console',
      }),
    });
    toast(enabled ? 'Regra reativada.' : 'Regra desativada.');
    await load();
  } catch (error) {
    toast('Patch Guard: ' + error.message, 'fail');
  }
};


function renderCampaigns() {
  $('#campaigns').innerHTML = state.campaigns.length
    ? state.campaigns.map((campaign) => campaignCard(campaign)).join('')
    : '<div class="empty-state">Nenhuma campanha criada.</div>';
}

function renderOverviewCampaigns() {
  const recent = state.campaigns.slice(0, 4);

  $('#overviewCampaigns').innerHTML = recent.length
    ? recent.map((campaign) => campaignCard(campaign, true)).join('')
    : '<div class="empty-state">Nenhuma campanha ainda.</div>';
}

function executionStatusControl(job) {
  const status = badge(statusLabel(job.status), jobClass(job.status));
  const attempt = '<small class="muted">tentativa ' + esc(job.attempt_count || 0) + '</small>';
  if (job.status === 'stalled' && roleAtLeast('admin')) {
    return status + '<br>' + attempt +
      '<br><button class="row-action danger-action" onclick="retryStalledJob(\'' + job.id + '\')">Revisar e tentar novamente</button>';
  }
  return status + '<br>' + attempt;
}

function renderJobs() {
  $('#jobCount').textContent = `${state.jobs.length} job${state.jobs.length === 1 ? '' : 's'}`;

  if (!state.jobs.length) {
    $('#jobs').innerHTML = `
      <tr>
        <td colspan="9"><div class="empty-state">Nenhuma execução registrada.</div></td>
      </tr>`;
    return;
  }

  $('#jobs').innerHTML = state.jobs.slice(0, 200).map((job) => `
    <tr>
      <td><strong>${esc(job.hostname || '-')}</strong></td>
      <td>${esc(job.campaign_name || '-')}</td>
      <td>${esc(actionLabel(job.action))}</td>
      <td>${executionStatusControl(job)}</td>
      <td>${when(job.started_at || job.claimed_at)}</td>
      <td>${when(job.finished_at)}</td>
      <td>${validationBadge(job.validation)}</td>
      <td>${rollbackControl(job)}</td>
      <td class="error-cell">${esc(job.error || '')}</td>
    </tr>
  `).join('');
}

function renderAudit() {
  $('#auditCount').textContent = `${state.audit.length} evento${state.audit.length === 1 ? '' : 's'}`;

  if (!state.audit.length) {
    $('#auditFeed').innerHTML = '<div class="empty-state">Nenhum evento de auditoria.</div>';
    return;
  }

  $('#auditFeed').innerHTML = state.audit.slice(0, 200).map((event) => `
    <article class="audit-item">
      <div class="audit-dot"></div>
      <div class="audit-content">
        <div class="audit-title">
          <strong>${esc(event.event_type)}</strong>
          <span>${when(event.created_at)}</span>
        </div>
        <p>
          <span>${esc(event.actor)}</span>
          ${event.object_type ? ` · ${esc(event.object_type)}` : ''}
          ${event.object_id ? ` · ${esc(event.object_id)}` : ''}
        </p>
        ${event.details && Object.keys(event.details).length
          ? `<code>${esc(JSON.stringify(event.details))}</code>`
          : ''}
      </div>
    </article>
  `).join('');
}


function renderUsers() {
  if (!$('#users')) return;
  $('#userCount').textContent = state.users.length + ' usuário' + (state.users.length === 1 ? '' : 's');

  if (!roleAtLeast('admin')) {
    $('#users').innerHTML = '';
    return;
  }

  $('#users').innerHTML = state.users.length ? state.users.map((user) => {
    const isSelf = state.user && user.id === state.user.id;
    return `
      <tr>
        <td><strong>${esc(user.username)}</strong>${isSelf ? '<br><small class="muted">sessão atual</small>' : ''}</td>
        <td>
          <select class="inline-select" id="role-${esc(user.id)}" ${isSelf ? 'disabled' : ''}>
            <option value="viewer" ${user.role === 'viewer' ? 'selected' : ''}>Viewer</option>
            <option value="operator" ${user.role === 'operator' ? 'selected' : ''}>Operator</option>
            <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
          </select>
        </td>
        <td>${badge(user.active ? 'ativo' : 'inativo', user.active ? 'ok' : 'muted-badge')}</td>
        <td>${when(user.last_login_at)}</td>
        <td class="user-actions">
          ${isSelf ? userRoleBadge(user.role) :
            '<button class="row-action" onclick="saveUserRole(\'' + user.id + '\')">Salvar perfil</button>' +
            '<button class="row-action ' + (user.active ? 'danger-action' : '') + '" onclick="toggleUser(\'' + user.id + '\',' + (!user.active) + ')">' + (user.active ? 'Desativar' : 'Ativar') + '</button>'}
        </td>
      </tr>`;
  }).join('') : '<tr><td colspan="5"><div class="empty-state">Nenhum usuário.</div></td></tr>';
}

window.saveUserRole = async (userId) => {
  if (!requireRole('admin')) return;
  const role = $('#role-' + userId).value;
  try {
    await api('/api/admin/users/' + userId, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
    toast('Perfil atualizado.');
    await load();
  } catch (error) {
    toast('Usuário: ' + error.message, 'fail');
  }
};

window.toggleUser = async (userId, active) => {
  if (!requireRole('admin')) return;
  if (!confirm((active ? 'Ativar' : 'Desativar') + ' este usuário?')) return;
  try {
    await api('/api/admin/users/' + userId, {
      method: 'PATCH',
      body: JSON.stringify({ active }),
    });
    toast(active ? 'Usuário ativado.' : 'Usuário desativado.');
    await load();
  } catch (error) {
    toast('Usuário: ' + error.message, 'fail');
  }
};


window.decideCampaignApproval = async (campaignId, decision) => {
  if (!requireRole('admin', 'Somente admin pode decidir aprovação de campanha.')) return;
  const verb = decision === 'approve' ? 'aprovar' : 'rejeitar';
  const reason = prompt('Motivo para ' + verb + ' esta campanha:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }
  try {
    await api('/api/admin/campaigns/' + campaignId + '/approval/' + decision, {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim() }),
    });
    toast(decision === 'approve' ? 'Campanha aprovada.' : 'Campanha rejeitada.');
    await load();
  } catch (error) {
    toast('Approval gate: ' + error.message, 'fail');
  }
};


window.deploy = async (id) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  if (!confirm('Implantar esta campanha nos endpoints selecionados?')) return;

  try {
    const result = await api(`/api/admin/campaigns/${id}/deploy`, { method: 'POST' });
    toast(`${result.agents_selected} endpoint(s) selecionado(s).`);
    await load();
  } catch (error) {
    toast(error.message, 'fail');
  }
};

window.showCampaignPreflight = async (campaignId) => {
  const target = document.getElementById('preflight-' + campaignId);
  if (!target) return;

  if (!target.hidden && target.dataset.loaded === '1') {
    target.hidden = true;
    return;
  }

  target.hidden = false;
  target.dataset.loaded = '0';
  target.innerHTML = '<div class="empty-state">Executando preflight...</div>';

  try {
    const result = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/preflight');
    const summary = result.summary || {};
    const drift = result.drift || { status: 'NO_BASELINE', changes: [] };
    const latest = result.latest_snapshot || null;
    const readiness = String(result.readiness || 'REVIEW').toUpperCase();
    const readinessClass = readiness === 'READY' ? 'ok' : readiness === 'BLOCKED' ? 'fail' : 'warn';
    const statusClass = (status) => status === 'passed' ? 'ok' : status === 'blocked' ? 'fail' : 'warn';
    const driftClass = drift.status === 'DEGRADED' ? 'fail' : drift.status === 'UNCHANGED' || drift.status === 'IMPROVED' ? 'ok' : 'warn';

    target.innerHTML =
      '<div class="preflight-head">' +
        '<div><p class="section-kicker">CHANGE READINESS</p><h4>Campaign Preflight</h4></div>' +
        '<div class="preflight-head-actions">' +
          badge(readiness, readinessClass) +
          badge('DRIFT ' + String(drift.status || 'NO_BASELINE'), driftClass) +
        '</div>' +
      '</div>' +
      '<div class="preflight-summary">' +
        '<span>Checks <strong>' + esc(summary.checks || 0) + '</strong></span>' +
        '<span>Passed <strong>' + esc(summary.passed || 0) + '</strong></span>' +
        '<span>Warnings <strong>' + esc(summary.warnings || 0) + '</strong></span>' +
        '<span>Blockers <strong>' + esc(summary.blockers || 0) + '</strong></span>' +
        '<span>Ring <strong>' + esc(summary.selected_ring || 0) + '/' + esc(summary.candidates || 0) + '</strong></span>' +
        (latest ? '<span>Último snapshot <strong>' + esc(shortWhen(latest.created_at)) + '</strong></span>' : '<span>Snapshot <strong>nenhum</strong></span>') +
      '</div>' +
      ((drift.changes || []).length
        ? '<div class="preflight-drift">' +
          '<strong>Drift desde o último snapshot</strong>' +
          (drift.changes || []).slice(0, 8).map((change) =>
            '<span class="drift-row ' + esc(change.direction || 'changed') + '">' +
              '<b>' + esc(change.label || change.key || '-') + '</b> ' +
              esc(String(change.from_status || '-').toUpperCase()) + ' → ' +
              esc(String(change.to_status || '-').toUpperCase()) +
              (change.to_message ? ' · ' + esc(change.to_message) : '') +
            '</span>'
          ).join('') +
          '</div>'
        : '') +
      '<div class="preflight-grid">' +
        (result.checks || []).map((check) =>
          '<article class="preflight-check ' + statusClass(check.status) + '">' +
            '<div class="preflight-check-head">' +
              '<strong>' + esc(check.label || check.key || '-') + '</strong>' +
              badge(String(check.status || '-').toUpperCase(), statusClass(check.status)) +
            '</div>' +
            '<p>' + esc(check.message || '-') + '</p>' +
            (check.blocking ? '<small class="text-danger">Bloqueia deploy</small>' : '') +
          '</article>'
        ).join('') +
      '</div>' +
      '<div class="preflight-actions">' +
        (roleAtLeast('operator') ? '<button onclick="snapshotCampaignPreflight(\'' + campaignId + '\')">Registrar snapshot</button>' : '') +
        '<button class="secondary" onclick="showPreflightHistory(\'' + campaignId + '\')">Histórico de preflight</button>' +
      '</div>' +
      '<p class="preflight-note">' + esc(result.note || '') + '</p>';

    target.dataset.loaded = '1';
  } catch (error) {
    target.innerHTML = '<div class="empty-state text-danger">Preflight: ' + esc(error.message) + '</div>';
  }
};


window.snapshotCampaignPreflight = async (campaignId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  try {
    const result = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/preflight/snapshot', {
      method: 'POST',
    });
    const snapshot = result.snapshot || {};
    const drift = result.drift || {};
    toast(
      'Snapshot ' + String(snapshot.readiness || '-') +
      ' registrado · SHA ' + String(snapshot.result_sha256 || '').slice(0, 12) +
      ' · drift ' + String(drift.status || 'NO_BASELINE')
    );
    const target = document.getElementById('preflight-' + campaignId);
    if (target) {
      target.dataset.loaded = '0';
      target.hidden = true;
    }
    await showCampaignPreflight(campaignId);
  } catch (error) {
    toast('Snapshot de preflight: ' + error.message, 'fail');
  }
};


window.showPreflightHistory = async (campaignId) => {
  try {
    const items = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/preflight/history?limit=50');
    if (!items.length) {
      alert('Nenhum snapshot de preflight registrado.');
      return;
    }
    alert(items.map((item) =>
      when(item.created_at) + ' · ' + item.actor + ' · ' + item.source + '\n' +
      'Readiness: ' + item.readiness + ' · deploy ' + (item.deploy_allowed ? 'allowed' : 'blocked') + '\n' +
      'SHA256: ' + item.result_sha256
    ).join('\n\n'));
  } catch (error) {
    toast('Histórico de preflight: ' + error.message, 'fail');
  }
};

window.downloadCampaignEvidencePack = async (campaignId) => {
  try {
    const pack = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/evidence-pack');
    const campaign = pack.sections && pack.sections.campaign ? pack.sections.campaign : {};
    const safeName = String(campaign.name || campaignId)
      .normalize('NFKD')
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80) || campaignId;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'be-safe-evidence-' + safeName + '-' + stamp + '.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    const summary = pack.summary || {};
    const manifest = pack.manifest || {};
    toast(
      'Evidence Pack: ' + esc(summary.jobs || 0) + ' job(s), ' +
      esc(summary.preflight_snapshots || 0) + ' preflight(s) · SHA ' +
      String(manifest.pack_sha256 || '').slice(0, 12)
    );
  } catch (error) {
    toast('Evidence Pack: ' + error.message, 'fail');
  }
};
window.showPatchApplicability = async (campaignId) => {
  try {
    const report = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/patch-applicability');
    const s = report.summary || {};
    const lines = [
      'Patch Applicability & Supersedence',
      '',
      'Estado: ' + String(report.state || '-').toUpperCase(),
      'Bloqueia deploy: ' + (report.blocking ? 'SIM' : 'não'),
      'Pacotes: ' + String(s.packages || 0),
      'Blocked: ' + String(s.blocked || 0),
      'Warnings: ' + String(s.warnings || 0),
      'Ready: ' + String(s.ready || 0),
      'Assets no ring: ' + String(s.selected_assets || 0),
    ];

    (report.patches || []).slice(0, 20).forEach((item) => {
      lines.push(
        '',
        String(item.patch_ref || '-') + ' · ' + String(item.state || '-').toUpperCase(),
        'missing ' + String(item.missing_assets || 0) +
          ' · unknown ' + String(item.unknown_assets || 0) +
          ' · observed ' + String(item.observed_assets || 0) +
          (item.preferred_replacement ? ' · replacement ' + String(item.preferred_replacement) : '')
      );
      (item.reasons || []).forEach((reason) => lines.push('  - ' + String(reason)));
    });

    lines.push('', String(report.note || ''));
    alert(lines.join('\n'));
  } catch (error) {
    toast('Applicability: ' + error.message, 'fail');
  }
};


window.showCampaignCollisions = async (campaignId) => {
  try {
    const report = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/change-collisions');
    const s = report.summary || {};
    const lines = [
      'Change Collision Guard',
      '',
      'Estado: ' + String(report.state || '-').toUpperCase(),
      'Bloqueia deploy: ' + (report.blocking ? 'SIM' : 'não'),
      'Assets do ring: ' + String(s.selected_assets || 0),
      'Colisão direta de endpoint: ' + String(s.direct_asset_collisions || 0),
      'Service+environment compartilhados: ' + String(s.shared_service_environment_segments || 0),
      'Owners compartilhados: ' + String(s.shared_owners || 0),
      'Outras campanhas: ' + String(s.other_campaigns || 0),
      'Jobs ativos envolvidos: ' + String(s.other_active_jobs || 0),
    ];

    if ((report.direct_asset_collisions || []).length) {
      lines.push('', 'Colisões diretas:');
      report.direct_asset_collisions.slice(0, 12).forEach((item) => lines.push(
        String(item.hostname || item.agent_id || '-') +
        ' · ' + String(item.other_campaign_name || '-') +
        ' · job ' + String(item.job_status || '-')
      ));
    }

    if ((report.shared_service_environment || []).length) {
      lines.push('', 'Contexto compartilhado:');
      report.shared_service_environment.slice(0, 12).forEach((item) => lines.push(
        String(item.business_service || '-') + ' / ' + String(item.environment || '-') +
        ' · ' + String(item.active_jobs || 0) + ' job(s) ativo(s)'
      ));
    }

    if ((report.shared_owners || []).length) {
      lines.push('', 'Owners compartilhados:');
      report.shared_owners.slice(0, 10).forEach((item) => lines.push(
        String(item.owner || '-') + ' · ' + String(item.active_jobs || 0) + ' job(s)'
      ));
    }

    lines.push('', String(report.note || ''));
    alert(lines.join('\n'));
  } catch (error) {
    toast('Collision Guard: ' + error.message, 'fail');
  }
};


window.showCampaignRingPlan = async (campaignId) => {
  try {
    const plan = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/ring-plan');
    const coverage = plan.coverage || {};
    const selection = Array.isArray(plan.selection) ? plan.selection : [];
    const lines = [
      'Smart Canary / Ring Planner',
      '',
      'Estratégia: ' + String(plan.strategy || '-').toUpperCase(),
      'Ring: ' + String(plan.percent || 0) + '%',
      'Selecionados: ' + String(plan.selected_count || 0) + '/' + String(plan.candidate_count || 0),
      'Critical cap: ' + String(plan.critical_cap_percent ?? '-') + '%' +
        (plan.critical_cap_count !== null && plan.critical_cap_count !== undefined
          ? ' · máximo preferencial ' + String(plan.critical_cap_count)
          : ''),
      'Críticos selecionados: ' + String(plan.critical_selected || 0),
      '',
      'Cobertura do canário:',
      'Business services: ' + String(coverage.business_services || 0),
      'Environments: ' + String(coverage.environments || 0),
      'OS segments: ' + String(coverage.os_segments || 0),
      'Owners: ' + String(coverage.owners || 0),
    ];

    if (selection.length) {
      lines.push('', 'Ordem determinística do ring:');
      selection.slice(0, 20).forEach((item, index) => lines.push(
        String(index + 1) + '. ' + String(item.hostname || item.agent_id || '-') +
        (item.business_service ? ' · ' + String(item.business_service) : '') +
        (item.environment ? ' · ' + String(item.environment) : '') +
        (item.os_family ? ' · ' + String(item.os_family) + ' ' + String(item.os_version || '') : '') +
        (item.criticality !== undefined ? ' · crit ' + String(item.criticality) : '')
      ));
    }

    if (Array.isArray(plan.rules) && plan.rules.length) {
      lines.push('', 'Regras de seleção:');
      plan.rules.forEach((rule, index) => lines.push(String(index + 1) + '. ' + String(rule)));
    }

    lines.push('', String(plan.note || ''));
    alert(lines.join('\n'));
  } catch (error) {
    toast('Smart Canary: ' + error.message, 'fail');
  }
};


window.showCampaignBlastRadius = async (campaignId) => {
  try {
    const report = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/blast-radius');
    const s = report.summary || {};
    const signals = Array.isArray(report.signals) ? report.signals : [];
    const assets = Array.isArray(report.assets) ? report.assets : [];
    const services = report.distribution && Array.isArray(report.distribution.business_services)
      ? report.distribution.business_services
      : [];

    const lines = [
      'Change Impact Preview',
      '',
      'Estado: ' + String(report.impact_state || '-').toUpperCase(),
      'Ring: ' + String(s.ring_assets || 0) + '/' + String(s.scope_assets || 0) +
        ' assets (' + String(s.ring_scope_percent || 0) + '% do escopo)',
      'Críticos: ' + String(s.critical_assets || 0),
      'Expostos externamente: ' + String(s.external_assets || 0),
      'Acima do risk appetite: ' + String(s.above_risk_appetite || 0),
      'Críticos sem owner: ' + String(s.critical_without_owner || 0),
      'Business services: ' + String(s.business_services || 0),
      'Owners: ' + String(s.owners || 0),
      'Ambientes: ' + String(s.environments || 0),
      'Asset Risk médio/máx: ' + String(s.average_asset_risk || 0) + ' / ' + String(s.max_asset_risk || 0),
    ];

    if (s.top_business_service) {
      lines.push(
        'Maior concentração: ' + String(s.top_business_service.name || '-') +
        ' · ' + String(s.top_business_service.assets || 0) + ' asset(s) · ' +
        String(s.top_business_service.percent || 0) + '%'
      );
    }

    if (signals.length) {
      lines.push('', 'Sinais de impacto:');
      signals.forEach((item) => lines.push(
        '[' + String(item.severity || '-').toUpperCase() + '] ' + String(item.message || '-')
      ));
    }

    if (services.length) {
      lines.push('', 'Distribuição por business service:');
      services.slice(0, 8).forEach((item) => lines.push(
        String(item.name || '-') + ' · ' + String(item.assets || 0) + ' · ' + String(item.percent || 0) + '%'
      ));
    }

    const sensitive = assets
      .slice()
      .sort((a, b) => Number(b.criticality || 0) - Number(a.criticality || 0) || Number(b.asset_risk || 0) - Number(a.asset_risk || 0))
      .slice(0, 10);
    if (sensitive.length) {
      lines.push('', 'Ativos mais sensíveis do ring:');
      sensitive.forEach((item) => lines.push(
        String(item.hostname || item.agent_id || '-') +
        ' · crit ' + String(item.criticality || 0) +
        ' · risk ' + String(item.asset_risk || 0) +
        ' · ' + String(item.business_service || 'sem service') +
        ' · ' + String(item.owner || 'sem owner')
      ));
    }

    lines.push('', 'Sem score oculto: o estado usa somente as regras explícitas exibidas no relatório.');
    alert(lines.join('\n'));
  } catch (error) {
    toast('Impact Preview: ' + error.message, 'fail');
  }
};


window.showCampaignFailureIntel = async (campaignId) => {
  try {
    const [report, preflight] = await Promise.all([
      api('/api/admin/reports/patch-failure-intelligence?lookback_days=30&limit=100'),
      api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/preflight'),
    ]);
    const check = (preflight.checks || []).find((item) => item.key === 'local_regression') || {};
    const matches = check.details && Array.isArray(check.details.matches) ? check.details.matches : [];
    const summary = report.summary || {};
    const lines = [
      'Patch Failure Intelligence',
      '',
      'Janela: ' + String(report.lookback_days || 30) + ' dias',
      'Regressões locais confirmadas: ' + String(summary.confirmed_local_regressions || 0),
      'Taxas de falha elevadas: ' + String(summary.elevated_failure_rates || 0),
      'Clusters de falha: ' + String(summary.failure_clusters || 0),
      '',
      'Campanha: ' + String(preflight.campaign_name || campaignId),
      'Estado local: ' + String((check.details || {}).state || 'no_evidence'),
    ];

    if (matches.length) {
      lines.push('', 'Evidência que casa com este ring:');
      matches.slice(0, 12).forEach((item) => {
        lines.push(
          String(item.patch_ref || '-') + ' · ' +
          String(item.os_family || '-') + ' ' + String(item.os_version || '-') +
          ' · ' + String(item.regression_state || '-') +
          ' · falha efetiva ' + String(item.effective_failure_rate ?? '-') + '%' +
          ' · ' + String(item.failed || 0) + ' install fail / ' +
          String(item.post_patch_regressions || 0) + ' pós-patch'
        );
      });
    } else {
      lines.push('', 'Nenhuma evidência local recente casando patch + SO/versão do ring.');
    }

    const relevantRefs = new Set(matches.map((item) => String(item.patch_ref || '').toLowerCase()));
    const clusters = (report.clusters || []).filter((item) => !relevantRefs.size || relevantRefs.has(String(item.patch_ref || '').toLowerCase()));
    if (clusters.length) {
      lines.push('', 'Top failure signatures:');
      clusters.slice(0, 8).forEach((item) => {
        lines.push(
          '[' + String(item.category || '-') + '] ' +
          String(item.patch_ref || '-') + ' · ' +
          String(item.count || 0) + 'x · ' +
          String(item.signature || 'unspecified')
        );
      });
    }

    alert(lines.join('\n'));
  } catch (error) {
    toast('Failure Intelligence: ' + error.message, 'fail');
  }
};




window.showPromotionAnalysis = async (campaignId) => {
  try {
    const result = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/promotion-analysis');
    const r = result.regression || {};
    const current = r.current || {};
    const previous = r.previous || {};
    const d = r.deltas || {};
    const recommendation = result.recommendation || {};
    alert(
      'Safe Promotion Analysis\n\n' +
      'Campaign: ' + (result.campaign_name || '-') + '\n' +
      'Regression: ' + (r.status || '-') + '\n' +
      'Recommendation: ' + (recommendation.action || '-') + '\n\n' +
      'Current ring: ' + (current.ring_percent || '-') + '% · success ' + (current.success_rate ?? '-') + '% · failure ' + (current.failure_rate ?? '-') + '%\n' +
      (previous.ring_percent ? 'Previous ring: ' + previous.ring_percent + '% · success ' + previous.success_rate + '% · failure ' + previous.failure_rate + '%\n' : 'Previous ring: no baseline\n') +
      'Success drop: ' + (d.success_rate_drop ?? '-') + ' p.p.\n' +
      'Failure increase: ' + (d.failure_rate_increase ?? '-') + ' p.p.\n' +
      'Validation delta: ' + (d.validation_failure_delta ?? '-') + '\n\n' +
      ((r.reasons || []).join('\n') || 'No regression reasons.')
    );
  } catch (error) {
    toast('Promotion analysis: ' + error.message, 'fail');
  }
};

window.showRingHistory = async (campaignId) => {
  try {
    const items = await api('/api/admin/campaigns/' + encodeURIComponent(campaignId) + '/ring-history?limit=50');
    if (!items.length) {
      alert('Nenhuma promoção de ring registrada.');
      return;
    }
    alert(items.map((item) =>
      when(item.created_at) + ' · ' + item.actor + ' · ' +
      item.decision + ' · ' + item.from_ring + '% → ' + item.to_ring + '%\n' +
      item.reason
    ).join('\n\n'));
  } catch (error) {
    toast('Histórico de rings: ' + error.message, 'fail');
  }
};

window.advanceCampaign = async (id, targetPercent) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
  if (!confirm('Avançar esta campanha para o ring de ' + targetPercent + '%?')) return;

  try {
    const result = await api('/api/admin/campaigns/' + id + '/advance', {
      method: 'POST',
      body: JSON.stringify({ target_percent: targetPercent, override_health_gate: false }),
    });
    toast('Ring avançado para ' + result.to_ring + '%. ' + result.new_agents + ' novo(s) endpoint(s).');
    await load();
  } catch (error) {
    toast('Health gate: ' + error.message, 'fail');
  }
};


window.retryStalledJob = async (jobId) => {
  if (!requireRole('admin', 'Somente admin pode autorizar retry de job stalled.')) return;
  const reason = prompt('Descreva a revisão feita antes de reexecutar este job:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }
  if (!confirm('ATENÇÃO: a tentativa anterior pode ter executado parcialmente. Confirmar nova tentativa?')) return;

  try {
    await api('/api/admin/jobs/' + jobId + '/retry', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim(), acknowledge_risk: true }),
    });
    toast('Job revisado e devolvido à fila.');
    await load();
  } catch (error) {
    toast('Retry: ' + error.message, 'fail');
  }
};


window.approveRollback = async (jobId) => {
  if (!requireRole('admin', 'Somente admin pode aprovar rollback.')) return;
  const reason = prompt('Motivo da aprovação do rollback (obrigatório):');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }
  if (!confirm('ATENÇÃO: o endpoint será restaurado para o checkpoint anterior e poderá reiniciar. Aprovar rollback?')) return;

  try {
    await api('/api/admin/jobs/' + jobId + '/rollback', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim(), acknowledge_risk: true }),
    });
    toast('Rollback aprovado e colocado na fila.');
    await load();
  } catch (error) {
    toast('Rollback: ' + error.message, 'fail');
  }
};

$('#loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const username = String(form.get('username') || '').trim();
  const password = String(form.get('password') || '');
  const button = $('#loginButton');

  button.disabled = true;
  button.textContent = 'Entrando...';
  $('#loginError').hidden = true;

  try {
    const result = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    state.sessionToken = result.session_token;
    state.user = result.user;
    event.target.reset();
    hideLogin();
    applyPermissions();
    await load();
  } catch (error) {
    $('#loginError').hidden = false;
    $('#loginError').textContent = error.status === 401 ? 'Usuário ou senha inválidos.' : error.message;
  } finally {
    button.disabled = false;
    button.textContent = 'Entrar';
  }
});

$('#logout').addEventListener('click', async () => {
  try {
    if (state.sessionToken) await api('/api/auth/logout', { method: 'POST' });
  } catch {
    // Logout local continua mesmo se a sessão já tiver expirado.
  }
  showLogin('');
});

$('#changePassword').addEventListener('click', async () => {
  if (!state.sessionToken || !state.user || state.user.break_glass) return;
  const currentPassword = prompt('Senha atual:');
  if (!currentPassword) return;
  const newPassword = prompt('Nova senha (mínimo 14 caracteres):');
  if (!newPassword) return;

  try {
    await api('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    toast('Senha alterada. Outras sessões foram revogadas.');
  } catch (error) {
    toast('Senha: ' + error.message, 'fail');
  }
});

$('#refresh').addEventListener('click', load);

$$('.nav-item').forEach((button) => {
  button.addEventListener('click', () => setView(button.dataset.view));
});

$$('.jump-view').forEach((button) => {
  button.addEventListener('click', () => setView(button.dataset.target));
});

$('#endpointSearch').addEventListener('input', renderAgents);
$('#endpointFilter').addEventListener('change', renderAgents);
$('#vulnerabilitySearch').addEventListener('input', renderVulnerabilities);
$('#vulnerabilityFilter').addEventListener('change', renderVulnerabilities);

$('#greenboneSync').addEventListener('click', async () => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;

  $('#greenboneSync').disabled = true;
  $('#greenboneSync').textContent = 'Sincronizando...';

  try {
    const result = await api('/api/admin/integrations/greenbone/sync', { method: 'POST' });
    const stats = result.result || {};
    toast('Greenbone: ' + Number(stats.findings || 0) + ' finding(s) sincronizado(s).');
    await load();
  } catch (error) {
    toast('Greenbone: ' + error.message, 'fail');
    await load();
  } finally {
    $('#greenboneSync').textContent = 'Sincronizar agora';
  }
});



$('#threatIntelSync').addEventListener('click', async () => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;

  $('#threatIntelSync').disabled = true;
  $('#threatIntelSync').textContent = 'Enriquecendo...';

  try {
    const result = await api('/api/admin/integrations/threat-intel/sync', { method: 'POST' });
    const stats = result.result || {};
    toast('Threat Intel: ' + Number(stats.updated || 0) + ' finding(s) enriquecido(s).');
    await load();
  } catch (error) {
    toast('Threat Intel: ' + error.message, 'fail');
    await load();
  } finally {
    $('#threatIntelSync').textContent = 'Sincronizar agora';
  }
});



$('#assetRiskSnapshot').addEventListener('click', async () => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;

  $('#assetRiskSnapshot').disabled = true;
  $('#assetRiskSnapshot').textContent = 'Salvando...';

  try {
    const result = await api('/api/admin/reports/asset-risk/snapshot', { method: 'POST' });
    const stats = result.result || {};
    toast('Asset Risk: ' + Number(stats.created || 0) + ' snapshot(s) salvo(s).');
    await load();
  } catch (error) {
    toast('Asset Risk: ' + error.message, 'fail');
  } finally {
    $('#assetRiskSnapshot').textContent = 'Salvar snapshot';
    $('#assetRiskSnapshot').disabled = false;
  }
});




document.addEventListener('click', (event) => {
  const target = event.target.closest('[data-agent-open]');
  if (target) openAgent(target.dataset.agentOpen);
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && $('#agentDrawer').classList.contains('open')) closeAgent();

  const target = event.target.closest && event.target.closest('[data-agent-open]');
  if (target && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    openAgent(target.dataset.agentOpen);
  }
});

$('#closeDrawer').addEventListener('click', closeAgent);
$('#drawerBackdrop').addEventListener('click', closeAgent);
$('#saveTags').addEventListener('click', saveAgentTags);

$('#clearAgentUpdateQuarantine').addEventListener('click', async () => {
  if (!requireRole('admin', 'Somente admin pode liberar release em quarentena.')) return;
  const agent = selectedAgent();
  if (!agent) return;

  const update = agent.inventory && agent.inventory.update && typeof agent.inventory.update === 'object'
    ? agent.inventory.update
    : {};
  const version = String(update.quarantined_version || update.staged_version || '');
  if (!version) {
    toast('A versão em quarentena não foi reportada pelo endpoint.', 'fail');
    return;
  }

  const reason = prompt('Motivo para liberar novamente a v' + version + ':');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }

  const approved = confirm(
    'Liberar novamente a v' + version + ' em ' + agent.hostname + '?\n\n' +
    'Essa release já sofreu rollback automático neste endpoint.'
  );
  if (!approved) return;

  try {
    await api('/api/admin/agents/' + agent.id + '/updates/quarantine/clear', {
      method: 'POST',
      body: JSON.stringify({
        expected_version: version,
        reason: reason.trim(),
        acknowledge_risk: true,
      }),
    });
    toast('Liberação da quarentena colocada na fila.');
    await load();
    renderAgentDrawer();
  } catch (error) {
    toast('Quarentena do agente: ' + error.message, 'fail');
  }
});

$('#activateAgentUpdate').addEventListener('click', async () => {
  if (!requireRole('admin', 'Somente admin pode ativar update do agente.')) return;
  const agent = selectedAgent();
  if (!agent) return;

  const update = agent.inventory && agent.inventory.update && typeof agent.inventory.update === 'object'
    ? agent.inventory.update
    : {};
  const expectedVersion = String(update.staged_version || '');
  if (!expectedVersion) {
    toast('O endpoint não reporta uma versão staged.', 'fail');
    return;
  }

  const reason = prompt('Motivo da ativação do agente (obrigatório):');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }

  const approved = confirm(
    'Ativar o agente v' + expectedVersion + ' em ' + agent.hostname + '?\n\n' +
    'O serviço será reiniciado. O launcher fará rollback automático se a nova versão não confirmar heartbeat.'
  );
  if (!approved) return;

  try {
    await api('/api/admin/agents/' + agent.id + '/updates/activate', {
      method: 'POST',
      body: JSON.stringify({
        expected_version: expectedVersion,
        reason: reason.trim(),
        acknowledge_risk: true,
      }),
    });
    toast('Ativação aprovada e colocada na fila.');
    await load();
    renderAgentDrawer();
  } catch (error) {
    toast('Ativação do agente: ' + error.message, 'fail');
  }
});

$('#bindMtls').addEventListener('click', async () => {
  if (!requireRole('admin', 'Somente admin pode vincular ou rotacionar certificado mTLS.')) return;
  const agent = selectedAgent();
  if (!agent) return;

  const fingerprint = prompt('Fingerprint SHA-1 do certificado cliente (com ou sem dois-pontos):');
  if (!fingerprint) return;

  const reason = prompt('Motivo do vínculo/rotação (obrigatório):');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }

  try {
    await api('/api/admin/agents/' + agent.id + '/mtls', {
      method: 'PUT',
      body: JSON.stringify({ fingerprint: fingerprint.trim(), reason: reason.trim() }),
    });
    toast('Certificado mTLS vinculado ao endpoint.');
    await load();
    renderAgentDrawer();
  } catch (error) {
    toast('mTLS: ' + error.message, 'fail');
  }
});

$('.drawer-tab').forEach((button) => {
  button.addEventListener('click', () => setDrawerTab(button.dataset.drawerTab));
});

function parseCriticalServices(value) {
  return String(value || '')
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseApplicationHealthChecks(value) {
  return String(value || '')
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((line, index) => {
      const separator = line.indexOf('=');
      const hasName = separator > 0;
      const name = hasName ? line.slice(0, separator).trim() : 'app-' + (index + 1);
      const url = hasName ? line.slice(separator + 1).trim() : line;
      return {
        name,
        url,
        expected_status: 200,
        body_contains: '',
        timeout_seconds: 5,
        verify_tls: true,
      };
    });
}

function agentRolloutRequestBody(form, acknowledgeRisk = false) {
  return {
    name: String(form.get('name') || '').trim(),
    description: String(form.get('description') || '').trim(),
    target_tag: String(form.get('target_tag') || '').trim(),
    ring_percent: Number(form.get('ring_percent') || 10),
    expected_version: String(form.get('expected_version') || '').trim(),
    reason: String(form.get('reason') || '').trim(),
    acknowledge_risk: Boolean(acknowledgeRisk),
  };
}

function agentRolloutSkipLabel(reason) {
  const labels = {
    not_linux: 'não Linux',
    tag_mismatch: 'fora da tag',
    stale_heartbeat: 'heartbeat antigo',
    activation_capability_missing: 'sem capability de ativação',
    version_not_upgrade: 'versão não é upgrade',
    not_staged: 'sem release staged',
    staged_version_mismatch: 'versão staged divergente',
    artifact_sha256_mismatch: 'SHA256 divergente',
    source_commit_mismatch: 'source commit divergente',
    signing_key_id_mismatch: 'chave de assinatura divergente',
    activation_not_eligible: 'ativação/quarentena pendente',
    active_execution: 'execução ativa',
  };
  return labels[reason] || reason;
}

function renderAgentRolloutPreview(data) {
  const target = $('#agentRolloutPreview');
  if (!target) return;

  const skipped = data.skipped || {};
  const skippedRows = Object.entries(skipped)
    .filter(([, count]) => Number(count || 0) > 0)
    .map(([reason, count]) => '<span>' + esc(agentRolloutSkipLabel(reason)) + ': <strong>' + esc(count) + '</strong></span>')
    .join('');

  const binding = data.release_binding || {};
  const selected = Array.isArray(data.agents)
    ? data.agents.filter((item) => item.selected).slice(0, 12)
    : [];

  target.hidden = false;
  target.innerHTML =
    '<strong>Preview do rollout</strong>' +
    '<div class="campaign-meta">' +
      '<span>Elegíveis: <strong>' + esc(data.eligible_agents || 0) + '</strong></span>' +
      '<span>Entram no ring: <strong>' + esc(data.selected_agents || 0) + '</strong></span>' +
      '<span>Ring: <strong>' + esc(data.ring_percent || 0) + '%</strong></span>' +
      '<span>TTL da aprovação: <strong>' + esc(Math.round(Number(data.approval_ttl_seconds || 0) / 60)) + ' min</strong></span>' +
    '</div>' +
    '<div class="campaign-meta">' +
      '<span>Release: <strong>v' + esc(data.expected_version || '-') + '</strong></span>' +
      '<span>SHA: <strong>' + esc(String(binding.artifact_sha256 || '').slice(0, 12)) + '…</strong></span>' +
      '<span>Commit: <strong>' + esc(String(binding.source_commit || '').slice(0, 12)) + '…</strong></span>' +
      '<span>Key ID: <strong>' + esc(String(binding.signing_key_id || '').slice(0, 12)) + '…</strong></span>' +
    '</div>' +
    (skippedRows ? '<div class="campaign-meta"><span>Fora do snapshot:</span>' + skippedRows + '</div>' : '') +
    (selected.length
      ? '<div class="campaign-meta"><span>Primeiro ring:</span>' +
        selected.map((item) => '<span><strong>' + esc(item.hostname || item.agent_id) + '</strong></span>').join('') +
        '</div>'
      : '<div class="form-hint">Nenhum endpoint entraria neste ring.</div>');
}

async function previewAgentRollout(formData) {
  const body = agentRolloutRequestBody(formData, false);
  const result = await api('/api/admin/agent-update-rollouts/preview', {
    method: 'POST',
    body: JSON.stringify(body),
  });
  renderAgentRolloutPreview(result);
  return result;
}

$('#agentRolloutPreviewButton').addEventListener('click', async () => {
  if (!requireRole('admin', 'Somente admin pode visualizar rollout do agente.')) return;
  const formElement = $('#agentRolloutForm');
  try {
    const result = await previewAgentRollout(new FormData(formElement));
    const skippedTotal = Object.values(result.skipped || {}).reduce(
      (sum, value) => sum + Number(value || 0),
      0
    );
    toast(
      'Preview: ' + result.selected_agents + ' no ring, ' +
      result.eligible_agents + ' elegíveis' +
      (skippedTotal ? ', ' + skippedTotal + ' fora do snapshot' : '') + '.'
    );
  } catch (error) {
    toast('Preview do rollout: ' + error.message, 'fail');
  }
});


$('#agentRolloutForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!requireRole('admin', 'Somente admin pode iniciar rollout do agente.')) return;

  const form = new FormData(event.target);
  const body = agentRolloutRequestBody(form, true);

  if (form.get('acknowledge_risk') !== 'on') {
    toast('Confirme o risco do restart e rollback do agente.', 'fail');
    return;
  }

  try {
    const preview = await previewAgentRollout(form);
    if (!Number(preview.selected_agents || 0)) {
      toast('Nenhum endpoint entraria no ring atual.', 'fail');
      return;
    }

    const skippedTotal = Object.values(preview.skipped || {}).reduce(
      (sum, value) => sum + Number(value || 0),
      0
    );
    const confirmation =
      'Iniciar rollout v' + body.expected_version + ' no ring de ' + body.ring_percent + '%?\n\n' +
      preview.selected_agents + ' endpoint(s) entram agora.\n' +
      preview.eligible_agents + ' endpoint(s) estão no snapshot elegível.\n' +
      skippedTotal + ' endpoint(s) ficaram fora.\n' +
      'A autorização expira em ' + Math.round(Number(preview.approval_ttl_seconds || 0) / 60) + ' min.';

    if (!confirm(confirmation)) return;

    const result = await api('/api/admin/agent-update-rollouts', {
      method: 'POST',
      body: JSON.stringify(body),
    });

    const skipped = result.skipped || {};
    const finalSkippedTotal = Object.values(skipped).reduce((sum, value) => sum + Number(value || 0), 0);
    toast(
      'Rollout iniciado: ' + result.initial_agents + ' no primeiro ring, ' +
      result.eligible_agents + ' elegíveis' +
      (finalSkippedTotal ? ', ' + finalSkippedTotal + ' fora do snapshot' : '') + '.'
    );
    event.target.reset();
    $('#agentRolloutPreview').hidden = true;
    $('#agentRolloutPreview').innerHTML = '';
    renderAgentRolloutForm();
    await load();
  } catch (error) {
    toast('Rollout do agente: ' + error.message, 'fail');
  }
});



const autoPatchPolicyForm = $('#autoPatchPolicyForm');
if (autoPatchPolicyForm) autoPatchPolicyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!requireRole('admin', 'Somente admin pode criar Auto Patch Policies.')) return;
  const form = new FormData(event.target);
  try {
    await api('/api/admin/auto-patch/policies', {
      method: 'POST',
      body: JSON.stringify({
        name: String(form.get('name') || '').trim(),
        mode: String(form.get('mode') || 'recommend'),
        target_os: String(form.get('target_os') || 'all').trim(),
        target_tag: String(form.get('target_tag') || '').trim(),
        require_kev: form.get('require_kev') === 'on',
        require_external: form.get('require_external') === 'on',
        require_patch_tuesday: form.get('require_patch_tuesday') === 'on',
        min_missing_assets: Number(form.get('min_missing_assets') || 1),
        confidence_floor: String(form.get('confidence_floor') || 'insufficient_data'),
        allow_eol: form.get('allow_eol') === 'on',
        superseded_action: String(form.get('superseded_action') || 'replace'),
        ring_percent: Number(form.get('ring_percent') || 10),
        require_approval: form.get('require_approval') === 'on',
        require_health_gate: form.get('require_health_gate') === 'on',
        require_rollback: form.get('require_rollback') === 'on',
      }),
    });
    event.target.reset();
    toast('Auto Patch Policy criada.');
    await load();
  } catch (error) {
    toast('Auto Patch Policy: ' + error.message, 'fail');
  }
});

const patchGuardForm = $('#patchGuardForm');
if (patchGuardForm) patchGuardForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!requireRole('admin', 'Somente admin pode criar regras do Patch Guard.')) return;

  const form = new FormData(event.target);
  const expiresAt = form.get('expires_at');
  try {
    await api('/api/admin/patch-block-rules', {
      method: 'POST',
      body: JSON.stringify({
        name: String(form.get('name') || '').trim(),
        patch_ref: String(form.get('patch_ref') || '').trim(),
        target_os: String(form.get('target_os') || 'all').trim(),
        target_tag: String(form.get('target_tag') || '').trim(),
        reason: String(form.get('reason') || '').trim(),
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      }),
    });
    event.target.reset();
    toast('Patch bloqueado pelo Patch Guard.');
    await load();
  } catch (error) {
    toast('Patch Guard: ' + error.message, 'fail');
  }
});


$('#campaignForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;

  const form = new FormData(event.target);
  const packages = String(form.get('packages') || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  const dayPresets = {
    all: [0, 1, 2, 3, 4, 5, 6],
    weekdays: [0, 1, 2, 3, 4],
    weekend: [5, 6],
    sunday: [6],
  };
  const rebootPolicy = form.get('reboot_policy') || 'never';

  const body = {
    name: form.get('name'),
    description: form.get('description') || '',
    target_os: form.get('target_os'),
    target_tag: form.get('target_tag') || '',
    ring_percent: Number(form.get('ring_percent') || 10),
    action: form.get('action'),
    allow_reboot: rebootPolicy === 'if_required',
    reboot_policy: rebootPolicy,
    maintenance_start: form.get('maintenance_start') || '',
    maintenance_end: form.get('maintenance_end') || '',
    maintenance_timezone: form.get('maintenance_timezone') || 'America/Sao_Paulo',
    maintenance_days: dayPresets[form.get('maintenance_days')] || dayPresets.all,
    post_patch_validation: form.get('post_patch_validation') === 'on',
    health_gate_enabled: form.get('health_gate_enabled') === 'on',
    health_gate_require_telemetry: form.get('health_gate_require_telemetry') === 'on',
    health_cpu_max_percent: Number(form.get('health_cpu_max_percent') || 95),
    health_cpu_max_delta: Number(form.get('health_cpu_max_delta') || 40),
    health_memory_max_percent: Number(form.get('health_memory_max_percent') || 95),
    health_memory_max_delta: Number(form.get('health_memory_max_delta') || 20),
    health_disk_min_free_percent: Number(form.get('health_disk_min_free_percent') || 5),
    health_disk_max_free_drop: Number(form.get('health_disk_max_free_drop') || 10),
    critical_services: parseCriticalServices(form.get('critical_services')),
    application_health_checks: parseApplicationHealthChecks(form.get('application_health_urls')),
    prepare_rollback: form.get('prepare_rollback') === 'on',
    rollback_required: form.get('rollback_required') === 'on',
    approval_required: form.get('approval_required') === 'on',
    approval_reason: String(form.get('approval_reason') || '').trim(),
    rollout_plan: String(form.get('rollout_plan') || '').split(',').map((value) => Number(value.trim())).filter((value) => Number.isFinite(value) && value >= 1 && value <= 100),
    soak_minutes: Number(form.get('soak_minutes') || 0),
    promotion_min_success_rate: Number(form.get('promotion_min_success_rate') || 90),
    promotion_max_success_drop: Number(form.get('promotion_max_success_drop') || 10),
    pause_on_failure: form.get('pause_on_failure') === 'on',
    ring_strategy: String(form.get('ring_strategy') || 'balanced'),
    canary_max_critical_percent: Number(form.get('canary_max_critical_percent') || 25),
    target_agent_id: form.get('target_agent_id') || '',
    target_agent_ids: Array.isArray(state.campaignTargetAgentIds) ? state.campaignTargetAgentIds : [],
    target_finding_id: form.get('target_finding_id') || '',
    not_before: form.get('not_before')
      ? new Date(form.get('not_before')).toISOString()
      : null,
    payload: { packages },
  };

  try {
    await api('/api/admin/campaigns', {
      method: 'POST',
      body: JSON.stringify(body),
    });

    event.target.reset();
    event.target.elements.ring_percent.value = 10;
    event.target.elements.ring_strategy.value = 'balanced';
    event.target.elements.canary_max_critical_percent.value = 25;
    event.target.elements.rollout_plan.value = '10,30,100';
    event.target.elements.soak_minutes.value = 60;
    event.target.elements.promotion_min_success_rate.value = 90;
    event.target.elements.promotion_max_success_drop.value = 10;
    event.target.elements.pause_on_failure.checked = true;
    event.target.elements.maintenance_timezone.value = 'America/Sao_Paulo';
    event.target.elements.post_patch_validation.checked = true;
    event.target.elements.health_gate_enabled.checked = true;
    event.target.elements.health_gate_require_telemetry.checked = true;
    event.target.elements.prepare_rollback.checked = true;
    event.target.elements.approval_required.checked = false;
    event.target.elements.approval_reason.value = '';
    state.campaignTargetAgentIds = [];
    $('#campaignSourceContext').hidden = true;
    $('#campaignSourceContext').innerHTML = '';
    toast('Campanha criada.');
    await load();
  } catch (error) {
    toast(error.message, 'fail');
  }
});

$('#userForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!requireRole('admin')) return;

  const form = new FormData(event.target);
  try {
    await api('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify({
        username: String(form.get('username') || '').trim(),
        password: String(form.get('password') || ''),
        role: String(form.get('role') || 'viewer'),
      }),
    });
    event.target.reset();
    toast('Usuário criado.');
    await load();
  } catch (error) {
    toast('Usuário: ' + error.message, 'fail');
  }
});

setInterval(() => {
  if (state.sessionToken) load();
}, 30000);

showLogin('');
