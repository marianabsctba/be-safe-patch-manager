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
    const [summary, agents, vulnerabilities, greenbone, threatIntel, remediationQueue, remediationHub, riskReduction, assetRisk, riskPolicies, agentRelease, campaigns, jobs, audit, users] = await Promise.all([
      api('/api/admin/summary'),
      api('/api/admin/agents'),
      api('/api/admin/vulnerabilities'),
      api('/api/admin/integrations/greenbone'),
      api('/api/admin/integrations/threat-intel'),
      api('/api/admin/reports/remediation-queue'),
      api('/api/admin/reports/remediation-hub'),
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
  renderRiskReductionOpportunities();
  renderAssetRisk();
  renderVulnerabilities();
  renderCampaigns();
  renderOverviewCampaigns();
  renderAgentRolloutForm();
  renderJobs();
  renderAudit();
  renderUsers();
  if (state.selectedAgentId) renderAgentDrawer();
}

function renderSummary(summary) {
  const release = state.agentRelease || {};
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
    { label: 'Risco aceito', value: summary.assets_risk_accepted || 0, hint: 'aceites ativos', cls: summary.assets_risk_accepted ? 'accent' : 'ok' },
    { label: 'Em tratamento', value: summary.assets_risk_in_treatment || 0, hint: 'planos ativos acima do appetite', cls: summary.assets_risk_in_treatment ? 'warn' : 'ok' },
    { label: 'Tratamento vencido', value: summary.assets_risk_treatment_overdue || 0, hint: 'prazo de treatment excedido', cls: summary.assets_risk_treatment_overdue ? 'danger' : 'ok' },
    { label: 'Risco sem ação', value: summary.assets_risk_untreated || 0, hint: 'acima do appetite sem aceite/plano', cls: summary.assets_risk_untreated ? 'danger' : 'ok' },
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

window.createRiskPolicy = async () => {
  if (!requireRole('admin', 'Somente admin pode criar política de risco.')) return;
  const name = prompt('Nome da política:');
  if (!name || name.trim().length < 3) return;
  const targetTag = prompt('Tag alvo (ex.: tier0, prod, lab):');
  if (!targetTag || !targetTag.trim()) return;
  const appetite = Number(prompt('Risk appetite 1–1000:', '700'));
  if (!Number.isInteger(appetite) || appetite < 1 || appetite > 1000) {
    toast('Risk appetite deve estar entre 1 e 1000.', 'fail');
    return;
  }
  const priority = Number(prompt('Prioridade da política (maior vence):', '100'));
  if (!Number.isInteger(priority) || priority < 1 || priority > 10000) {
    toast('Prioridade inválida.', 'fail');
    return;
  }
  const reason = prompt('Motivo da política:');
  if (!reason || reason.trim().length < 5) return;

  try {
    await api('/api/admin/risk-policies', {
      method: 'POST',
      body: JSON.stringify({
        name: name.trim(),
        target_tag: targetTag.trim().toLowerCase(),
        risk_appetite: appetite,
        priority,
        enabled: true,
        reason: reason.trim(),
      }),
    });
    toast('Política de risco criada.');
    await load();
  } catch (error) {
    toast('Política de risco: ' + error.message, 'fail');
  }
};

window.editRiskPolicy = async (policyId) => {
  if (!requireRole('admin', 'Somente admin pode editar política de risco.')) return;
  const policy = (state.riskPolicies || []).find((item) => item.id === policyId);
  if (!policy) return;

  const name = prompt('Nome:', policy.name);
  if (name === null || name.trim().length < 3) return;
  const tag = prompt('Tag alvo:', policy.target_tag);
  if (tag === null || !tag.trim()) return;
  const appetite = Number(prompt('Risk appetite 1–1000:', String(policy.risk_appetite)));
  if (!Number.isInteger(appetite) || appetite < 1 || appetite > 1000) {
    toast('Risk appetite inválido.', 'fail');
    return;
  }
  const priority = Number(prompt('Prioridade (maior vence):', String(policy.priority)));
  if (!Number.isInteger(priority) || priority < 1 || priority > 10000) {
    toast('Prioridade inválida.', 'fail');
    return;
  }
  const enabledRaw = prompt('Status: on ou off', policy.enabled ? 'on' : 'off');
  if (enabledRaw === null || !['on', 'off'].includes(enabledRaw.trim().toLowerCase())) {
    toast('Use on ou off.', 'fail');
    return;
  }
  const reason = prompt('Motivo da alteração:');
  if (!reason || reason.trim().length < 5) return;

  try {
    await api('/api/admin/risk-policies/' + policyId, {
      method: 'PUT',
      body: JSON.stringify({
        name: name.trim(),
        target_tag: tag.trim().toLowerCase(),
        risk_appetite: appetite,
        priority,
        enabled: enabledRaw.trim().toLowerCase() === 'on',
        reason: reason.trim(),
      }),
    });
    toast('Política de risco atualizada.');
    await load();
  } catch (error) {
    toast('Política de risco: ' + error.message, 'fail');
  }
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

  const owner = prompt('Owner do plano de tratamento:');
  if (!owner || owner.trim().length < 2) return;
  const action = prompt('Ação planejada:');
  if (!action || action.trim().length < 5) return;
  const daysRaw = prompt('Prazo em dias:', '30');
  const days = Number(daysRaw);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    toast('Prazo inválido.', 'fail');
    return;
  }

  try {
    await api('/api/admin/agents/' + agentId + '/risk-treatments', {
      method: 'POST',
      body: JSON.stringify({
        owner: owner.trim(),
        action: action.trim(),
        due_at: new Date(Date.now() + days * 86400000).toISOString(),
      }),
    });
    toast('Plano de tratamento criado.');
    await load();
  } catch (error) {
    toast('Plano de tratamento: ' + error.message, 'fail');
  }
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

  const owner = prompt('Owner:', treatment.owner || '');
  if (owner === null || owner.trim().length < 2) return;
  const action = prompt('Ação:', treatment.action || '');
  if (action === null || action.trim().length < 5) return;
  const status = prompt(
    'Status: planned, in_progress, completed ou cancelled',
    treatment.status || 'planned'
  );
  if (status === null || !['planned', 'in_progress', 'completed', 'cancelled'].includes(status.trim())) {
    toast('Status inválido.', 'fail');
    return;
  }

  let evidence = treatment.completion_evidence || '';
  if (status.trim() === 'completed') {
    const entered = prompt('Evidência de conclusão (obrigatória):', evidence);
    if (!entered || entered.trim().length < 5) {
      toast('Informe evidência de conclusão.', 'fail');
      return;
    }
    evidence = entered.trim();
  }

  try {
    await api('/api/admin/agents/' + agentId + '/risk-treatments/' + treatmentId, {
      method: 'PUT',
      body: JSON.stringify({
        owner: owner.trim(),
        action: action.trim(),
        status: status.trim(),
        completion_evidence: evidence,
      }),
    });
    toast('Plano de tratamento atualizado.');
    await load();
  } catch (error) {
    toast('Plano de tratamento: ' + error.message, 'fail');
  }
};


window.createAssetRiskAcceptance = async (agentId) => {
  if (!requireRole('admin', 'Somente admin pode aceitar risco.')) return;

  const reason = prompt('Motivo da aceitação de risco:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }
  const daysRaw = prompt('Validade da aceitação em dias (1–365):', '30');
  const days = Number(daysRaw);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    toast('Validade deve ficar entre 1 e 365 dias.', 'fail');
    return;
  }

  const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
  try {
    await api('/api/admin/agents/' + agentId + '/risk-acceptances', {
      method: 'POST',
      body: JSON.stringify({
        reason: reason.trim(),
        expires_at: expiresAt,
      }),
    });
    toast('Risco aceito temporariamente. O score não foi alterado.');
    await load();
  } catch (error) {
    toast('Aceitação de risco: ' + error.message, 'fail');
  }
};

window.revokeAssetRiskAcceptance = async (agentId, acceptanceId) => {
  if (!requireRole('admin', 'Somente admin pode revogar aceitação de risco.')) return;

  const reason = prompt('Motivo da revogação da aceitação:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }

  try {
    await api('/api/admin/agents/' + agentId + '/risk-acceptances/' + acceptanceId + '/revoke', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.trim() }),
    });
    toast('Aceitação de risco revogada.');
    await load();
  } catch (error) {
    toast('Revogação de risco: ' + error.message, 'fail');
  }
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
  const currentCriticality = profile.criticality == null
    ? ''
    : String(profile.criticality);
  const criticalityRaw = prompt(
    'Criticidade 1–5. Deixe vazio para automático por tags.\nAtual efetiva: ' +
    String((effective.criticality || {}).score || '-'),
    currentCriticality
  );
  if (criticalityRaw === null) return;
  let criticality = null;
  if (criticalityRaw.trim() !== '') {
    criticality = Number(criticalityRaw);
    if (!Number.isInteger(criticality) || criticality < 1 || criticality > 5) {
      toast('Criticidade precisa ser um inteiro entre 1 e 5.', 'fail');
      return;
    }
  }

  const exposureDefault = profile.external === true ? 'externo' : profile.external === false ? 'interno' : 'auto';
  const exposureRaw = prompt('Exposição: auto, interno ou externo.', exposureDefault);
  if (exposureRaw === null) return;
  const exposureValue = exposureRaw.trim().toLowerCase();
  if (!['auto', 'interno', 'externo'].includes(exposureValue)) {
    toast('Use auto, interno ou externo.', 'fail');
    return;
  }
  const external = exposureValue === 'auto' ? null : exposureValue === 'externo';

  const controlsDefault = Array.isArray(profile.compensating_controls)
    ? profile.compensating_controls.join(', ')
    : 'auto';
  const controlsRaw = prompt(
    'Controles: auto ou lista separada por vírgula.\nPermitidos: segmented, edr-protected, restricted-egress',
    controlsDefault
  );
  if (controlsRaw === null) return;

  let compensatingControls = null;
  if (controlsRaw.trim().toLowerCase() !== 'auto') {
    compensatingControls = controlsRaw
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
  }

  const ownerRaw = prompt('Owner responsável pelo ativo (opcional):', profile.owner || '');
  if (ownerRaw === null) return;
  const businessServiceRaw = prompt('Business service / aplicação (opcional):', profile.business_service || '');
  if (businessServiceRaw === null) return;
  const environmentRaw = prompt('Environment (ex.: prod, staging, dev, lab) (opcional):', profile.environment || '');
  if (environmentRaw === null) return;

  const reason = prompt('Motivo da alteração do perfil de risco:');
  if (!reason || reason.trim().length < 5) {
    toast('Informe um motivo com pelo menos 5 caracteres.', 'fail');
    return;
  }

  try {
    await api('/api/admin/agents/' + agentId + '/risk-profile', {
      method: 'PUT',
      body: JSON.stringify({
        criticality,
        external,
        compensating_controls: compensatingControls,
        owner: ownerRaw.trim(),
        business_service: businessServiceRaw.trim(),
        environment: environmentRaw.trim().toLowerCase(),
        reason: reason.trim(),
      }),
    });
    toast('Perfil de risco atualizado e snapshot registrado.');
    await load();
  } catch (error) {
    toast('Perfil de risco: ' + error.message, 'fail');
  }
};


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
      ['Cruza appetite', summary.appetite_crossings || 0],
    ].map(([label, value]) =>
      '<div><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'
    ).join('');
  }

  const table = $('#remediationHubTable');
  if (!table) return;
  if (!items.length) {
    table.innerHTML = '<tr><td colspan="9"><div class="empty-state">Sem grupos de remediação com patch reference conhecida.</div></td></tr>';
    return;
  }

  table.innerHTML = items.map((item, index) => {
    const cves = Array.isArray(item.cves) ? item.cves : [];
    const osFamilies = Array.isArray(item.os_families) ? item.os_families : [];
    const assets = Array.isArray(item.affected_assets) ? item.affected_assets : [];
    const topAssets = assets.slice(0, 3).map((asset) =>
      esc(asset.hostname) + ' (-' + esc(asset.risk_reduction) + ')'
    ).join('<br>');
    const campaignButton = (
      item.single_asset_campaign_ready && item.primary_finding_id && roleAtLeast('operator')
        ? '<button class="row-action" onclick="prepareCampaignFromFinding(\'' + item.primary_finding_id + '\')">Preparar campanha</button>'
        : '<small class="muted">' + (item.asset_count > 1 ? 'multi-asset · revisar escopo' : 'análise') + '</small>'
    );

    return '<tr>' +
      '<td><strong>#' + esc(index + 1) + '</strong></td>' +
      '<td><strong>' + esc(item.patch_ref) + '</strong><br><small class="muted">' + esc(osFamilies.join(', ') || '-') + '</small></td>' +
      '<td><strong>' + esc(item.finding_count) + '</strong><br><small class="muted">' + esc(item.cve_count) + ' CVEs</small></td>' +
      '<td><strong>' + esc(item.asset_count) + '</strong><br><small class="muted">' + topAssets + '</small></td>' +
      '<td><strong>' + esc(item.before_risk_total) + ' → ' + esc(item.projected_risk_total) + '</strong></td>' +
      '<td><strong>-' + esc(item.risk_reduction) + '</strong><br><small class="muted">' + esc(item.reduction_percent) + '%</small></td>' +
      '<td><strong>' + esc(item.appetite_crossings) + '</strong></td>' +
      '<td><small>' + esc(cves.slice(0, 4).join(', ') || '-') + (cves.length > 4 ? ' +' + esc(cves.length - 4) : '') + '</small></td>' +
      '<td>' + campaignButton + '</td>' +
    '</tr>';
  }).join('');
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

window.prepareCampaignFromFinding = (findingId) => {
  if (!requireRole('operator', 'Perfil operator ou admin necessário.')) return;
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
  const presets = [10, 30, 100];
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
  const nextRing = nextRingPercent(campaign.ring_percent);
  const ringReady = Boolean(health.ready);
  const healthRate = Number(health.success_rate || 0);
  const payload = campaign.payload || {};
  const healthPolicy = payload.health_policy || {};
  const isAgentRollout = payload.rollout_type === 'agent_update' || campaign.action === 'activate_agent_update';
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
    action = '<button onclick="deploy(\'' + campaign.id + '\')">Implantar ' + esc(campaign.ring_percent) + '%</button>';
  } else if (canControlCampaign && campaign.status === 'deployed' && nextRing) {
    action = ringReady
      ? '<button onclick="advanceCampaign(\'' + campaign.id + '\',' + nextRing + ')">Avançar para ' + nextRing + '%</button>'
      : '<button disabled title="' + esc(healthReasonLabel(health.reason)) + '">Gate aguardando</button>';
  }

  return `
    <article class="campaign ${compact ? 'compact-card' : ''}">
      <div class="campaign-main">
        <div class="campaign-title-row">
          <h3>${esc(campaign.name)}</h3>
          ${badge(statusLabel(campaign.status), campaign.status === 'deployed' ? 'ok' : 'info')}
          ${campaign.rollout_complete ? badge('100% liberado', 'ok') : ''}
        </div>

        ${compact ? '' : `<p>${esc(campaign.description || 'Sem descrição')}</p>`}

        <div class="campaign-meta">
          ${badge((campaign.target_os || 'all').toUpperCase())}
          ${campaign.target_tag ? badge(campaign.target_tag, 'info') : ''}
          ${payload.target_agent_hostname ? badge('endpoint: ' + payload.target_agent_hostname, 'info') : ''}
          ${payload.source_cve ? badge(payload.source_cve, 'warn') : ''}
          ${isAgentRollout ? badge('AGENT v' + (payload.expected_version || '?'), 'info') : ''}
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

      ${action ? `<div class="campaign-actions">${action}</div>` : ''}
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
    target_agent_id: form.get('target_agent_id') || '',
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
    event.target.elements.maintenance_timezone.value = 'America/Sao_Paulo';
    event.target.elements.post_patch_validation.checked = true;
    event.target.elements.health_gate_enabled.checked = true;
    event.target.elements.health_gate_require_telemetry.checked = true;
    event.target.elements.prepare_rollback.checked = true;
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
