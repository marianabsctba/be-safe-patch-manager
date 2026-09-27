const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
  token: '',
  summary: null,
  agents: [],
  vulnerabilities: [],
  greenbone: null,
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
};

function headers() {
  return {
    'Content-Type': 'application/json',
    'X-Admin-Token': state.token,
  };
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
    throw new Error(`${response.status} ${body}`);
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
  if (status === 'failed') return 'fail';
  if (status === 'running' || status === 'claimed') return 'warn';
  return 'info';
}

function actionLabel(action) {
  if (action === 'install_updates') return 'Instalar updates';
  if (action === 'rollback_checkpoint') return 'Rollback aprovado';
  return 'Scan de updates';
}

function statusLabel(status) {
  const labels = {
    draft: 'Rascunho',
    deployed: 'Implantada',
    pending: 'Pendente',
    claimed: 'Recebida',
    running: 'Executando',
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
  if (!state.token) return;

  $('#refresh').classList.add('spin');

  try {
    const [summary, agents, vulnerabilities, greenbone, campaigns, jobs, audit] = await Promise.all([
      api('/api/admin/summary'),
      api('/api/admin/agents'),
      api('/api/admin/vulnerabilities'),
      api('/api/admin/integrations/greenbone'),
      api('/api/admin/campaigns'),
      api('/api/admin/jobs'),
      api('/api/admin/audit'),
    ]);

    state.summary = summary;
    state.agents = agents;
    state.vulnerabilities = vulnerabilities;
    state.greenbone = greenbone;
    state.campaigns = campaigns;
    state.jobs = jobs;
    state.audit = audit;

    renderAll();

    $('#lastUpdate').textContent = `Atualizado ${new Date().toLocaleTimeString('pt-BR', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })}`;
  } catch (error) {
    if (String(error.message).startsWith('401 ')) {
      state.token = '';
      $('#saveToken').textContent = 'Conectar';
      $('#lastUpdate').textContent = 'Sessão desconectada';
      toast('Token administrativo inválido.', 'fail');
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
  renderVulnerabilities();
  renderCampaigns();
  renderOverviewCampaigns();
  renderJobs();
  renderAudit();
  if (state.selectedAgentId) renderAgentDrawer();
}

function renderSummary(summary) {
  const entries = [
    { label: 'Endpoints', value: summary.agents || 0, hint: `${summary.online || 0} online`, cls: 'neutral' },
    { label: 'Compliance', value: `${summary.compliance_percent || 0}%`, hint: `${summary.compliant || 0} compliant`, cls: 'accent' },
    { label: 'Updates pendentes', value: summary.pending_updates || 0, hint: 'itens detectados', cls: summary.pending_updates ? 'warn' : 'ok' },
    { label: 'Críticos', value: summary.critical_updates || 0, hint: 'prioridade alta', cls: summary.critical_updates ? 'danger' : 'ok' },
    { label: 'Reboot pendente', value: summary.reboot_required || 0, hint: 'endpoints', cls: summary.reboot_required ? 'warn' : 'ok' },
    { label: 'Falhas', value: summary.failed_jobs || 0, hint: 'jobs acumulados', cls: summary.failed_jobs ? 'danger' : 'ok' },
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

    return true;
  });
}

function renderAgents() {
  const items = filteredAgents();

  if (!items.length) {
    $('#agents').innerHTML = `
      <tr>
        <td colspan="9"><div class="empty-state">Nenhum endpoint encontrado.</div></td>
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
    ['Remediadas', state.vulnerabilities.filter((item) => item.status === 'remediated').length, 'confirmadas por status/rescan', 'ok'],
  ].map(([label, value, hint, cls]) => `
    <article class="card ${cls}">
      <span>${esc(label)}</span>
      <strong>${esc(value)}</strong>
      <small>${esc(hint)}</small>
    </article>
  `).join('');

  const items = filteredVulnerabilities();
  if (!items.length) {
    $('#vulnerabilities').innerHTML = '<tr><td colspan="9"><div class="empty-state">Nenhum finding encontrado.</div></td></tr>';
    return;
  }

  $('#vulnerabilities').innerHTML = items.map((item) => `
    <tr>
      <td><strong>${esc(item.cve || 'sem CVE')}</strong></td>
      <td>${badge(item.severity || 'unknown', vulnerabilitySeverityClass(item.severity))}</td>
      <td><strong>${Number(item.cvss || 0).toFixed(1)}</strong></td>
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
      <td>${badge(vulnerabilityStatusLabel(item.status), item.status === 'remediated' ? 'ok' : item.status === 'open' ? 'warn' : 'info')}</td>
      <td>${when(item.last_seen)}</td>
      <td>
        ${item.status === 'open' && item.matched
          ? '<button class="row-action" onclick="prepareCampaignFromFinding(\'' + item.id + '\')">Criar campanha</button>'
          : ''}
      </td>
    </tr>
  `).join('');
}

window.prepareCampaignFromFinding = (findingId) => {
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
  form.elements.description.value =
    'Remediação de ' + (finding.cve || finding.external_id) +
    ' detectada por ' + finding.source +
    ' · CVSS ' + Number(finding.cvss || 0).toFixed(1) +
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

  $('#drawerHostname').textContent = agent.hostname || '-';
  $('#drawerSubtitle').textContent = ((agent.os_name || agent.os_family || '-') + ' ' + (agent.os_version || '')).trim();

  $('#drawerBadges').innerHTML = [
    isOnline(agent) ? badge('online', 'ok') : badge('offline', 'muted-badge'),
    badge(risk.label, risk.cls),
    agent.reboot_required ? badge('reboot pendente', 'warn') : '',
    ...(agent.tags || []).map((tag) => badge(tag, 'info')),
  ].join('');

  const metrics = [
    ['Updates pendentes', Number(agent.pending_updates || 0), Number(agent.pending_updates || 0) ? 'warn' : 'ok'],
    ['Críticas', Number(agent.critical_updates || 0), Number(agent.critical_updates || 0) ? 'danger' : 'ok'],
    ['Reboot', agent.reboot_required ? 'SIM' : 'não', agent.reboot_required ? 'warn' : 'ok'],
    ['Último contato', shortWhen(agent.last_seen), isOnline(agent) ? 'ok' : 'neutral'],
    ['Rollback', agent.inventory && agent.inventory.rollback && agent.inventory.rollback.checkpoint_supported ? 'disponível' : 'indisponível', agent.inventory && agent.inventory.rollback && agent.inventory.rollback.checkpoint_supported ? 'ok' : 'neutral'],
  ];

  $('#drawerMetrics').innerHTML = metrics.map((item) =>
    '<article class="drawer-metric ' + item[2] + '">' +
      '<span>' + esc(item[0]) + '</span>' +
      '<strong>' + esc(item[1]) + '</strong>' +
    '</article>'
  ).join('');

  $('#drawerTags').value = (agent.tags || []).join(', ');

  const identity = [
    ['Agent ID', agent.id],
    ['IP', agent.ip_address || '-'],
    ['Família', agent.os_family || '-'],
    ['Arquitetura', agent.arch || '-'],
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
    return '<button class="row-action danger-action" onclick="approveRollback(\'' + job.id + '\')">Aprovar rollback</button>';
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
  return badge(labels[status] || status, cls);
}

function healthReasonLabel(reason) {
  const labels = {
    'no jobs in current ring': 'sem jobs no ring',
    'current ring still has active jobs': 'jobs ainda em execução',
    'current ring has non-terminal jobs': 'jobs ainda não finalizados',
    'success rate below 90%': 'sucesso abaixo de 90%',
    'post-patch validation failed': 'validação pós-patch falhou',
    'waiting for post-patch validation': 'aguardando validação pós-patch',
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
  const windowEnabled = Boolean(payload.maintenance_start && payload.maintenance_end);
  const windowText = windowEnabled
    ? payload.maintenance_start + '–' + payload.maintenance_end + ' · ' +
      maintenanceDaysLabel(payload.maintenance_days) + ' · ' + (payload.maintenance_timezone || 'UTC')
    : 'sem janela restritiva';

  let action = '';
  if (campaign.status === 'draft') {
    action = '<button onclick="deploy(\'' + campaign.id + '\')">Implantar ' + esc(campaign.ring_percent) + '%</button>';
  } else if (campaign.status === 'deployed' && nextRing) {
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
          <span>Ring atual <strong>${esc(campaign.ring_percent)}%</strong></span>
          <span>${esc(actionLabel(campaign.action))}</span>
          ${campaign.not_before ? `<span>Após ${esc(shortWhen(campaign.not_before))}</span>` : ''}
        </div>

        <div class="campaign-policy">
          <span>Janela: <strong>${esc(windowText)}</strong></span>
          <span>Reboot: <strong>${esc(rebootPolicyLabel(payload.reboot_policy))}</strong></span>
          <span>Pós-patch: <strong>${payload.post_patch_validation === false ? 'desativado' : 'obrigatório'}</strong></span>
          <span>Rollback: <strong>${payload.prepare_rollback === false ? 'desativado' : payload.rollback_required ? 'checkpoint obrigatório' : 'checkpoint best effort'}</strong></span>
        </div>

        <div class="campaign-meta">
          ${campaign.status === 'deployed'
            ? badge(ringReady ? 'health gate OK' : 'health gate bloqueado', ringReady ? 'ok' : 'warn')
            : ''}
          ${campaign.status === 'deployed' ? `<span>Ring: ${Number(health.jobs || 0)} job(s)</span>` : ''}
          ${campaign.status === 'deployed' ? `<span>Sucesso: ${healthRate}%</span>` : ''}
          ${campaign.status === 'deployed' && Number(health.active || 0) ? `<span>Ativos: ${health.active}</span>` : ''}
          ${campaign.status === 'deployed' && Number(validation.waiting || 0) ? `<span>Validação aguardando: ${validation.waiting}</span>` : ''}
          ${campaign.status === 'deployed' && Number(validation.failed || 0) ? `<span class="text-danger">Validação falhou: ${validation.failed}</span>` : ''}
          ${campaign.status === 'deployed' && health.reason ? `<span>${esc(healthReasonLabel(health.reason))}</span>` : ''}
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
      <td>${badge(statusLabel(job.status), jobClass(job.status))}</td>
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

window.deploy = async (id) => {
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


window.approveRollback = async (jobId) => {
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

$('#saveToken').addEventListener('click', () => {
  const candidate = $('#token').value.trim();

  if (!candidate) {
    toast('Informe o token administrativo.', 'fail');
    return;
  }

  state.token = candidate;
  $('#token').value = '';
  $('#saveToken').textContent = 'Conectado';
  load();
});

$('#token').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    $('#saveToken').click();
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
  if (!state.token) {
    toast('Conecte com o token administrativo primeiro.', 'fail');
    return;
  }

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

$('.drawer-tab').forEach((button) => {
  button.addEventListener('click', () => setDrawerTab(button.dataset.drawerTab));
});

$('#campaignForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!state.token) {
    toast('Conecte com o token administrativo primeiro.', 'fail');
    return;
  }

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
    event.target.elements.prepare_rollback.checked = true;
    $('#campaignSourceContext').hidden = true;
    $('#campaignSourceContext').innerHTML = '';
    toast('Campanha criada.');
    await load();
  } catch (error) {
    toast(error.message, 'fail');
  }
});

setInterval(() => {
  if (state.token) load();
}, 30000);