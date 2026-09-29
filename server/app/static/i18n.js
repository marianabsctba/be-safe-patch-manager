(() => {
  const translations = {
    en: {
      "Visão geral":"Overview","Vulnerabilidades":"Vulnerabilities","Campanhas":"Campaigns","Execuções":"Executions","Auditoria":"Audit","Usuários":"Users",
      "Aguardando autenticação":"Waiting for authentication","Atualizar":"Refresh","Senha":"Password","Sair":"Logout","POSTURA":"POSTURE","Patch compliance":"Patch compliance",
      "Com pendências":"Pending","Críticas":"Critical","Reboot pendente":"Pending reboot","RISCO":"RISK","Endpoints prioritários":"Priority endpoints","Ver todos":"View all",
      "Abrir Risk Workbench":"Open Risk Workbench","ATIVIDADE":"ACTIVITY","Campanhas recentes":"Recent campaigns","Gerenciar":"Manage",
      "Acesso ao console":"Console access","Entre com sua conta. A sessão fica somente na memória do navegador.":"Sign in with your account. The session stays only in browser memory.",
      "Usuário":"Username","Entrar":"Sign in","Resumo":"Summary","Inventário":"Inventory","Histórico":"History","Salvar":"Save","Fechar":"Close","Cancelar":"Cancel",
      "Identificação":"Identification","Patches detectados":"Detected patches","Inventário reportado pelo agente":"Inventory reported by agent","Jobs deste endpoint":"Jobs for this endpoint",
      "Campanhas":"Campaigns","Nova campanha":"New campaign","Criar campanha":"Create campaign","Atualizado":"Updated","Permissão insuficiente.":"Insufficient permission.",
      "Rascunho":"Draft","Implantada":"Deployed","Pendente":"Pending","Bloqueado":"Blocked","Recebida":"Claimed","Executando":"Running","Travado / revisão":"Stalled / review",
      "Sucesso":"Success","Falha":"Failed","Ignorada":"Skipped","Instalar updates":"Install updates","Rollback aprovado":"Approved rollback","Ativar update do agente":"Activate agent update",
      "Liberar quarentena do agente":"Release agent quarantine","Scan de updates":"Update scan","Crítico":"Critical","Atenção":"Attention","sim":"yes","não":"no",
      "Estratégia do canário":"Canary strategy","Balanced coverage-first":"Balanced coverage-first","Legacy hash determinístico":"Legacy deterministic hash",
      "Máx. crítico no canário (%)":"Max critical in canary (%)","Plano de rollout":"Rollout plan","Ring inicial (%)":"Initial ring (%)",
      "Smart Canary":"Smart Canary","Collision Guard":"Collision Guard","Applicability":"Applicability","Reboot Plan":"Reboot Plan","Impact Preview":"Impact Preview","Evidence Pack":"Evidence Pack","Failure Intel":"Failure Intel","Safe Promotion":"Safe Promotion",
      "GOVERNANÇA":"GOVERNANCE","Português (Brasil)":"Portuguese (Brazil)","English":"English","Español":"Spanish","Idioma":"Language","Idioma do tenant":"Tenant language"
    },
    es: {
      "Visão geral":"Vista general","Vulnerabilidades":"Vulnerabilidades","Campanhas":"Campañas","Execuções":"Ejecuciones","Auditoria":"Auditoría","Usuários":"Usuarios",
      "Aguardando autenticação":"Esperando autenticación","Atualizar":"Actualizar","Senha":"Contraseña","Sair":"Salir","POSTURA":"POSTURA","Patch compliance":"Cumplimiento de parches",
      "Com pendências":"Con pendientes","Críticas":"Críticas","Reboot pendente":"Reinicio pendiente","RISCO":"RIESGO","Endpoints prioritários":"Endpoints prioritarios","Ver todos":"Ver todos",
      "Abrir Risk Workbench":"Abrir Risk Workbench","ATIVIDADE":"ACTIVIDAD","Campanhas recentes":"Campañas recientes","Gerenciar":"Gestionar",
      "Acesso ao console":"Acceso a la consola","Entre com sua conta. A sessão fica somente na memória do navegador.":"Inicia sesión con tu cuenta. La sesión permanece solo en la memoria del navegador.",
      "Usuário":"Usuario","Entrar":"Entrar","Resumo":"Resumen","Inventário":"Inventario","Histórico":"Historial","Salvar":"Guardar","Fechar":"Cerrar","Cancelar":"Cancelar",
      "Identificação":"Identificación","Patches detectados":"Parches detectados","Inventário reportado pelo agente":"Inventario reportado por el agente","Jobs deste endpoint":"Jobs de este endpoint",
      "Nova campanha":"Nueva campaña","Criar campanha":"Crear campaña","Atualizado":"Actualizado","Permissão insuficiente.":"Permiso insuficiente.",
      "Rascunho":"Borrador","Implantada":"Desplegada","Pendente":"Pendiente","Bloqueado":"Bloqueado","Recebida":"Recibida","Executando":"Ejecutando","Travado / revisão":"Detenido / revisión",
      "Sucesso":"Éxito","Falha":"Fallo","Ignorada":"Omitida","Instalar updates":"Instalar actualizaciones","Rollback aprovado":"Rollback aprobado","Ativar update do agente":"Activar actualización del agente",
      "Liberar quarentena do agente":"Liberar cuarentena del agente","Scan de updates":"Escaneo de actualizaciones","Crítico":"Crítico","Atenção":"Atención","sim":"sí","não":"no",
      "Estratégia do canário":"Estrategia canary","Balanced coverage-first":"Balanced coverage-first","Legacy hash determinístico":"Hash determinístico legacy",
      "Máx. crítico no canário (%)":"Máx. críticos en canary (%)","Plano de rollout":"Plan de rollout","Ring inicial (%)":"Ring inicial (%)",
      "Smart Canary":"Smart Canary","Collision Guard":"Collision Guard","Applicability":"Aplicabilidad","Reboot Plan":"Plan de reinicio","Impact Preview":"Vista previa de impacto","Evidence Pack":"Paquete de evidencias","Failure Intel":"Inteligencia de fallos","Safe Promotion":"Promoción segura",
      "GOVERNANÇA":"GOBERNANZA","Português (Brasil)":"Portugués (Brasil)","English":"Inglés","Español":"Español","Idioma":"Idioma","Idioma do tenant":"Idioma del tenant"
    }
  };

  const localeMap = { "pt-BR": "pt-BR", en: "en-US", es: "es-ES" };
  let locale = "pt-BR";
  let tenant = { id: "default", name: "Be Safe", locale: "pt-BR", supported_locales: [] };
  const sourceText = new WeakMap();
  const sourceTitle = new WeakMap();
  const sourcePlaceholder = new WeakMap();

  function t(value) {
    const raw = String(value ?? "");
    if (locale === "pt-BR") return raw;
    return (translations[locale] && translations[locale][raw]) || raw;
  }

  function browserLocale() {
    return localeMap[locale] || "pt-BR";
  }

  function translateNode(node) {
    if (!node || node.nodeType !== Node.TEXT_NODE) return;
    if (!sourceText.has(node)) sourceText.set(node, node.nodeValue);
    const raw = sourceText.get(node);
    const trimmed = raw.trim();
    if (!trimmed) return;
    const translated = t(trimmed);
    node.nodeValue = raw.replace(trimmed, translated);
  }

  function apply(root = document.body) {
    if (!root) return;
    document.documentElement.lang = locale;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(translateNode);
    root.querySelectorAll?.("[title]").forEach((el) => {
      if (!sourceTitle.has(el)) sourceTitle.set(el, el.getAttribute("title") || "");
      const value = sourceTitle.get(el);
      el.setAttribute("title", t(value));
    });
    root.querySelectorAll?.("[placeholder]").forEach((el) => {
      if (!sourcePlaceholder.has(el)) sourcePlaceholder.set(el, el.getAttribute("placeholder") || "");
      const value = sourcePlaceholder.get(el);
      el.setAttribute("placeholder", t(value));
    });
    const selector = document.querySelector("#tenantLocale");
    if (selector && selector.value !== locale) selector.value = locale;
  }

  async function loadTenant() {
    try {
      const response = await fetch("/api/tenant", { headers: { "Accept": "application/json" } });
      if (response.ok) {
        tenant = await response.json();
        if (["pt-BR", "en", "es"].includes(tenant.locale)) locale = tenant.locale;
      }
    } catch (_) {}
    apply();
    window.dispatchEvent(new CustomEvent("be-safe-locale-ready", { detail: { locale, tenant } }));
    return tenant;
  }

  function setLocale(next) {
    if (!["pt-BR", "en", "es"].includes(next)) return;
    locale = next;
    apply();
    window.dispatchEvent(new CustomEvent("be-safe-locale-changed", { detail: { locale, tenant } }));
  }

  window.BSI18N = {
    t, apply, loadTenant, setLocale,
    get locale() { return locale; },
    get tenant() { return tenant; },
    browserLocale,
  };

  document.addEventListener("DOMContentLoaded", loadTenant);
})();
