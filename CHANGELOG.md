## Unreleased — Planejamento de remediação dos hotspots

- Nova visualização somente leitura correlacionando hotspots e a fila de remediação existente por agent_id exato.
- Evidencia referências de patch por finding, candidatos indicados pela fila e lacunas de correlação sem presumir aplicabilidade.
- Limites explícitos de 100 hotspots e 500 findings exibidos; informa contagens omitidas.
- Testes de ordenação, correlação, limites e escaping integrados ao CI.

## Unreleased — Triagem operacional dos hotspots

- Nova visão somente leitura para cruzar até 100 endpoints do relatório de exposição com o inventário carregado, exclusivamente pelo agent_id.
- Evidencia agentes ausentes no inventário carregado, offline/heartbeat desconhecido, reboot e contagem independente de patches pendentes.
- Navegação ao drawer do endpoint apenas quando há correspondência exata; sem automação de execução ou correlação presumida finding–patch.
- Testes de correlação, limites da evidência e escaping de HTML adicionados ao CI.

## Unreleased — Exportação rastreável de Exposure Hotspots

- Botão de exportação CSV autenticada na visão executiva (até 100 endpoints ranqueados).
- Colunas para exposição observada, findings sem agente, datas inválidas e timestamp da coleta.
- Sanitização contra CSV/spreadsheet formula injection e testes Node executados pelo CI.
- Não confundir o top 100 com o conjunto inteiro; os agregados mantêm o escopo completo do relatório.

# Changelog

## 0.58.0

- control plane passa para versão 0.58.0; agente permanece em 0.16.0;
- adicionado Exception Budget / Risk Budget por owner ou business_service;
- budget controla quantidade mensal e horas mensais de waiver;
- relatório classifica utilização como healthy, warning ou exhausted;
- criação de waiver calcula consumo projetado antes da aprovação;
- estouro de budget escalona automaticamente o waiver para dual approval;
- endpoints de criação, atualização, listagem e relatório de budgets;
- auditoria registra criação e atualização de budgets.


## 0.57.0

- control plane e dashboard passam para versão 0.57.0; agente permanece em 0.16.0;
- Exception Governance adiciona dual approval para waiver em Tier 0 ou criticidade >=4;
- solicitante não pode fornecer a segunda aprovação;
- owner da exceção passa a ser obrigatório;
- waiver pending não suprime enforcement até completar quorum;
- máximo de 3 waivers ativos por campanha;
- novo endpoint de segunda aprovação;
- novo relatório de waiver governance com active, pending, expiring_24h, expired e revoked;
- relatório inclui ranking de policies mais excepcionadas e owners com mais waivers;
- console Policy Eval mostra owner/status e ação de segunda aprovação.


## 0.56.0

- control plane e dashboard passam para versão 0.56.0; agente permanece em 0.16.0;
- adicionado Patch Policy Waiver com vínculo campaign + policy version + SHA-256;
- waiver exige admin, motivo e expiração futura, limitada a 30 dias;
- violações continuam visíveis como waived em vez de serem removidas do relatório;
- somente waiver ativo e com digest idêntico à versão atual suprime enforcement;
- nova versão de policy invalida naturalmente waiver antigo por mudança de digest;
- endpoint de listagem, criação e revogação de waivers;
- auditoria registra criação e revogação com policy, versão, motivo e violações cobertas;
- Evidence Pack ganha seção policy_waivers;
- console Policy Eval permite criar waiver direto na violação.


## 0.55.0

- control plane e dashboard passam para versão 0.55.0; agente permanece em 0.16.0;
- adicionado bundle be-safe-patch-policy-bundle/v1 para fluxo GitOps;
- export inclui última versão de cada policy, SHA-256 por policy e manifest SHA-256 do bundle;
- validação de import rejeita schema inválido, policy duplicada, digest divergente, contagem divergente e bundle tampered;
- dry-run compara bundle proposto com campanhas existentes sem modificar estado;
- impacto classifica campanhas como newly_blocked, resolved, still_blocked ou still_compliant;
- dry-run detecta também mudanças de matching das policies;
- import validado cria nova versão local e preserva supersedes_id; policies idênticas ficam unchanged;
- auditoria do import registra digest do bundle, quantidade criada/inalterada e resumo de impacto;
- documentação GitOps adicionada ao README.


## 0.54.0

- control plane e dashboard passam para versão 0.54.0; agente permanece em 0.16.0;
- adicionado Patch Policy-as-Code com schema be-safe-patch-policy/v1;
- policies possuem versionamento imutável, SHA-256, prioridade, autor e supersedes_id;
- match suporta action, SO, tags, ambientes e criticidade mínima;
- requirements suportam ring inicial máximo, health gate, rollback, janela e quorum mínimo de aprovação;
- Preflight passa a avaliar a última versão habilitada por nome e bloquear violações;
- deploy inclui policy_as_code entre blockers obrigatórios;
- Evidence Pack ganha seção policy_as_code;
- API adiciona listagem, criação, nova versão, simulação e avaliação por campanha;
- console ganha botão Policy Eval com compliance, violações e digest da policy;
- Auto Patch Policy continua separado: ele decide quando propor/draftar remediação; Policy-as-Code governa se a campanha pode executar.


## 0.53.0

- control plane e dashboard passam para versão 0.53.0; agente permanece em 0.16.0;
- adicionado Explainable Change Risk Engine com score determinístico 0-100;
- fatores são decomponíveis, com pontos, evidência e fonte explícitos;
- engine reutiliza Blast Radius, Change Collision, Maintenance Risk, Applicability e Failure Intelligence;
- níveis LOW, MODERATE, HIGH e CRITICAL com thresholds documentados;
- risco de vulnerabilidade é separado de risco operacional: KEV, ransomware e EPSS entram apenas como urgency context;
- mudanças HIGH/CRITICAL passam a declarar controles mínimos requeridos;
- mudanças CRITICAL bloqueiam Preflight quando faltam health gate, rollback preparado, ring inicial <=10% ou janela de manutenção;
- deploy passa a respeitar o blocker change_risk;
- novo endpoint /api/admin/campaigns/{campaign_id}/change-risk;
- console ganha botão Change Risk com decomposição visual do score e controles ausentes;
- Evidence Pack ganha seção change_risk com score, fatores, modelo e urgency context;
- adicionados testes de explicabilidade, blocking de controles críticos e cenário low-risk sem blocker inventado.


## 0.52.0

- control plane e dashboard passam para versão 0.52.0; agente permanece em 0.16.0;
- Approval Gate evolui para CAB / Change Authority com quorum explícito;
- campanhas de install_updates com ativos criticality 4-5 ou tag Tier 0 passam a exigir automaticamente 2 aprovadores distintos;
- campanhas comuns configuradas com approval_required continuam exigindo 1 aprovação;
- solicitante não pode aprovar nem rejeitar a própria campanha;
- mesmo ator não pode votar duas vezes na mesma mudança;
- qualquer rejeição torna a decisão terminal;
- adicionada tabela campaign_approval_votes com ator, decisão, motivo e timestamp;
- campaign_approvals passa a persistir required_approvals e policy_json;
- Preflight exibe progresso de quorum e continua bloqueando deploy até atingir todas as aprovações;
- console passa a mostrar badge CAB com contagem aprovadas/necessárias;
- Evidence Pack preserva a trilha completa do Change Authority via seção approval;
- adicionados testes de enforcement automático Tier 0/critical, quorum duplo, voto duplicado e rejeição terminal.


## 0.51.0

- control plane e dashboard passam para versão 0.51.0; agente permanece em 0.16.0;
- adicionado Signed Evidence Attestation com Ed25519 para Campaign Evidence Packs;
- assinatura vincula produto, issuer, campaign_id, digest SHA-256, generated_at e signing_key_id;
- chave de attestation é independente da chave de assinatura de releases do agente;
- quando signing está habilitado, exportação falha fechada se a chave privada estiver ausente ou inválida;
- verificador do console passa a validar a assinatura com chave pública confiável e exibir issuer/key id;
- adicionado verificador offline scripts/verify-evidence-pack.py para auditoria independente do servidor;
- adicionado utilitário de geração e identificação de chave scripts/evidence-attestation-key.py;
- Docker Compose ganha mount dedicado /evidence-trust e configuração explícita por ambiente;
- exportação e verificação registram status da assinatura no audit trail;
- adicionados testes de assinatura válida, digest adulterado, assinatura adulterada e modo desabilitado.
- CI passa a executar um drill completo de geração de chave, assinatura e verificação offline;
- UX diferencia pacote íntegro de confiança efetivamente estabelecida por assinatura/âncora externa.


## 0.50.0

- control plane e dashboard passam para versão 0.50.0; agente permanece em 0.16.0;
- adicionado Evidence Pack Integrity Verifier;
- verificador recalcula SHA-256 do pacote e de cada seção e confere consistência entre conteúdo, section_hashes e manifest;
- validação pode receber SHA-256 confiável registrado fora do arquivo para detectar alteração seguida de recomputação dos hashes internos;
- verificador também valida schema e vínculo opcional com campaign_id esperado;
- console ganha ação Verify Pack com seleção local do JSON, resumo visual e estado de cada seção;
- verificações pela API geram audit event com resultado, digest calculado e divergências;
- adicionados testes de pacote íntegro, adulteração simples, adulteração com rehash e campaign binding.


## 0.49.0

- control plane e dashboard passam para versão 0.49.0; agente permanece em 0.16.0;
- adicionado Scope Drift Guard;
- campanhas novas capturam baseline de escopo na criação com SHA-256 próprio;
- baseline inclui agent id, hostname, SO/versão, tags, business service, environment, owner, criticidade e exposição externa;
- endpoint entrando ou saindo do escopo após criação bloqueia deploy;
- mudanças de contexto sem mudança de membership geram warning;
- campanhas legadas sem baseline recebem warning, sem blocker retroativo;
- console ganha ação Scope Drift;
- Preflight ganha check Scope Drift Guard;
- Evidence Pack passa a incluir scope_drift com SHA-256 próprio;
- adicionados testes de asset entering/leaving scope, context drift, estabilidade e integridade do Evidence Pack.


## 0.48.0

- control plane e dashboard passam para versão 0.48.0; agente permanece em 0.16.0;
- adicionado Maintenance Risk & Reboot Orchestration;
- campanhas cruzam reboot pendente, Patch Catalog, applicability por endpoint, criticidade, serviços críticos, reboot policy e janela;
- reboot requerido por patch com policy `never` passa a bloquear o deploy antes da criação dos jobs;
- ativos críticos com reboot provável ou pendente geram warning explicável;
- janela de manutenção é comparada com mediana e p95 de duração observada quando existem pelo menos 3 jobs comparáveis;
- metadata de reboot desconhecida permanece explícita, sem inferência;
- console ganha ação Reboot Plan;
- Preflight ganha check Maintenance & Reboot Readiness;
- Evidence Pack passa a incluir maintenance_risk com SHA-256 próprio;
- adicionados testes de conflito de reboot, ativo crítico, capacidade da janela e integridade do Evidence Pack.


## 0.47.0

- control plane e dashboard passam para versão 0.47.0; agente permanece em 0.16.0;
- adicionado Tenant Settings persistente;
- locales suportados: pt-BR, en e es;
- pt-BR permanece como idioma padrão;
- GET /api/tenant disponibiliza configuração pública de locale antes do login;
- PUT /api/admin/tenant permite ao admin alterar o idioma padrão do tenant com auditoria;
- console ganha seletor PT-BR / EN / ES no topo;
- usuários não-admin podem trocar o idioma apenas localmente sem alterar o tenant;
- adicionado runtime i18n com fallback em PT-BR;
- datas e horários passam a respeitar o locale ativo;
- adicionada migration 0031_tenant_locale;
- adicionados testes de persistência e auditoria da configuração do tenant.


## 0.46.0

- control plane e dashboard passam para versão 0.46.0; agente permanece em 0.16.0;
- adicionado Patch Applicability & Supersedence Guard;
- campanhas cruzam os pacotes com Patch Catalog, lifecycle, grafo de supersedence e applicability real por endpoint;
- patch superseded com replacement leaf conhecido passa a bloquear deploy;
- patch sem nenhum endpoint missing, quando todos os alvos possuem observação, passa a bloquear deploy como not applicable;
- EOL, metadata stale e applicability parcial/ausente geram warning explicável;
- Preflight ganha check Patch Applicability & Supersedence;
- console ganha ação Applicability por campanha;
- Evidence Pack passa a incluir patch_applicability com SHA-256 próprio;
- adicionados testes de supersedence e ausência comprovada de applicability.


## 0.45.0

- control plane e dashboard passam para versão 0.45.0; agente permanece em 0.16.0;
- adicionado Change Collision Guard entre campanhas;
- colisão direta identifica o mesmo endpoint com job não terminal em outra campanha e bloqueia o deploy;
- colisões de business service + environment e owner geram warning explicável, sem impor política de CAB;
- relatório mostra campanhas concorrentes, jobs ativos, endpoints, services, environments e owners envolvidos;
- Preflight ganha check Change Collision Guard;
- console ganha ação Collision Guard por campanha;
- Evidence Pack passa a incluir change_collisions com SHA-256 próprio;
- jobs terminais não são considerados colisão ativa;
- adicionados testes de colisão direta, colisão contextual, jobs terminais e integridade do Evidence Pack.


## 0.44.0

- control plane e dashboard passam para versão 0.44.0; agente permanece em 0.16.0;
- adicionado Smart Canary / Adaptive Ring Planner;
- campanhas novas usam estratégia balanced coverage-first por padrão; campanhas legadas sem configuração continuam no modo hash;
- seleção balanceada prioriza menor representação de business service, environment, segmento de SO/versão e owner;
- teto preferencial de ativos críticos no canário é configurável por campanha;
- hash estável do agent é usado somente como desempate final no modo balanced;
- seleção é determinística e explicável, sem score composto oculto;
- console ganha ação Smart Canary e controles de estratégia/teto crítico no formulário de campanha;
- Preflight ganha check Smart Canary;
- Evidence Pack passa a incluir ring_plan com SHA-256 próprio;
- adicionados testes de determinismo, diversidade, critical cap, fallback e integridade no Evidence Pack.


## 0.43.0

- control plane e dashboard passam para versão 0.43.0; agente permanece em 0.16.0;
- adicionado Blast Radius Intelligence / Change Impact Preview por campanha;
- impacto do ring reutiliza Asset Risk, criticality, external exposure, risk appetite, owner, business service e environment;
- relatório mostra escopo total, ring real, concentração, ativos críticos, externos, acima do appetite e críticos sem owner;
- estados explícitos: contained, concentrated e critical_scope;
- regras de classificação são documentadas e não usam score composto oculto;
- Preflight passa a incluir Blast Radius como warning explicável, sem bloquear por padrão;
- Evidence Pack passa a incluir a seção blast_radius com SHA-256 próprio;
- console ganha ação Impact Preview;
- adicionados testes de Business Context, criticidade, concentração, warning do Preflight e integridade no Evidence Pack.


## 0.42.0

- control plane e dashboard passam para versão 0.42.0; agente permanece em 0.16.0;
- adicionado Patch Failure Intelligence baseado exclusivamente no histórico local observado;
- falhas são agrupadas por patch, SO, versão, categoria e assinatura normalizada;
- assinaturas removem valores voláteis como URL, hex e números longos para reduzir fragmentação de clusters;
- categorias incluem install, download/network, dependency, reboot, disk, permission, applicability, stalled, compatibility, post-patch regression e rollback;
- estados por segmento passam a ser stable, observed_failures, elevated_failure_rate ou confirmed_local_regression;
- regressão local confirmada exige no mínimo 3 resultados comparáveis, 2 falhas efetivas e taxa >=50%;
- Campaign Preflight cruza patch + SO/versão do ring com a inteligência local e bloqueia regressões confirmadas antes de criar jobs;
- console ganha ação Failure Intel por campanha;
- adicionado endpoint de relatório /api/admin/reports/patch-failure-intelligence;
- adicionados testes de clustering, normalização, matching por patch e bloqueio do Preflight.


## 0.41.0

- control plane e dashboard passam para versão 0.41.0; agente permanece em 0.16.0;
- adicionado Campaign Evidence Pack exportável por campanha;
- pack consolida configuração, approval, preflight snapshots, decisões de rings, jobs, health/validation, rollback, remediation evidence, freeze override e audit trail;
- manifest inclui SHA-256 do pacote e SHA-256 individual por seção;
- hashing usa JSON canonicalizado com chaves ordenadas para verificação reproduzível fora da plataforma;
- console ganha ação Evidence Pack e download direto em JSON;
- exportação gera evento de auditoria próprio com digest e resumo do pacote;
- adicionados testes de integridade do manifest e preservação de evidências de job.


## 0.40.0

- control plane e dashboard passam para versão 0.40.0; agente permanece em 0.16.0;
- adicionado Preflight Evidence Ledger com snapshots imutáveis por campanha;
- cada snapshot registra readiness, deploy_allowed, resumo, resultado completo, ator, origem, timestamp e SHA-256;
- adicionado Drift Detection entre o estado atual e o último snapshot;
- drift classifica NO_BASELINE, UNCHANGED, IMPROVED, CHANGED ou DEGRADED e lista cada gate alterado;
- tentativas de deploy passam a registrar automaticamente o preflight observado naquele momento;
- console permite registrar snapshot manual, visualizar drift e consultar histórico de evidências;
- adicionada migration 0030_campaign_preflight_snapshots;
- adicionados testes de hashing, persistência, drift e snapshot automático no deploy.


## 0.39.0

- control plane e dashboard passam para versão 0.39.0; agente permanece em 0.16.0;
- adicionado Campaign Preflight / Change Readiness antes do deploy;
- preflight consolida scope, Approval Gate, Change Freeze, Patch Guard, compatibilidade/capabilities de agente, heartbeat, mTLS, maintenance window e Patch Confidence;
- readiness é explícito em READY, REVIEW ou BLOCKED, sem score composto oculto;
- enforcement de compatibilidade e mTLS podem bloquear o deploy antes da criação de jobs;
- console ganha painel visual de preflight dentro de cada campanha;
- deploy retorna o snapshot completo do preflight quando um controle impeditivo bloqueia a mudança;
- adicionados testes para approval pendente, Patch Guard, incompatibilidade de agente e heartbeat stale.


## 0.38.0

- control plane e dashboard passam para versão 0.38.0; agente permanece em 0.16.0;
- adicionada Regression Intelligence por ring, sem score composto opaco;
- comparação usa success rate, failure rate, falhas de validação pós-patch e duração média observada dos jobs;
- campanhas ganham promotion_max_success_drop em pontos percentuais;
- regressão acima do limite pausa promoção mesmo quando o threshold absoluto de sucesso ainda é atendido;
- Safe Promotion retorna STABLE, REGRESSION ou NO_BASELINE, deltas, motivos e recomendação;
- console exibe badge de regressão, recomendação e ação Safe Promotion;
- adicionado endpoint promotion-analysis e testes de regressão, estabilidade e pause.

## 0.37.0

- control plane e dashboard passam para versão 0.37.0; agente permanece em 0.16.0;
- adicionado Progressive Rollout Governance com rollout_plan, soak_minutes, promotion_min_success_rate e pause_on_failure;
- campanhas passam a expor estados DRAFT, RUNNING, SOAK, PROMOTE, PAUSE e COMPLETE;
- avanço de ring respeita o próximo ring configurado e bloqueia promoção durante soak ou pause, mantendo override explícito auditável;
- campaign_health passa a usar o threshold configurado de sucesso para campanhas de patch;
- adicionada migration 0029_campaign_ring_decisions para histórico imutável de deploy/promoções;
- deploy inicial e cada promoção persistem from_ring, to_ring, decisão, ator, motivo e snapshot de health;
- console ganha configuração de plano/soak/threshold e usa o next_ring da campanha no lugar de preset global;
- adicionados testes de SOAK, PROMOTE, PAUSE, COMPLETE e threshold configurável.

## 0.36.0

- control plane e dashboard passam para versão 0.36.0; agente permanece em 0.16.0;
- adicionada migration 0028_auto_patch_evaluations e Decision Ledger imutável para avaliações explícitas;
- Auto Patch Simulation passa a mostrar funil de escopo: missing total, excluídos por OS, tag e external, selecionados e amostra de ativos;
- decisões elegíveis expõem blast radius do ring inicial em percentual e quantidade de endpoints;
- cada POST de evaluate persiste ator, modo, summary e snapshot completo das decisões; consultas de histórico não reexecutam policies;
- console ganha tabela de histórico, detalhe do ledger e ação Simular por policy/patch;
- adicionados testes de scope funnel, persistência do ledger, simulation e blast radius.

## 0.35.0

- control plane e dashboard passam para versão 0.35.0; agente permanece em 0.16.0;
- adicionado Auto Patch Policy Engine persistente com migration 0027_auto_patch_policies;
- policies operam em `recommend` ou `draft`; não existe auto-deploy nesta versão;
- condições suportam KEV, exposição externa, Patch Tuesday, mínimo de ativos, confidence floor, OS/tag, EOL e supersedence;
- KEV + external força canary de até 5%; Patch Tuesday mantém pilot de até 10%;
- confidence abaixo do floor gera hold; EOL é bloqueado por padrão; replacement superseded exige leaf observada como missing;
- Patch Guard e Change Freeze bloqueiam antes da criação de draft; Approval Gate, health gate e rollback são herdados;
- targeting consulta `patch_applicability` completo e drafts são deduplicados por policy + effective patch;
- console ganha workspace Auto Patch Policy com criação de policy, avaliação explicável e criação de drafts elegíveis;
- adicionados testes de emergency canary, confidence hold, Patch Guard e deduplicação de draft.

## 0.34.0

- control plane e dashboard passam para versão 0.34.0; agente permanece em 0.16.0;
- adicionados adapters oficiais `msrc_cvrf` e `ubuntu_security` ao Patch Feed Orchestrator;
- MSRC CVRF v3 parser consolida Vendor Fix por KB e extrai CVEs, produto, severidade, release date e supersedence;
- Ubuntu Security API adapter consulta notices/details e converte pacotes corrigidos em metadata compatível com patch refs Linux;
- adapters usam somente HTTPS hardcoded, timeout, limite de 12 MiB e conditional GET com ETag/Last-Modified;
- adicionada migration 0026_patch_feed_adapter_state para configuração e cache/state por provider;
- configuração do adapter fica separada de estado/cache para não misturar governança com transporte;
- adicionados testes com fixtures para parser MSRC, parser Ubuntu, dispatch e cache 304.

## 0.33.0

- control plane e dashboard passam para versão 0.33.0; agente permanece em 0.16.0;
- adicionado Change Freeze / Blackout Calendar persistente com migration 0025_change_freeze;
- janelas podem ser segmentadas por sistema operacional e tag;
- deploy de campanha e avanço de ring falham fechado durante freeze ativa;
- emergency override por campanha exige administrador e justificativa auditada;
- override pode ser revogado e volta a bloquear a campanha imediatamente;
- console ganha painel Change Freeze com status ativo/agendado, escopo e período;
- adicionados testes de matching, bloqueio, override e revogação.

## 0.32.0

- control plane e dashboard passam para versão 0.32.0; agente permanece em 0.16.0;
- adicionado Patch Feed Orchestrator com providers persistentes, health, scheduling e sync manual;
- adicionada migration 0024_patch_feed_providers;
- provider curated passa a alimentar o Patch Metadata Enrichment Engine usando priority/TTL próprios;
- circuit breaker abre após N falhas consecutivas e usa cooldown configurável; reset administrativo disponível;
- worker em background sincroniza apenas providers enabled e due, compartilhando lock com sync manual;
- console ganha painel de providers com status, record count, último sucesso, erro e ações de sync/reset;
- adicionados testes de scheduling, sync, failure counter, circuit open e reset.

## 0.31.0

- control plane e dashboard passam para versão 0.31.0; agente permanece em 0.16.0;
- adicionado Patch Metadata Enrichment Engine com importação em lote, dry-run, prioridade de fonte e TTL;
- adicionada migration 0023_patch_metadata_evidence e tabela de evidências por patch/fonte;
- provenance passa a ser field-level: source, priority, observed_at, expires_at e actor por campo;
- conflito de fonte inferior é registrado sem sobrescrever metadata mais confiável;
- manual lifecycle recebe prioridade máxima (1000), preservando decisão administrativa explícita;
- CVEs fornecidas por metadata enrichment passam a complementar CVEs vindas do scanner sem substituí-las;
- Patch Catalog mostra metadata stale e conflitos e resume a saúde do enrichment;
- adicionados testes de precedence, dry-run, stale metadata, conflito e CVE merge.

## 0.30.0

- control plane e dashboard passam para versão 0.30.0; agente permanece em 0.16.0;
- Patch Catalog ganha lifecycle governado: classificação, release date, EOL, fonte e auditoria;
- adicionada migration 0022_patch_lifecycle;
- supersedence passa a formar grafo com `supersedes`, `superseded_by`, replacement chain, leaf replacement e estado obsolete;
- deployment readiness ganha estado `superseded` e recomenda a leaf patch em vez da atualização obsoleta;
- patches EOL entram em review, sem serem classificadas automaticamente como seguras para deploy;
- Patch Tuesday intelligence calcula a janela do segundo Tuesday somente a partir de release date explícita;
- console exibe Patch Tuesday, EOL, idade, supersedence e permite manutenção administrativa auditada do lifecycle;
- adicionados testes de Patch Tuesday, grafo de supersedence, leaf selection, EOL e update de lifecycle.

## 0.29.0

- control plane e dashboard passam para versão 0.29.0; agente permanece em 0.16.0;
- adicionado Patch Intelligence / Patch Catalog persistente com migration 0021_patch_catalog;
- heartbeats passam a alimentar catálogo normalizado por patch reference e estado por endpoint;
- `missing` vem diretamente do scan; `installed_inferred` exige desaparecimento após job de instalação bem-sucedido; demais deltas ficam `no_longer_reported`;
- catálogo correlaciona Patch Confidence local, CVEs abertas, KEV/ransomware context e Patch Guard;
- novo deployment readiness explicável: blocked, review, pilot, ready_with_controls, ready ou not_applicable;
- console ganha visão Patch Catalog com cobertura, evidência e readiness sem chamar ausência de scan de instalação comprovada;
- adicionados testes de sincronização, inferência pós-job e readiness bloqueado.

## 0.28.0

- control plane e dashboard passam para versão 0.28.0; agente permanece em 0.16.0;
- adicionado Approval Gate persistente por campanha com migration 0020_campaign_approvals;
- campanhas podem exigir aprovação administrativa antes do primeiro deploy, com motivo da solicitação e decisão auditada;
- segregação de função impede o solicitante de aprovar a própria campanha;
- deploy falha fechado enquanto aprovação obrigatória estiver pending, rejected ou ausente;
- Remediation Decision Engine passa a recomendar Approval Gate automaticamente para P0 ou change risk alto;
- drafts preparados pelo Remediation Hub herdam a exigência e o motivo sugerido, mantendo decisão humana separada do deploy;
- console mostra estado de aprovação por campanha e permite approve/reject para admins;
- adicionados testes para pending gate, aprovação por segundo ator e bloqueio de self-approval.

## 0.27.0

- control plane e dashboard passam para versão 0.27.0; agente permanece em 0.16.0;
- adicionado Patch Guard persistente com migration 0019_patch_block_rules;
- admins podem bloquear patch references globalmente ou por SO/tag, com motivo, expiração opcional, enable/disable e auditoria;
- deploy inicial e avanço de ring de campanhas install_updates passam a falhar antes da criação de jobs quando uma regra ativa casa com o patch e os endpoints do lote;
- API expõe listagem e gestão das regras com RBAC viewer/admin;
- console de Campanhas ganha workspace Patch Guard com status, escopo, expiração e ações administrativas;
- Remediation Hub passa a exibir contadores P0/P1 e change risk alto; corrigido colspan da tabela após a inclusão da nova coluna;
- adicionados testes de matching por SO/tag, expiração e bloqueio fail-closed no deploy.

## 0.26.0

- control plane e dashboard passam para versão 0.26.0; agente permanece em 0.16.0;
- Remediation Hub ganha um Decision Engine explicável por grupo de patch, sem score opaco adicional;
- prioridade operacional passa a ser P0/P1/P2/P3 com razões objetivas baseadas em CISA KEV, ransomware known, EPSS, SLA, exposição externa e criticidade do ativo;
- risco da vulnerabilidade e risco da mudança ficam separados: change_risk usa Patch Confidence local, criticidade e blast radius;
- cada grupo passa a expor plano de rollout recomendado por rings, incluindo canário de 5% quando o change risk é alto e a população permite;
- guidance informa health gate obrigatório, checkpoint de rollback recomendado/obrigatório e necessidade de janela de manutenção;
- draft criado pelo Remediation Hub herda ring inicial, health gate e rollback do guidance, mas continua sem executar deploy automaticamente;
- console mostra prioridade, change risk, sinais críticos e sequência de rings diretamente no Remediation Hub;
- ordenação do Hub passa a priorizar P0/P1 antes da redução projetada de risco;
- adicionados testes unitários do Decision Engine para emergência KEV/ransomware, change risk alto e rollout de baixo risco.

## 0.25.0

- control plane e dashboard passam para versão 0.25.0; agente permanece em 0.16.0;
- migration `0018_project_scope` adiciona filtros contextuais persistentes aos Remediation Projects;
- escopo pode combinar patch reference com tag, business service, environment, asset owner, exposição externa/interna e criticidade mínima;
- filtros usam o mesmo Asset Accountability / Risk Profile já existente, evitando taxonomia paralela;
- projetos `static` aplicam o filtro na criação e congelam os finding IDs resultantes;
- projetos `dynamic` reavaliam continuamente os filtros contextuais e deixam entradas/saídas explícitas como novos findings ou scope drift;
- mudança de business service/environment/owner/exposure/criticalidade não é contada falsamente como remediação;
- API de criação de projeto passa a aceitar filtros contextuais opcionais;
- console ganhou filtros contextuais no modal de criação e passa a mostrar a regra efetiva de escopo em cada projeto;
- adicionados testes cobrindo combinação de business context, exposição, criticidade e mudança dinâmica de contexto.

## 0.24.0

- control plane e dashboard passam para versão 0.24.0; agente permanece em 0.16.0;
- migration `0017_project_intel` enriquece o histórico de Remediation Projects;
- projetos passam a calcular risco restante, risco reduzido desde o baseline e progresso percentual de redução de risco;
- progresso operacional passa a ser comparado com progresso esperado pelo prazo, expondo schedule variance;
- Project Intelligence inclui KEV, SLA vencido/próximo, ativos externos, aging médio/máximo, EPSS médio/máximo e contexto de business service/owner;
- attention state distingue `critical`, `needs_attention`, `watch` e `on_track` sem criar score opaco adicional;
- histórico de projeto persiste risk burndown, threat/SLA signals, exposição, aging e attention state;
- consultas de projeto passam a preload de risk profile e vulnerabilities para reduzir N+1;
- console de Remediation Projects foi ampliada com redução de risco, threat/SLA, schedule variance e attention state;
- Prometheus expõe atenção de projetos, risco restante/reduzido, KEV e SLA vencido;
- adicionados alertas para projetos críticos e findings de projeto com SLA vencido;
- Grafana ganhou painéis de projetos críticos, risco restante, risco reduzido e SLA vencido;
- adicionados testes para inteligência de projeto, risk burndown e observabilidade.

## 0.23.0

- control plane e dashboard passam para versão 0.23.0; agente permanece em 0.16.0;
- adicionados Remediation Projects persistentes com migration `0015_remediation_projects`;
- projetos agrupam trabalho por patch reference sem executar patch automaticamente;
- cada projeto possui owner, prazo, status, baseline de findings/ativos, redução potencial inicial, motivo e trilha de auditoria;
- escopo `static` congela os findings iniciais; escopo `dynamic` incorpora novos findings da mesma patch/tag;
- scope drift é explícito: finding que sai da tag ainda aberto não é contabilizado como remediado;
- progresso usa backlog realmente rastreado e não concede progresso falso por mudança de escopo;
- projeto não pode ser concluído enquanto ainda houver findings rastreados abertos;
- lifecycle suporta `active`, `awaiting_verification`, `completed` e `cancelled`;
- Remediation Hub passa a oferecer criação direta de projeto;
- console ganha workspace de Remediation Projects com baseline/current, drift, progresso, owner, prazo e status;
- projeto elegível pode pré-preencher draft de campanha com população exata de até 500 endpoints;
- campanha continua separada do projeto e exige revisão explícita de ring, janela, health gate e deploy;
- adicionados testes para static/dynamic scope, progresso, conclusão, auditoria e scope drift.
- migration `0016_remediation_project_history` adiciona burndown persistente dos Remediation Projects;
- snapshots registram backlog rastreado, escopo atual, ativos, fechamentos, novos findings, scope drift, progresso e origem;
- histórico é capturado em criação/alteração do projeto e em mudanças relevantes de vulnerability backlog, com debounce nos syncs automáticos;
- console ganhou timeline de burndown por Remediation Project.
- Prometheus passa a expor Remediation Projects e Risk Reduction Goals por status, além de contadores de itens vencidos;
- adicionados alertas para Remediation Projects e Risk Reduction Goals vencidos.

## 0.22.0

- control plane e dashboard passam para versão 0.22.0; agente permanece em 0.16.0;
- adicionados Risk Reduction Goals persistentes com migration `0014_risk_reduction_goals`;
- goals suportam baseline congelado, target máximo, owner, prazo, escopo global ou dinâmico por tag e trilha de auditoria;
- métricas suportadas incluem Asset Risk médio, ativos acima do appetite, findings abertos e ativos Critical/High;
- valor atual é recalculado sobre o escopo vivo sem reescrever o baseline histórico;
- progresso é calculado contra baseline → target e o pace indica `on_track`, `at_risk`, `overdue`, `achieved`, `completed` ou `cancelled`;
- conclusão manual exige que o target esteja realmente atingido;
- console ganha Risk Reduction Goals na overview com criação e gestão via governance workspace;
- overview ganha Risk Program Overview com exposure backlog, threat-active assets, owner coverage, MTTR, evidência verificada, patch success, goals e maior alavanca do Remediation Hub;
- a visão executiva não cria score agregado oculto; ela apresenta métricas observáveis e explicáveis do ambiente;
- adicionados testes de baseline, progresso, escopo por tag, conclusão e overdue.

## 0.21.0

- control plane passa para versão 0.21.0; agente permanece em 0.16.0;
- campanhas passam a suportar população exata multi-asset congelada no momento da criação;
- Remediation Hub pode preparar draft de campanha diretamente a partir do grupo de patch, preservando a lista exata de endpoints alvo;
- encoding de patch refs no fluxo da console foi endurecido;
- adicionados testes de targeting multi-asset;
- Risk Acceptance, Risk Profile, Risk Policy e Treatment Plan deixam de depender de prompts simples e passam a usar workspace modal de governança;
- Remediation Hub passa a produzir deployment guidance com base no Patch Confidence local;
- guidance diferencia coleta de evidência, revisão de falhas, pilot e controlled rollout;
- draft preparado pelo Remediation Hub usa ring sugerido pelo guidance, mas continua exigindo revisão humana antes do deploy;
- adicionados testes do deployment guidance.

## 0.20.0

- control plane e dashboard passam para versão 0.20.0; agente permanece em 0.16.0;
- adicionado Remediation Hub agrupando findings pela mesma patch reference;
- impacto do Remediation Hub é recalculado por ativo antes da agregação, evitando soma incorreta de deltas independentes;
- grupos exibem findings cobertos, ativos afetados, CVEs, redução projetada e quantidade de ativos que cruzariam abaixo do appetite;
- adicionado Asset Accountability em `AssetRiskProfile` com owner, business service e environment;
- migration `0013_asset_accountability` adiciona o contexto de accountability sem alterar a fórmula do Asset Risk;
- relatório de Asset Risk passa a mostrar cobertura de owner e ativos críticos/altos sem owner;
- console exibe accountability por ativo e permite editar o contexto no perfil de risco;
- adicionado Active Threat Watch baseado em sinais objetivos de CISA KEV, EPSS alto e ransomware known;
- Active Threat Watch agrupa por CVE e mostra ativos afetados, exposição externa, criticidade, patch refs e sinais de ameaça;
- adicionado Patch Confidence baseado no histórico local de jobs `install_updates`;
- Patch Confidence mostra success rate, amostra, falhas, stalled/blocked e classificação high/medium/low/insufficient_data;
- Remediation Hub passa a exibir Patch Confidence quando existe histórico local da mesma patch reference;
- adicionado Business Context report por owner, business service e environment, com risco médio/máximo, appetite e coverage de governança;
- adicionado Remediation Performance report com MTTR, success rate, evidência verificada, patch duration e breaches abertos;
- tendência de Asset Risk passa a carregar os dois snapshots mais recentes de toda a frota em uma única query com window function;
- overview executivo passa a mostrar Threat Watch, Remediation Groups, Patch Confidence baixa e Owner Coverage;
- documentação deixa explícito que Active Threat Watch não é classificação própria de threat research e que Patch Confidence não representa telemetria global de fabricante.

## 0.19.0

- control plane e dashboard passam para versão 0.19.0; agente permanece em 0.16.0;
- Risk Acceptance e Treatment Plan agora só podem ser criados quando o ativo está acima do appetite efetivo;
- criação concorrente de governança é serializada por ativo no backend;
- campos administrativos relevantes são validados também após trim para impedir valores compostos apenas por espaços;
- mudanças de Risk Profile, Risk Policy, Risk Acceptance e Treatment Plan geram snapshots imediatos dos ativos afetados;
- snapshots históricos persistem model version, decomposition, cálculo, policy/appetite e estado de governança;
- adicionado retention configurável de snapshots via `ASSET_RISK_HISTORY_RETENTION_DAYS`;
- Risk Reduction Simulation, Opportunities e Plan permitem estimar impacto e ordenar remediação sem alterar estado real;
- etapas elegíveis do plano podem pré-preencher campanhas, mantendo criação e deploy explícitos;
- timeline de Asset Risk fica disponível na console para viewer/operator/admin;
- top contributors passam a informar ativos afetados e participação percentual;
- relatório e oportunidades de risco reduzem consultas repetidas por policy e relacionamentos;
- listagem de vulnerabilidades passa a ordenar por risco antes de aplicar o limit, evitando ocultar finding antigo e urgente;
- Threat Intel expõe freshness, age, degraded e stale em Prometheus;
- adicionados alertas de Threat Intel stale/degraded e novos painéis Grafana;
- overview executivo passa a mostrar risco aceito, em tratamento, treatment vencido e risco acima do appetite sem ação;
- exceções de SLA passam a impor máximo de 365 dias, validação pós-trim e lock concorrente no finding;
- documentação e imagens de features foram atualizadas para refletir a arquitetura e a console atuais.

## 0.18.0

- control plane e dashboard passam para versão 0.18.0; agente permanece em 0.16.0;
- adicionado SLA configurável de vulnerabilidades por severidade;
- findings abertos passam a receber prazo, idade, horas restantes e estado `within_sla`, `due_soon` ou `breached`;
- estados não abertos permanecem visíveis como `excluded` e não inflam breach counters;
- novo endpoint `GET /api/admin/reports/vulnerability-sla` consolida política, totais, severidade e findings priorizados;
- summary administrativo passa a expor vulnerabilidades em breach e próximas do vencimento;
- dashboard mostra cards de SLA e estado por finding na tabela de vulnerabilidades;
- adicionadas exceções formais de SLA com motivo, aprovador, validade e revogação auditada;
- exceção ativa pausa o contador de breach sem alterar o status real do finding;
- expiração devolve automaticamente o finding ao cálculo normal de SLA;
- adicionada priorização contextual com score 0–100 e razões explicáveis;
- score combina CVSS, EPSS/KEV quando presentes, idade do finding e tags de criticidade/exposição do endpoint;
- dashboard mostra risco contextual e total de findings urgentes;
- adicionada integração opcional de threat intel com FIRST EPSS e CISA KEV;
- sync enriquece findings abertos sem sobrescrever evidência original do scanner;
- falha de uma fonte mantém a outra ativa e sinaliza estado degradado;
- worker opcional executa sync periódico e o operador pode solicitar sync manual;
- adicionada fila de remediação orientada a risco e SLA, com recomendação de próxima ação e justificativas;
- findings elegíveis podem abrir a campanha pré-preenchida, mas continuam exigindo revisão humana antes do deploy;
- adicionada camada de risco por ativo 0–1000, criticidade 1–5, exposição externa e fatores compensatórios;
- adicionado risk appetite configurável e contagem de ativos acima do limite;
- adicionados snapshots persistentes do risco por ativo e migration `0007_risk_history`;
- Greenbone e Threat Intel geram snapshots com intervalo mínimo para evitar ruído;
- console mostra tendência de risco (`up`, `down`, `flat`, `new`) e permite snapshot manual auditado;
- adicionada decomposição explicável do Asset Risk e ranking global de `top_contributors`;
- adicionada documentação técnica completa em `docs/risk-model.md` com fórmula, escalas, APIs, exemplos e princípios de segurança;
- adicionado `AssetRiskProfile` persistente com migration `0008_risk_profiles`;
- admin pode sobrescrever criticidade, exposição e controles por ativo, com precedência `profile > tags > default`;
- alterações de perfil exigem motivo, ficam auditadas e geram novo snapshot de risco;
- console permite editar o perfil de risco diretamente no ranking de ativos;
- adicionadas políticas de risk appetite por tag via `asset_risk_policies` e migration `0009_risk_policies`;
- políticas possuem prioridade, enable/disable, auditoria e fallback para `ASSET_RISK_APPETITE`;
- relatório de Asset Risk passa a indicar policy efetiva, appetite por ativo e estado acima/abaixo do limite;
- console permite criar e editar políticas de appetite por tag;
- adicionada aceitação temporária de Asset Risk via `asset_risk_acceptances` e migration `0010_risk_accept`;
- aceite não reduz score nem altera evidência; apenas muda o estado de governança para `accepted` enquanto válido;
- aceitações exigem admin, motivo e validade de até 365 dias, com revogação e auditoria;
- console separa ativos acima do appetite em aceitos e não aceitos;
- adicionado `AssetRiskTreatment` e migration `0011_risk_treatment`;
- Treatment Plans possuem owner, ação, prazo, estados `planned/in_progress/completed/cancelled` e evidência obrigatória na conclusão;
- relatório distingue `in_treatment`, `treatment_overdue`, `accepted` e `above_appetite`;
- console permite criar e atualizar planos de tratamento por ativo;
- endurecida a normalização de EPSS e flags booleanas para evitar falsos positivos por strings como `false`;
- EPSS percentual é suportado e valores fora de `0..1` são rejeitados em vez de clampados;
- tags de exposição deixaram de elevar também a criticidade, removendo double count de contexto;
- tendência de Asset Risk passa a comparar com o snapshot anterior quando o snapshot mais recente já representa o score atual;
- adicionada Risk Reduction Simulation por ativo/finding via `/api/admin/agents/{agent_id}/risk-simulation`;
- simulação calcula before/after, delta, percentual de redução e cruzamento abaixo do appetite sem mutar findings, evidência, campanhas ou histórico;
- console ganhou ação `Simular impacto` e painel de resultado projetado;
- adicionado relatório `risk-reduction-opportunities` com ranking por redução projetada de Asset Risk;
- oportunidades incluem impacto individual, appetite, SLA e ação recomendada, sem mutar o estado real;
- removido agregado de redução total porque simulações individuais não são matematicamente aditivas;
- console ganhou tabela de oportunidades priorizadas por maior redução de risco;
- adicionado Risk Reduction Plan por ativo com seleção gulosa de maior ganho marginal e recálculo a cada etapa;
- plano informa score antes/depois, redução marginal, redução acumulada e cruzamento do appetite;
- console ganhou ação `Plano de redução` e painel de sequência projetada;
- etapas do Risk Reduction Plan agora expõem elegibilidade de campanha e referências de patch;
- console permite `Preparar campanha` a partir de uma etapa elegível, apenas pré-preenchendo o draft; deploy continua separado;
- migration `0012_risk_snapshot_details` enriquece snapshots de Asset Risk com model version, decomposition, cálculo, policy/appetite e governança;
- histórico passa a explicar o score histórico sem depender de recálculo com regras futuras;
- Asset Risk agora expõe `calculation` com base, multiplicadores, raw score e cap aplicado;
- console ganhou Asset Risk Timeline por ativo com score, delta, appetite/policy, governança, model version e origem de cada snapshot;
- Timeline e Risk Reduction Plan passam a ficar visíveis também para viewer, mantendo alterações de governança restritas;
- corrigido ID da revision Alembic 0006 para respeitar o limite da tabela `alembic_version` no PostgreSQL;
- configuração do SLA é feita por variáveis de ambiente, sem migration ou mudança no agente;
- adicionados testes de breach, due soon, exclusão, agregação e summary.

## 0.17.0

- control plane e dashboard passam para versão 0.17.0; agente permanece em 0.16.0;
- aprovações de ativação do agente ganham TTL configurável;
- endpoints precisam apresentar heartbeat recente para nova aprovação;
- aprovação fica vinculada à versão, SHA-256, source commit e signing key id da release assinada;
- claim revalida expiração, identidade staged e release atualmente publicada;
- autorização inválida é encerrada como `skipped` antes da emissão de claim token;
- avanço de ring renova a janela curta de aprovação somente para o novo lote;
- mudança da release publicada bloqueia continuidade de rollout já aprovado;
- adicionado preview administrativo de rollout do agente;
- preview usa o mesmo snapshot determinístico e explica motivos de inelegibilidade;
- console recalcula o preview imediatamente antes da confirmação;
- Prometheus passa a expor aprovações pendentes, próximas de expirar, expiradas e invalidadas;
- adicionados alertas para aprovação expirada ou próxima do vencimento;
- adicionados testes de autorização expirada, drift de release, heartbeat antigo, preview e renovação por ring.

## 0.16.0

- agente e control plane passam para versão 0.16.0;
- releases que sofrem rollback do watchdog entram em quarentena no endpoint;
- nova ativação da mesma release fica bloqueada até liberação explícita;
- liberação da quarentena exige admin, motivo e confirmação de risco;
- adicionada capability `signed_update_quarantine_v1`;
- rollout do próprio agente passa a usar rings 10%, 30% e 100%;
- população elegível do rollout é congelada no momento da criação;
- rollout do agente exige 100% de sucesso no ring;
- gate de rollout do agente não permite override;
- somente admin pode promover rings de atualização do agente;
- confirmação da nova versão possui timeout limitado;
- watchdog rollback impede avanço do ring;
- manifest assinado passa ao schema 2 com `source_commit` e `signing_key_id`;
- servidor e agente validam a identidade da chave pública de assinatura;
- console exibe provenance sanitizada da release;
- releases antigas são removidas somente após ativação confirmada;
- staging confirmado é limpo de forma segura;
- GC preserva current/previous e recusa seguir symlinks inseguros;
- adicionados testes de quarentena, rollout congelado, perfect gate, provenance, retenção e staging cleanup.


## 0.15.0

- backend e agente passam para versão 0.15.0;
- adicionado launcher estável separado da release ativa;
- instalador Linux passa a usar releases versionadas e symlink `current`;
- adicionada capability `signed_update_activation_v1`;
- ativação exige aprovação administrativa, motivo e confirmação de risco;
- ativação automática fica limitada ao Linux nesta versão;
- agente revalida assinatura, tamanho e SHA-256 antes da promoção;
- ativação automática recusa mudança em `requirements.txt`;
- nova release passa por compile check e startup preflight;
- confirmação da nova release exige heartbeat aceito pelo servidor;
- após três tentativas sem confirmação, o launcher restaura a versão anterior;
- servidor audita resultado da ativação informado por heartbeat;
- console, Prometheus e Grafana exibem estado da ativação;
- adicionados testes de troca atômica, confirmação por heartbeat, retorno à versão anterior, dependência alterada e API de aprovação;
- Windows permanece somente com staging assinado.


## 0.14.0

- backend e agente passam para versão 0.14.0;
- adicionada assinatura Ed25519 para releases do agente;
- criado `scripts/agent-release.py` para geração de chave, build, assinatura e verificação;
- chave privada de release não é necessária no servidor Patch Manager;
- servidor valida assinatura, SHA-256 e tamanho antes de anunciar uma release;
- endpoint do agente só serve o artefato exato referenciado pelo manifest assinado;
- agente recebe chave pública pinada durante provisioning;
- agente verifica novamente assinatura, versão, tamanho e SHA-256 antes do staging;
- downgrade e mesma versão são recusados;
- redirects no download de update são recusados;
- pacote possui limite de 50 MiB;
- ZIP aceita somente `patch_agent.py` e `requirements.txt`;
- archive entries inesperadas, duplicadas ou inseguras são recusadas;
- release é extraída apenas em diretório de staging protegido;
- v0.14 não ativa automaticamente o agente staged;
- adicionado `--check-update` para verificação/staging manual;
- Linux e Windows passam a aceitar chave pública de update no instalador;
- console mostra release assinada, updates staged e erros de staging;
- Prometheus/Grafana monitoram estado de staging;
- CI executa build/verify real com chave Ed25519 efêmera;
- testes cobrem tamper de manifest, tamper de artefato, downgrade, archive malicioso e endpoints de distribuição.


## 0.13.0

- backend e agente passam para versão 0.13.0;
- agente passa a reportar versão, protocolo e capabilities no inventário;
- User-Agent do agente passa a usar a constante de versão real;
- servidor classifica agentes como supported, outdated, protocol_unsupported ou unknown;
- adicionados `AGENT_MIN_VERSION`, `AGENT_MIN_PROTOCOL` e `AGENT_ENFORCE_COMPATIBILITY`;
- Compose base opera em modo observação para migração gradual;
- overlay de produção força enforcement de compatibilidade;
- requirements de capabilities são derivados por ação/política do job;
- jobs incompatíveis viram `blocked` antes de qualquer claim;
- jobs blocked por compatibilidade são reavaliados no heartbeat;
- upgrade do agente devolve automaticamente jobs compatíveis para pending;
- health gate reconhece e explica jobs bloqueados por compatibilidade;
- dashboard mostra versão/protocolo/capabilities e agentes incompatíveis;
- adicionados filtros e contadores de frota incompatível e jobs blocked;
- Prometheus/Grafana passam a monitorar compatibilidade da frota;
- adicionados alertas de agentes incompatíveis e jobs blocked quando enforcement está ativo;
- corrigidos seletores do drawer que usavam seletor singular com `forEach`;
- adicionados testes de comparação de versão, capabilities, blocking, observation mode e auto-unblock.


## 0.12.0

- backend passa para versão 0.12.0;
- adicionada migration `0005_remediation_evidence`;
- criada entidade persistente de evidência de remediação;
- evidência vincula finding, campanha, job, endpoint, task Greenbone e reports;
- rescan só é solicitado após validação pós-patch `passed`;
- integração usa `start_task()` na task do finding original;
- report retornado pelo rescan fica persistido na evidência;
- reconciliação exige task correta, report exato e task `Done`;
- prova usa `external_id + CVE`;
- ausência comprovada gera `verified` e pode marcar finding como `remediated`;
- presença confirmada gera `still_detected`;
- `accepted_risk` e `false_positive` não são sobrescritos;
- novo rescan manual exige operator e motivo;
- dashboard exibe estado da evidência e retry quando aplicável;
- Prometheus/Grafana recebem métricas do ciclo de evidência;
- adicionados testes do ciclo de remediação.


## 0.11.0

- backend passa para versão 0.11.0;
- agente passa a reportar telemetria de saúde com `psutil`;
- CPU é amostrada e agregada antes de compor o snapshot;
- adicionados percentuais de memória e espaço livre em disco;
- baseline de saúde é coletado imediatamente antes da instalação;
- resultado do job registra `health_baseline` e snapshot imediato pós-patch;
- política ativa de health gate é persistida no agente por até 24h para sobreviver a reboot;
- heartbeat pós-patch passa a carregar a telemetria de saúde atual;
- adicionados thresholds configuráveis de CPU, memória e disco;
- adicionada validação de serviços críticos Linux/Windows;
- adicionados health checks locais de aplicação;
- health URLs são limitadas a localhost/loopback e rejeitam credenciais embutidas;
- telemetria obrigatória ausente bloqueia o gate em modo fail-closed;
- health gate não executa rollback automático;
- console adiciona configuração avançada do health gate;
- drawer do endpoint exibe CPU, memória, disco e resumo de checks críticos;
- campanhas exibem política e motivo de regressão;
- Prometheus ganha métricas agregadas de telemetria e checks falhando;
- adicionados alertas para checks críticos e erros persistentes de coleta;
- dashboard Grafana passa a exibir telemetria e health checks;
- adicionados testes de regressão, baseline, persistência da política e proteção contra health check remoto.

## 0.10.0

- backend passa para versão 0.10.0;
- adicionados probes separados `/health` e `/ready`;
- Docker healthcheck passa a usar readiness;
- adicionado endpoint interno `/metrics` com `prometheus-client`;
- NGINX de produção bloqueia acesso público a `/metrics`;
- adicionadas métricas agregadas de endpoints online/offline e vínculo mTLS;
- adicionadas métricas de updates pendentes/críticos e reboot requerido;
- adicionadas métricas de jobs e campanhas por status;
- adicionadas métricas de vulnerabilidades por status/severidade;
- adicionadas métricas de estado e último sync Greenbone;
- adicionadas métricas HTTP por rota normalizada, status e latência;
- hostname, IP, CVE e fingerprint não são usados como labels;
- backup passa a publicar estado de sucesso atomicamente em `runtime/backup-status.json`;
- adicionadas métricas de backup status, timestamp, age e tamanho;
- adicionadas regras de alerta Prometheus;
- adicionado dashboard Grafana importável;
- adicionados testes de readiness, privacidade das métricas e backup freshness;
- CI passa a validar rules/config Prometheus e JSON do dashboard Grafana.

## 0.9.0

- backend passa para versão 0.9.0;
- API do host vinculada somente a `127.0.0.1:8080` no Compose base;
- adicionado `docker-compose.prod.yml` com NGINX em 80/443;
- HTTP redirecionado para HTTPS;
- TLS limitado a TLS 1.2/1.3 no proxy de produção;
- certificado cliente obrigatório nas rotas dos agentes;
- fingerprint do certificado mTLS vinculado ao `agent_id`;
- token individual do agente continua obrigatório além do mTLS;
- migration `0004_agent_mtls`;
- rotação/vínculo de fingerprint auditado por administrador;
- estado mTLS exibido no drawer do endpoint;
- agente recusa URL HTTP e `tls_verify=false`;
- agentes Linux e Windows aceitam material mTLS e CA customizada;
- chave privada do agente protegida por permissões/ACL;
- adicionados scripts de backup e restore PostgreSQL;
- dumps em formato custom, validados e acompanhados de SHA-256;
- restore exige confirmação explícita e mantém a aplicação parada em caso de falha;
- adicionado restore drill real no CI;
- CI valida o overlay de produção e executa `nginx -t` com certificados efêmeros;
- adicionados testes de vínculo, rejeição e rotação mTLS.

## 0.8.0

- removida a dependência do token administrativo compartilhado para operação normal;
- adicionados usuários humanos persistidos no PostgreSQL;
- senhas protegidas com Argon2;
- adicionadas sessões opacas server-side com expiração configurável;
- token bruto de sessão nunca é persistido no banco;
- dashboard mantém a sessão somente em memória do navegador;
- adicionado login/logout e troca de senha no console;
- adicionado RBAC nativo com `viewer`, `operator` e `admin`;
- leituras administrativas exigem `viewer`;
- campanhas, tags, vulnerabilidades e sync Greenbone exigem `operator`;
- rollback, retry de `stalled` e gestão de usuários exigem `admin`;
- adicionada tela administrativa de usuários;
- ações humanas passam a registrar `user:<username>` na auditoria;
- adicionado bootstrap seguro do primeiro administrador;
- adicionado break-glass opcional, desabilitado quando não configurado;
- impedido auto-rebaixamento do administrador atual;
- impedida remoção ou desativação do último administrador ativo;
- adicionada migration `0003_rbac_sessions`;
- adicionados testes de login, sessão, logout e matriz RBAC.

## 0.7.0

- PostgreSQL passa a ser o banco padrão no Docker Compose;
- adicionado Alembic com migrations versionadas;
- container executa `alembic upgrade head` antes da API;
- adicionados tokens efêmeros de claim por tentativa de job;
- adicionados leases de `claimed` e `running`;
- `claimed` expirado pode voltar à fila se a execução nunca iniciou;
- `running` expirado vira `stalled` e não é reentregue automaticamente;
- retry de `stalled` exige confirmação administrativa e invalida o claim anterior;
- resultados terminais repetidos e idênticos são idempotentes;
- resultados conflitantes ou claims obsoletos são recusados;
- agente renova o lease durante operações demoradas;
- dashboard mostra jobs `stalled`, tentativa atual e ação de revisão/retry;
- adicionados testes automatizados para claim, idempotência, lease, stalled e retry;
- CI passa a validar migrations em PostgreSQL real;
- configuração dos leases exposta em `.env.example`.

> Dados de SQLite de versões anteriores não são migrados automaticamente para PostgreSQL.

## 0.6.0

- adicionada integração opcional Greenbone/OpenVAS via GMP;
- adicionada dependência oficial `python-gvm`;
- suporte a transporte TLS e Unix socket;
- sync automático periódico e sync manual pela dashboard;
- leitura do último relatório das tasks do Greenbone;
- normalização de resultados GMP para findings do Patch Manager;
- status da integração sem exposição de credenciais;
- estado da integração persistido em tabela própria;
- reconciliação opcional de findings ausentes como `not_detected`, nunca automaticamente `remediated`;
- configuração Greenbone documentada em `.env.example`.
## 0.5.0

- adicionada tabela normalizada de vulnerabilidades;
- adicionada ingestão administrativa de findings de scanners;
- correlação de findings por hostname/IP com endpoints gerenciados;
- nova tela de Vulnerabilidades com CVE, CVSS, severidade, origem e status;
- campanha pode ser pré-preenchida a partir de finding correlacionado;
- campanhas podem ser direcionadas a um único `target_agent_id` sem tag temporária;
- finding não é marcado como remediado automaticamente após patching;
- base preparada para sync OpenVAS/Greenbone via GMP e rescan posterior.

## 0.1.1

Security and public-repository hardening release.

- removed internal project naming from public documentation;
- server now fails closed when required secrets are missing, weak, placeholder-like, or identical;
- dashboard no longer persists the administrator token in `localStorage`;
- agents delete the shared enrollment token after successful enrollment;
- Windows installer restricts `agent.json` ACLs to LocalSystem and Administrators;
- Linux and Windows installers prompt for the enrollment token by default instead of requiring it in command history;
- expanded `.gitignore` for secrets, certificates, runtime data, logs and local environments;
- added `SECURITY.md`;
- changed project license to Apache-2.0;
- bumped API and agent version to 0.1.1.
- added a conservative pre-publication secret/runtime-file check and GitHub Actions validation workflow.
