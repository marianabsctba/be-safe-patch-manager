# Changelog

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
