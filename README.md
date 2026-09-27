# Be Safe Patch Manager

Patch management **agent-based** para Windows e Linux, com inventário, campanhas, rollout progressivo, health gates, janelas de manutenção, evidências de execução e proteção de rollback.

> **Status:** MVP / laboratório — v0.12. A base já executa patching real, mas ainda exige hardening e validação em laboratório antes de uso em produção.

![Be Safe Patch Manager — Visão geral](docs/images/dashboard-overview.webp)

## O que já funciona

- inventário e heartbeat de endpoints;
- scan de updates pendentes;
- dashboard de compliance, risco, endpoints, vulnerabilidades, campanhas, execuções e auditoria;
- ingestão normalizada de findings de scanners, começando por OpenVAS/Greenbone;
- correlação de finding por hostname/IP com endpoint gerenciado;
- CVE, severidade, CVSS, solução e referências de patch por finding;
- criação de campanha a partir de finding correlacionado;
- evidência de remediação vinculando finding, campanha, job e endpoint;
- rescan Greenbone automático após patch validado;
- reconciliação pelo report exato retornado pelo `start_task()`;
- prova por combinação `external_id + CVE`;
- estado `verified` somente após report pós-patch concluído sem a CVE;
- estado `still_detected` quando o rescan confirma persistência da vulnerabilidade;
- novo rescan manual auditado para erro ou finding ainda detectado;
- Windows Update Agent via COM no Windows;
- `apt`, `dnf` e `yum` no Linux;
- campanhas por SO, tag, pacote/KB e percentual;
- rollout progressivo determinístico em **10% → 30% → 100%**;
- health gate antes de promover o próximo ring;
- janela de manutenção opcional por horário, dias e timezone;
- política de reboot;
- validação pós-patch com heartbeat novo;
- baseline de saúde imediatamente antes do patch;
- comparação pós-patch de CPU, memória e espaço livre em disco;
- validação opcional de serviços críticos;
- health checks locais de aplicação por HTTP(S) loopback;
- thresholds de regressão configuráveis por campanha;
- política de health gate persistida no agente para sobreviver a reboot;
- modo fail-closed quando telemetria de saúde é obrigatória;
- checkpoint de rollback antes do patch, quando suportado;
- aprovação manual de rollback;
- evidências e trilha de auditoria;
- PostgreSQL como banco padrão no Docker Compose;
- schema versionado com Alembic;
- lease por tentativa de execução e token efêmero de claim;
- resultados terminais idempotentes;
- jobs em execução com lease expirado viram `stalled` e nunca são reentregues automaticamente;
- retry de job `stalled` exige revisão e confirmação administrativa;
- autenticação humana por usuário e senha com hash Argon2;
- RBAC nativo com perfis `viewer`, `operator` e `admin`;
- sessões opacas server-side com token armazenado apenas em hash no banco;
- sessão do console mantida somente em memória no navegador;
- bootstrap do primeiro administrador e break-glass opcional;
- autenticação separada para usuários, enrollment e agentes;
- token individual por endpoint;
- HTTPS de produção com NGINX e TLS 1.2/1.3;
- mTLS obrigatório nas rotas de agentes no overlay de produção;
- certificado cliente vinculado ao `agent_id` por fingerprint;
- rotação auditada de certificado mTLS por admin;
- API do backend exposta no host somente em `127.0.0.1:8080`;
- backup PostgreSQL em formato custom com SHA-256;
- restore protegido por confirmação explícita;
- restore drill real no CI;
- liveness em `/health` e readiness em `/ready`;
- métricas Prometheus agregadas em `/metrics`;
- métricas HTTP por rota normalizada, status e latência;
- métricas de endpoints online/offline, mTLS, jobs, campanhas, vulnerabilidades e Greenbone;
- freshness do último backup exposta sem filename/checksum;
- regras de alerta Prometheus versionadas;
- dashboard Grafana importável;
- CI validando rules Prometheus e JSON do Grafana;
- nenhuma ação de shell remoto arbitrário.

## Dashboard

### Visão geral

![Dashboard — Visão geral](docs/images/dashboard-overview.webp)

> A captura acima usa a interface real da `main`; somente os dados foram simulados para mostrar a dashboard populada.

### Execuções, validação e rollback

![Dashboard — Execuções e rollback](docs/images/dashboard-executions.webp)

A tela de execuções consolida status do job, validação pós-patch e estado de rollback. Quando um checkpoint Windows elegível existe, a aprovação de rollback é explícita, exige motivo e gera um novo job auditável.

## Arquitetura

![Be Safe Patch Manager — Arquitetura geral](docs/images/architecture-overview.webp)

A implementação atual é centralizada em FastAPI. O Docker Compose usa PostgreSQL por padrão e o schema é versionado com Alembic. SQLite continua disponível para desenvolvimento e testes. Os agentes Windows e Linux fazem polling de jobs, enviam heartbeat, inventário, patch scan e evidências de execução.

A v0.6 possui ingestão normalizada, correlação com endpoints e sync opcional automático ou manual via GMP. A plataforma continua sem declarar remediação automaticamente: o status remediado deve representar evidência explícita do scanner/processo.

A v0.8 adiciona autenticação humana e RBAC no próprio Patch Manager. Leituras administrativas exigem pelo menos `viewer`; operação de campanhas, tags, vulnerabilidades e sync exige `operator`; gestão de usuários, retry de jobs `stalled` e rollback exigem `admin`.

A v0.11 adiciona baseline de saúde coletado pelo agente imediatamente antes da instalação e comparação pós-patch antes da promoção do ring. A política pode considerar CPU, memória, espaço livre em disco, serviços críticos e health endpoints locais da aplicação.

A v0.12 fecha o ciclo de remediação para findings Greenbone vinculados a campanhas de patch. Depois que o job termina e a validação pós-patch passa, o worker solicita um novo scan da task original via GMP, acompanha o report retornado por esse `start_task()` e registra evidência de presença ou ausência da mesma combinação `external_id + CVE`.

## Fluxo seguro de implantação

![Be Safe Patch Manager — Fluxo seguro de implantação](docs/images/secure-rollout-flow.webp)

O fluxo atual é:

1. criar a campanha com alvo, ring, pacotes/KBs, janela e política de reboot;
2. preparar checkpoint de rollback quando habilitado e suportado;
3. distribuir o primeiro ring;
4. aguardar o health gate;
5. promover para 30%;
6. promover para 100%;
7. usar rollback somente com aprovação manual quando necessário.

O health gate exige, no ring atual:

- nenhum job ativo;
- jobs em estado terminal;
- taxa de sucesso de pelo menos 90%;
- validação pós-patch sem falha ou espera;
- heartbeat novo após a instalação;
- ausência de reboot ainda pendente;
- ausência de regressão no número de updates pendentes/críticos em relação ao baseline;
- quando habilitado, health gate de sistema/aplicação sem regressão ou check crítico falhando.

### Critério de regressão de saúde

Quando o health gate avançado está habilitado, o agente coleta um baseline **imediatamente antes** da instalação. A política ativa é mantida localmente por até 24 horas para que o endpoint continue reportando os mesmos checks depois de um reboot.

No heartbeat pós-patch o servidor compara:

- **CPU:** valor absoluto máximo e aumento máximo em pontos percentuais;
- **memória:** valor absoluto máximo e aumento máximo em pontos percentuais;
- **disco:** espaço livre mínimo e queda máxima de espaço livre;
- **serviços críticos:** cada serviço configurado precisa estar saudável;
- **aplicação:** cada health check configurado precisa responder conforme a política.

Os padrões apresentados pela console são:

- CPU máxima: 95%;
- aumento máximo de CPU: 40 p.p.;
- memória máxima: 95%;
- aumento máximo de memória: 20 p.p.;
- disco livre mínimo: 5%;
- queda máxima de disco livre: 10 p.p.

Esses valores são ponto de partida, não uma definição universal de saúde. A campanha pode alterá-los conforme o workload.

A console habilita o health gate avançado por padrão em novas campanhas. Na API, `health_gate_enabled` permanece `false` por padrão para compatibilidade com clientes antigos.

Se `health_gate_require_telemetry=true`, ausência de CPU, memória, disco ou baseline válido bloqueia o gate. Isso evita interpretar falta de evidência como ambiente saudável.

Health checks de aplicação executados pelo agente aceitam somente HTTP(S) para `localhost` ou endereços loopback. URLs remotas e credenciais embutidas são rejeitadas. O objetivo é observar a aplicação local sem criar uma capacidade genérica de acesso HTTP interno.

Uma regressão de saúde **não executa rollback automaticamente**. Ela bloqueia a promoção do próximo ring e apresenta o motivo. Rollback continua exigindo aprovação administrativa explícita.

## Vulnerabilidades e OpenVAS

A API administrativa aceita findings normalizados de scanners em:

`POST /api/admin/vulnerabilities/import`

Exemplo de payload:

```json
{
  "source": "openvas",
  "scan_id": "scan-2026-09-27",
  "findings": [
    {
      "external_id": "result-123",
      "host": "pc-001",
      "ip_address": "10.10.10.20",
      "cves": ["CVE-2026-12345"],
      "title": "Exemplo de vulnerabilidade",
      "severity": "critical",
      "cvss": 9.8,
      "port": "443/tcp",
      "solution": "Aplicar atualização do fabricante",
      "patch_refs": ["KB1234567"],
      "resolved": false
    }
  ]
}
```

O servidor tenta correlacionar o finding com um agente por IP ou hostname. Findings não correlacionados continuam visíveis para tratamento.

A interface permite preparar uma campanha diretamente a partir de um finding correlacionado. A campanha fica vinculada ao `agent_id` no payload, sem criar tags temporárias.

**Importante:** instalar um patch continua não sendo prova de remediação. Quando a campanha é criada a partir de um finding Greenbone e executa `install_updates`, a v0.12 cria uma evidência vinculada ao job. O finding só é marcado automaticamente como `remediated` quando o rescan pós-patch termina e a mesma combinação `external_id + CVE` não aparece no report exato retornado pelo Greenbone.

### Sync automático via GMP

A v0.6 adiciona integração opcional com o `gvmd` usando a biblioteca oficial `python-gvm`.

No `.env` real:

```dotenv
GREENBONE_ENABLED=true
GREENBONE_TRANSPORT=tls
GREENBONE_HOST=greenbone.interno.local
GREENBONE_PORT=9390
GREENBONE_USERNAME=
GREENBONE_PASSWORD=
GREENBONE_SYNC_INTERVAL=900
GREENBONE_RECONCILE_ABSENT=false
```

Também é suportado `GREENBONE_TRANSPORT=unix` com `GREENBONE_SOCKET=/run/gvmd/gvmd.sock`. Nesse caso, o socket precisa estar disponível dentro do container.

As credenciais são lidas somente de variáveis de ambiente. O endpoint de status e a dashboard não devolvem usuário, senha ou chave privada.

Quando o sync automático está habilitado, o serviço autentica no `gvmd`, consulta o último relatório das tasks, busca resultados via GMP, normaliza os findings, correlaciona endpoints e registra evidências em auditoria.

Sync manual:

`POST /api/admin/integrations/greenbone/sync`

Estado da integração:

`GET /api/admin/integrations/greenbone`

Por segurança, `GREENBONE_RECONCILE_ABSENT=false` é o padrão. Quando habilitado, um finding que desaparece do último relatório da mesma task vira `not_detected`, nunca `remediated` automaticamente.

### Ciclo de remediação com evidência

Para uma campanha criada a partir de finding OpenVAS/Greenbone:

1. o finding guarda a task Greenbone e o report em que foi detectado;
2. o job de `install_updates` cria uma evidência em `waiting_validation`;
3. patch, heartbeat e health gate precisam terminar com validação `passed`;
4. o worker chama `start_task(task_id)`;
5. o `report_id` retornado pelo Greenbone fica persistido;
6. a reconciliação só acontece quando essa task está `Done` e esse mesmo report está disponível;
7. a prova compara `external_id + CVE`.

Estados principais: `waiting_validation`, `rescan_requested`, `verified`, `still_detected`, `error` e `unsupported`.

`verified` pode atualizar findings `open` ou `not_detected` para `remediated`. Estados humanos como `accepted_risk` e `false_positive` não são sobrescritos automaticamente.

Novo rescan manual só é permitido para `error` ou `still_detected`, exige perfil `operator` e motivo, e fica auditado.

A automação reutiliza a task registrada no finding original. Ela não cria targets, scanners ou tasks arbitrárias no Greenbone.

## Rollback

Rollback não é tratado como uma operação genérica ou automática.

### Windows

Quando o endpoint suporta System Restore, o agente pode criar um restore point antes da instalação. A evidência do checkpoint fica associada ao job.

A restauração só é colocada na fila após:

- aprovação explícita do administrador;
- motivo obrigatório;
- confirmação de risco.

O job de rollback usa somente o restore point registrado e agenda o reboot necessário para concluir a restauração.

### Linux

O agente detecta Snapper configurado e pode criar snapshot quando disponível. Na v0.12, a recuperação Linux permanece **manual**; o Patch Manager registra a evidência do snapshot, mas não executa rollback automático de filesystem.

A campanha pode usar dois modos:

- **best effort:** tenta criar checkpoint e continua se ele não estiver disponível;
- **checkpoint obrigatório:** a instalação é bloqueada se a proteção de rollback não puder ser criada.

## Quick start

### Servidor

Pré-requisitos: Docker e Docker Compose.

```bash
cp .env.example .env
```

Gere os segredos antes de subir o ambiente:

```bash
python3 - <<'PY'
import secrets
print("BOOTSTRAP_ADMIN_PASSWORD=" + secrets.token_urlsafe(32))
print("ENROLLMENT_TOKEN=" + secrets.token_urlsafe(48))
print("POSTGRES_PASSWORD=" + secrets.token_urlsafe(48))
PY
```

Defina também `BOOTSTRAP_ADMIN_USERNAME` no `.env`. No primeiro startup, se ainda não existir nenhum usuário, o servidor cria esse administrador e grava somente o hash Argon2 da senha.

Depois do primeiro login confirmado, os valores `BOOTSTRAP_ADMIN_USERNAME` e `BOOTSTRAP_ADMIN_PASSWORD` podem ser removidos do `.env`; eles não são necessários quando já existe usuário no banco.

`BREAK_GLASS_ADMIN_TOKEN` é opcional e deve permanecer vazio em operação normal. Se for usado para contingência, precisa ser um valor aleatório forte e separado do `ENROLLMENT_TOKEN`.

O Compose sobe PostgreSQL, aguarda o healthcheck do banco e executa `alembic upgrade head` antes de iniciar a API.

> A v0.12 não migra automaticamente dados de um banco SQLite criado por versões anteriores. Para uma implantação nova, comece diretamente no PostgreSQL.

Para laboratório local:

```bash
docker compose up -d --build
docker compose ps
```

A porta 8080 fica vinculada somente ao loopback do host:

```text
http://127.0.0.1:8080
```

Para implantação com HTTPS e mTLS:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Nesse modo, o acesso externo deve ocorrer por HTTPS na porta 443.

### Agente Linux

```bash
sudo ./deploy/install-linux.sh https://patch.seudominio.local piloto
```

O instalador solicita o `ENROLLMENT_TOKEN` sem ecoar o valor. Após o primeiro enrollment, o token compartilhado é removido da configuração local e fica somente a credencial individual do agente.

### Agente Windows

Execute PowerShell como Administrador:

```powershell
Set-ExecutionPolicy -Scope Process Bypass

.\deploy\windows\install-agent.ps1 `
  -ServerUrl "https://patch.seudominio.local" `
  -Tags @("piloto")
```

O instalador solicita o enrollment token como `SecureString`, aplica ACL restritiva ao `agent.json` e cria a tarefa agendada do agente.

## Como os agentes operam

Cada agente:

1. faz enrollment inicial;
2. remove o enrollment token compartilhado;
3. executa scan periódico;
4. envia heartbeat com inventário, patches, telemetria de saúde e capacidade de rollback;
5. faz polling de jobs;
6. executa somente ações permitidas;
7. envia resultado e evidências;
8. faz novo scan/heartbeat após patching.

As ações aceitas são restritas a:

- `scan_updates`;
- `install_updates`;
- `rollback_checkpoint` — criado pelo servidor somente após aprovação administrativa válida.

Não existe endpoint de shell remoto arbitrário.

## Semântica segura de execução

Cada entrega de job recebe um token efêmero de claim e um lease.

- um job `claimed` que nunca começou pode voltar à fila quando o lease expira;
- quando o agente informa `running`, passa a renovar o lease enquanto a operação está em andamento;
- um job `running` com lease expirado vira `stalled`;
- `stalled` nunca é reexecutado automaticamente;
- o operador precisa revisar e aprovar explicitamente um retry;
- o retry invalida o token da tentativa anterior;
- um resultado terminal repetido e idêntico é aceito de forma idempotente;
- um resultado terminal conflitante é recusado.

Os tempos padrão são configuráveis por `JOB_CLAIM_LEASE_SECONDS` e `JOB_RUNNING_LEASE_SECONDS`.

## Autenticação e RBAC

O console usa login por usuário e senha. As senhas são armazenadas com Argon2 e cada login gera uma sessão opaca com expiração configurável por `AUTH_SESSION_TTL_SECONDS`.

A sessão é mantida somente em memória no navegador. Um refresh da página exige novo login por design.

Perfis:

- `viewer`: leitura de dashboard, endpoints, vulnerabilidades, campanhas, execuções e auditoria;
- `operator`: inclui criação/implantação/avanço de campanhas, tags, tratamento de vulnerabilidades e sync Greenbone;
- `admin`: inclui gestão de usuários, retry de job `stalled` e aprovação de rollback.

A auditoria registra ações humanas com `user:<username>`.

## HTTPS e mTLS

O `docker-compose.yml` base mantém o backend acessível no host somente em `127.0.0.1:8080`. Para implantação, use o overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

O overlay adiciona NGINX nas portas 80/443. HTTP é redirecionado para HTTPS. O console usa TLS normal; as rotas `/api/agent/` exigem certificado cliente válido assinado pela CA configurada.

Antes de subir o overlay, coloque fora do Git:

```text
deploy/nginx/tls/server.crt
deploy/nginx/tls/server.key
deploy/nginx/tls/agent-ca.crt
```

`server.crt` pode ser uma cadeia de certificado público ou privado. `agent-ca.crt` é a CA usada para validar os certificados individuais dos agentes.

Cada agente deve receber um certificado cliente próprio. No enrollment, o NGINX valida a cadeia e encaminha o fingerprint do certificado para o backend. O Patch Manager vincula esse fingerprint ao `agent_id`. Depois disso, chamadas do agente exigem simultaneamente certificado válido, fingerprint correto e token individual do endpoint.

O fingerprint informado pelo NGINX é usado como identificador de vínculo. A autenticação criptográfica continua sendo a validação mTLS da cadeia do certificado.

Para Linux:

```bash
sudo env \
  PATCH_CLIENT_CERT=/caminho/agent.crt \
  PATCH_CLIENT_KEY=/caminho/agent.key \
  PATCH_CA_CERT=/caminho/server-ca.crt \
  ./deploy/install-linux.sh https://patch.seudominio.local piloto
```

`PATCH_CA_CERT` é opcional quando o certificado do servidor já é confiado pelo sistema operacional.

No Windows:

```powershell
.\deploy\windows\install-agent.ps1 `
  -ServerUrl "https://patch.seudominio.local" `
  -ClientCertificatePath "C:\Temp\agent.crt" `
  -ClientKeyPath "C:\Temp\agent.key" `
  -CaCertificatePath "C:\Temp\server-ca.crt" `
  -Tags @("piloto")
```

A chave privada é copiada para a área do agente com ACL restrita. O agente também recusa `http://` e `tls_verify=false`.

Admins podem vincular ou rotacionar explicitamente um fingerprint pela tela do endpoint ou por `PUT /api/admin/agents/{agent_id}/mtls`. Isso permite migrar endpoints existentes sem recriar o inventário.

## Backup e restore

Crie um dump PostgreSQL:

```bash
./scripts/backup-postgres.sh
```

O script usa `pg_dump --format=custom`, valida o dump com `pg_restore --list` e gera um arquivo `.sha256`.

Para restaurar:

```bash
CONFIRM_RESTORE=YES ./scripts/restore-postgres.sh backups/patchmgr-YYYYMMDDTHHMMSSZ.dump
```

O restore verifica o checksum quando disponível, valida o dump, para o Patch Manager, executa o restore em transação única e só volta a iniciar a aplicação se o processo terminar com sucesso. Em caso de falha, a aplicação permanece parada para revisão.

Os dumps contêm dados operacionais e devem ser tratados como informação sensível. O script não criptografa o arquivo. Para produção, envie os backups para armazenamento off-host criptografado e com retenção definida.

O CI executa um restore drill real em PostgreSQL: cria dado marcador, gera dump, restaura em outro database e confirma o conteúdo restaurado.

Após um backup concluído, o script também atualiza atomicamente `runtime/backup-status.json`. O exporter lê somente timestamp e tamanho para calcular freshness. Nome de arquivo e checksum não são publicados como métricas.

## Observabilidade

A v0.10 separa os probes:

```text
GET /health   liveness da aplicação
GET /ready    PostgreSQL acessível + pelo menos um admin ativo
GET /metrics  métricas Prometheus internas
```

O healthcheck do Docker usa `/ready`. O NGINX de produção responde `404` para `/metrics`; o scrape deve ocorrer diretamente no backend local ou por uma rede privada de observabilidade.

Exemplo para Prometheus executando no próprio host:

```yaml
scrape_configs:
  - job_name: be-safe-patch-manager
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

O exemplo completo está em:

```text
deploy/prometheus/scrape.example.yml
```

Regras de alerta:

```text
deploy/prometheus/patch-manager.rules.yml
```

Incluem banco indisponível, aplicação sem scrape, jobs `stalled`, backup ausente/antigo, Greenbone sem sync saudável, proporção elevada de endpoints offline, erros HTTP 5xx persistentes, checks críticos falhando e erros persistentes de coleta de saúde.

Dashboard Grafana:

```text
deploy/grafana/patch-manager-overview.json
```

O dashboard mostra estado do banco, endpoints online/offline, jobs stalled, updates críticas, reboots pendentes, backup age, Greenbone, taxa HTTP, p95 de latência, endpoints com telemetria e health checks críticos falhando.

As métricas são deliberadamente agregadas. Hostname, IP, usuário, CVE, título de vulnerabilidade, token e fingerprint de certificado não são usados como labels.

Se o Prometheus estiver em container separado, `127.0.0.1` aponta para o próprio container. Nesse caso, conecte-o por rede Docker privada ou configure acesso ao host sem publicar a porta 8080 externamente.

`AGENT_ONLINE_SECONDS` define a janela usada para considerar um endpoint online. O padrão é 300 segundos.

## Segurança já implementada

- autenticação humana por usuário/senha com Argon2;
- RBAC `viewer` / `operator` / `admin`;
- sessão opaca com token armazenado somente em SHA-256 no banco;
- sessão do console somente em memória no navegador, sem `localStorage` ou `sessionStorage`;
- bootstrap seguro do primeiro administrador;
- break-glass opcional e desabilitado quando não configurado;
- proteção contra auto-rebaixamento e remoção do último admin ativo;
- `ENROLLMENT_TOKEN` forte e separado da autenticação humana;
- credencial individual por agente;
- enrollment token descartado após registro;
- ações do agente em allowlist;
- validação de nomes de pacotes e KBs;
- arquivo de configuração Linux com modo `0600`;
- ACL restritiva no Windows;
- rollout em rings e health gate;
- janela de manutenção;
- validação pós-patch com baseline de CPU/memória/disco, serviços e aplicação;
- aprovação manual de rollback;
- auditoria de operações;
- leases de execução e proteção contra resultado de tentativa obsoleta;
- retry manual para jobs `stalled`;
- PostgreSQL no Compose;
- migrations Alembic;
- testes automatizados de semântica de jobs;
- CI executando migrations contra PostgreSQL real;
- `.gitignore` para secrets, chaves, certificados, bancos e logs;
- SECURITY.md;
- pre-publish security check;
- CI com migrations PostgreSQL, restore drill, testes Python, validação de Python/Shell/JavaScript, NGINX, Prometheus e Grafana.

Para produção, ainda são recomendados:

- SSO/federação de identidade opcional;
- política de rotação de senhas e credenciais de agentes;
- HA e replicação/estratégia de continuidade;
- rate limiting;
- code signing do agente;
- assinatura de políticas/campanhas;
- hardening do host e do reverse proxy;
- testes de integração Windows/Linux.

Leia também [SECURITY.md](SECURITY.md).

## Estrutura

```text
be-safe-patch-manager/
├── docker-compose.yml
├── docker-compose.prod.yml
├── .env.example
├── LICENSE
├── README.md
├── SECURITY.md
├── CHANGELOG.md
├── docs/
│   └── images/
│       ├── dashboard-overview.webp
│       ├── dashboard-executions.webp
│       ├── architecture-overview.webp
│       └── secure-rollout-flow.webp
├── .github/workflows/ci.yml
├── scripts/pre-publish-check.py
├── scripts/backup-postgres.sh
├── scripts/restore-postgres.sh
├── server/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── tests/
│   └── app/
│       ├── main.py
│       ├── observability.py
│       ├── greenbone.py
│       ├── database.py
│       ├── models.py
│       ├── schemas.py
│       ├── security.py
│       └── static/
│           ├── index.html
│           ├── style.css
│           └── app.js
├── agent/
│   ├── patch_agent.py
│   ├── requirements.txt
│   └── config.example.json
└── deploy/
    ├── install-linux.sh
    ├── systemd/patch-manager-agent.service
    ├── windows/install-agent.ps1
    ├── nginx/default.conf
    ├── prometheus/
    │   ├── scrape.example.yml
    │   └── patch-manager.rules.yml
    └── grafana/patch-manager-overview.json
```

## Roadmap

Próximas evoluções planejadas:

- ingestão de CVEs do Wazuh;
- patching de aplicações de terceiros;
- integração ITSM/SOAR;
- SLA, exceções e relatórios consolidados;
- testes de integração reais em endpoints Windows/Linux;
- assinatura e distribuição endurecida do agente;
- HA, retenção off-host e testes periódicos de recuperação completa.

## Licença

Apache License 2.0. Veja [LICENSE](LICENSE).
