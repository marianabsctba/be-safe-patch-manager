# Be Safe Patch Manager

Patch management **agent-based** para Windows e Linux, com inventário, campanhas, rollout progressivo, health gates, janelas de manutenção, evidências de execução e proteção de rollback.

> **Status:** MVP / laboratório — v0.7. A base já executa patching real, mas ainda exige hardening e validação em laboratório antes de uso em produção.

![Be Safe Patch Manager — Visão geral](docs/images/dashboard-overview.webp)

## O que já funciona

- inventário e heartbeat de endpoints;
- scan de updates pendentes;
- dashboard de compliance, risco, endpoints, vulnerabilidades, campanhas, execuções e auditoria;
- ingestão normalizada de findings de scanners, começando por OpenVAS/Greenbone;
- correlação de finding por hostname/IP com endpoint gerenciado;
- CVE, severidade, CVSS, solução e referências de patch por finding;
- criação de campanha a partir de finding correlacionado;
- Windows Update Agent via COM no Windows;
- `apt`, `dnf` e `yum` no Linux;
- campanhas por SO, tag, pacote/KB e percentual;
- rollout progressivo determinístico em **10% → 30% → 100%**;
- health gate antes de promover o próximo ring;
- janela de manutenção opcional por horário, dias e timezone;
- política de reboot;
- validação pós-patch com heartbeat novo;
- checkpoint de rollback antes do patch, quando suportado;
- aprovação manual de rollback;
- evidências e trilha de auditoria;
- PostgreSQL como banco padrão no Docker Compose;
- schema versionado com Alembic;
- lease por tentativa de execução e token efêmero de claim;
- resultados terminais idempotentes;
- jobs em execução com lease expirado viram `stalled` e nunca são reentregues automaticamente;
- retry de job `stalled` exige revisão e confirmação administrativa;
- autenticação separada para administrador, enrollment e agentes;
- token individual por endpoint;
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
- ausência de regressão no número de updates pendentes/críticos em relação ao baseline.

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

**Importante:** instalar um patch não altera automaticamente o finding para remediado. A confirmação deve vir de rescan ou de atualização explícita do status.

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

O agente detecta Snapper configurado e pode criar snapshot quando disponível. Na v0.7, a recuperação Linux permanece **manual**; o Patch Manager registra a evidência do snapshot, mas não executa rollback automático de filesystem.

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
print("ADMIN_TOKEN=" + secrets.token_urlsafe(48))
print("ENROLLMENT_TOKEN=" + secrets.token_urlsafe(48))
print("POSTGRES_PASSWORD=" + secrets.token_urlsafe(48))
PY
```

Copie os valores para `.env`. O Compose sobe PostgreSQL, aguarda o healthcheck do banco e executa `alembic upgrade head` antes de iniciar a API.

> A v0.7 não migra automaticamente dados de um banco SQLite criado por versões anteriores. Para uma implantação nova, comece diretamente no PostgreSQL.

Suba o serviço:

```bash
docker compose up -d --build
docker compose ps
```

Dashboard local:

```text
http://IP-DO-SERVIDOR:8080
```

Em produção, use reverse proxy com HTTPS e não exponha a API administrativa diretamente à Internet.

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
4. envia heartbeat com inventário, patches e capacidade de rollback;
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

## Segurança já implementada

- `ADMIN_TOKEN` e `ENROLLMENT_TOKEN` obrigatórios, fortes e distintos;
- credencial individual por agente;
- enrollment token descartado após registro;
- token administrativo somente em memória no navegador;
- ações do agente em allowlist;
- validação de nomes de pacotes e KBs;
- arquivo de configuração Linux com modo `0600`;
- ACL restritiva no Windows;
- rollout em rings e health gate;
- janela de manutenção;
- validação pós-patch;
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
- CI com migrations PostgreSQL, testes Python, validação de Python, Shell e JavaScript.

Para produção, ainda são recomendados:

- TLS obrigatório;
- SSO/RBAC;
- rotação e revogação de credenciais;
- mTLS para agentes;
- backup e HA;
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
    └── windows/install-agent.ps1
```

## Roadmap

Próximas evoluções planejadas:

- disparo controlado de rescan após patching;
- reconciliação completa CVE → endpoint → patch → rescan → evidência;
- ingestão de CVEs do Wazuh;
- patching de aplicações de terceiros;
- integração ITSM/SOAR;
- SLA, exceções e relatórios consolidados;
- testes de integração reais em endpoints Windows/Linux;
- assinatura e distribuição endurecida do agente;
- HA e estratégia de backup/restore testada.

## Licença

Apache License 2.0. Veja [LICENSE](LICENSE).
