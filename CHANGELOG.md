# Changelog

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
