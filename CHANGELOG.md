# Changelog

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
