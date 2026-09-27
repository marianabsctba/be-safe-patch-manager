# Changelog

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
