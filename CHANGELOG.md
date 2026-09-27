# Changelog

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
