# Security Policy

## Supported version

Security fixes are currently applied to the latest release of the project.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected vulnerability that could put users or deployments at risk.

Use GitHub's **Private vulnerability reporting** feature for this repository when it is enabled. Include:

- affected version or commit;
- reproduction steps;
- expected and observed behavior;
- security impact;
- relevant logs or screenshots with secrets removed.

If private vulnerability reporting is not enabled, contact the repository owner through a private channel before publishing technical details.

## Secrets

Never commit production tokens, `.env` files, endpoint `agent.json` files, private keys, certificates containing private keys, database files, or logs containing credentials.

The server intentionally refuses to start when `ADMIN_TOKEN` or `ENROLLMENT_TOKEN` is absent, too short, still resembles a placeholder, or both tokens are identical.

The endpoint agent removes the shared enrollment token from its configuration after successful enrollment and retains only its unique agent credential.

## Deployment guidance

This repository is an MVP and should not be exposed directly to the public Internet without additional controls. For production deployments, use HTTPS, network segmentation, administrative access controls, token rotation, rate limiting, database backups, and an external identity/RBAC layer.

The agent deliberately does not expose arbitrary remote shell execution. Keep that property when contributing new job types.
