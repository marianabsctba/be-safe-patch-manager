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

The server refuses to start when `ENROLLMENT_TOKEN` is absent, weak, or placeholder-like.

On an empty database, the server also refuses to start unless a valid bootstrap administrator is provided through `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD`. Once an administrator exists, bootstrap credentials are no longer required and should be removed from the deployment environment.

Human passwords are hashed with Argon2. Console sessions are opaque server-side sessions; only a SHA-256 hash of the session token is stored in the database, and the browser keeps the raw session token only in memory.

`BREAK_GLASS_ADMIN_TOKEN` is optional. When configured, it must be strong and different from the enrollment token. Leave it unset for normal operation.

The endpoint agent removes the shared enrollment token from its configuration after successful enrollment and retains only its unique agent credential.

## Deployment guidance

This repository is an MVP and should not be exposed directly to the public Internet without additional controls. Native RBAC is implemented, but production deployments should still use HTTPS, network segmentation, rate limiting, database backups, credential lifecycle controls, and optionally external SSO/federation.

The agent deliberately does not expose arbitrary remote shell execution. Keep that property when contributing new job types.


## Production TLS and agent identity

The production Compose overlay terminates HTTPS at NGINX and requires a verified client certificate for every `/api/agent/` request. The backend is bound on the host only to `127.0.0.1:8080`.

Each agent certificate fingerprint is bound to one agent record. The fingerprint is an identity-binding value supplied by NGINX after certificate-chain validation; certificate trust comes from mTLS validation against the configured agent CA.

Agents still require their individual application token. Possession of only a valid client certificate or only an agent token is not sufficient when `AGENT_MTLS_REQUIRED=true`.

Never commit server private keys, agent private keys, CA private keys or generated certificates. The repository ignores common certificate and key extensions.

## Backups

Database backups may contain endpoint inventory, vulnerability information, audit records and authentication metadata. Treat them as sensitive.

The included backup script creates a PostgreSQL custom-format dump and SHA-256 checksum but does not encrypt the dump. Production copies should be stored off-host in encrypted storage with access control and retention.

Restore requires explicit `CONFIRM_RESTORE=YES`. If restore fails, the application is intentionally left stopped for investigation.
