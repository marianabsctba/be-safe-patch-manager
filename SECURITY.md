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


## Observability exposure

`/metrics` is intentionally blocked by the production NGINX configuration and should be scraped only through loopback or a private monitoring network.

Prometheus labels are kept low-cardinality and must not contain endpoint hostnames, IP addresses, usernames, CVEs, vulnerability titles, agent tokens, session tokens or client-certificate fingerprints.

`/health` is a liveness probe and does not query the database. `/ready` checks database reachability and the presence of an active administrator.

The backup exporter publishes only backup success state, timestamp, age and size. Backup filenames and SHA-256 values remain in the local runtime status file and are not exported as metrics.


## Endpoint health checks

The v0.11 health gate does not introduce arbitrary command execution.

Critical service names are validated against a restricted character set before they are sent to agents. Linux service checks use `systemctl is-active`; Windows service checks use the operating-system service API exposed through psutil.

Application health checks are restricted to HTTP(S) URLs whose host is `localhost` or a loopback IP address. URLs with embedded credentials and remote targets are rejected by the server and validated again by the agent.

Health telemetry stored in heartbeat inventory can contain operational state. Prometheus exports only aggregated counts and never uses service names, application-check names, hostnames or addresses as labels.

A health regression blocks ring advancement. It does not authorize or trigger rollback. Rollback retains its separate administrative approval gate.


## Remediation evidence and Greenbone rescans

Automated remediation evidence is deliberately narrower than generic Greenbone control.

The Patch Manager starts only the Greenbone task identifier already attached to the original vulnerability finding. It does not create arbitrary targets, scanners or scan tasks as part of the remediation flow.

A patch job must complete and pass post-patch validation before a rescan may be requested. The report ID returned by Greenbone is persisted and reconciliation waits for that exact report to reach a completed task state.

Automatic remediation is based on the absence of the same stable finding identity plus CVE from that exact post-patch report. A random later report, a running or partial report, or disappearance from an unrelated task cannot prove remediation.

Accepted-risk and false-positive workflow states are not overwritten by automated evidence. Manual rescan requests are restricted to operators, allowed only after an error or a still-detected result, require a reason and are audited.

Prometheus exposes only aggregate remediation lifecycle counts. Task IDs, report IDs, CVEs and endpoint identifiers are not used as metric labels.


## Agent fleet compatibility

Agent version and feature compatibility are treated as an execution-safety control.

Agents report a semantic software version, a protocol version and a bounded list of capabilities. In production, compatibility enforcement is enabled and an agent that does not meet the configured minimum version/protocol or a job's required capabilities cannot claim that job.

Compatibility blocking happens before a claim token is issued and before execution begins. A compatibility-blocked job is not treated as a failed patch attempt. When the endpoint later reports a compatible runtime, only jobs blocked specifically by the compatibility control are returned to the pending queue.

The base Compose configuration keeps enforcement disabled to allow staged fleet migration. Operators should not disable enforcement in production merely to bypass an outdated agent. Upgrade or replace the incompatible agent instead.

This version does not implement automatic agent self-update. Future distribution should require authenticated transport plus cryptographic artifact verification/signing before execution.
