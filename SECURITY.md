# Security policy · Haq v0.4

## Scope and privacy

Haq is a curated Pakistani legal-rights navigator, not live AI or legal representation. All descriptions/topic matching remain in the browser. The legal service serves public reference material only. Account data is separate from legal guidance; no case descriptions/uploads are accepted by a backend endpoint. Optional accounts are not required for guidance.

Runtime: gateway, web, identity, legal-reference, private PostgreSQL 17. See `MICROSERVICES.md` for deployment and recovery. No administrative user/panel exists. If one is introduced, require MFA, explicit authorization and dedicated tests before enabling it.

## Controls implemented

- Exact public asset and API methods; restrictive CSP (connect-src self), MIME/referrer/permissions headers, production framing denial/HSTS/HTTPS enforcement.
- Explicit host/origin checks, bounded URL/header/body handling, strict JSON/schema validation, CSRF and safe non-reflective errors. No wildcard/credentialed CORS or debug responses.
- Distinct internal service credentials; user forwarding/internal headers stripped; cookies sent only to identity; only gateway published. Independent private RPC/database networks in Compose.
- PostgreSQL DML-only runtime role; separate NOLOGIN schema owner; privileged one-shot migrations/imports only. Parameterized async queries, transaction-local clients, rollback, locks, uniqueness/foreign keys and migration checksums.
- Argon2id passwords, opaque hash-only multi-device sessions and secure cookie rotation/revocation. Explicit provider linking, no email auto-merge; OIDC/PKCE/state/nonce checks and Facebook token/subject validation.
- Global, client/account/route rate limits and bounded Argon2 work. **In-process only**: no fleet-wide limiter; Compose intentionally runs one gateway/identity replica.
- No request bodies, query strings, tokens, passwords, cookies or raw addresses in application security logs. Upstream failure/readiness information contains no credentials/addresses. No private values in API errors.
- Explicit read-only legacy import preserves users/hashes/provider links and revokes old sessions/tokens. No silent account merge, data reset or overwrite.
- Streaming AES-256-GCM PostgreSQL snapshots, wrong-key/tamper checks, isolated restore verification, and new-database-only recovery. Source archives have an explicit allowlist and checksum restore drill.
- Container definitions run application services non-root, read-only, with dropped capabilities, no-new-privileges and resource limits. OS/container execution/scan still needs verification on the deployment host.

## Secrets and scans

Actual `.env*`, native `.runtime/` PostgreSQL/configuration, `private/`, backups, keys and dependencies are excluded from source ZIPs and Docker build context. Keep private configuration mode 600 and its directory appropriately restricted. Never place server credentials in frontend scripts or generated HTML. Snapshot/restoration of the workspace may reset filesystem modes; repair private permissions before starting services.

`npm run scan:secrets` checks source/token patterns and local Git tracked-sensitive-file/history when available; it excludes provisioned local `.env*` files and private runtime stores. Tracked private env filenames and Git history still fail the gate. It is not a full credential/DLP audit. No repository/remote is connected here; remote history/CI enforcement was not inspected.

Run `npm run security` after changes: build, secret/dependency audit, legacy regressions, **real PostgreSQL/service integration**, browser legal/auth/XSS/CSP/privacy checks, Python tooling tests and source restore drill. It fails if PostgreSQL test configuration is missing. Configure the provided remote CI and make it a required branch check. Address all high/critical dependencies before production; include OS/image/host scanning, not npm alone.

## Deployment obligations and limitations

Before production, provision real HTTPS/domain and exact trusted proxy addresses, supported/pinned/scanned container images, real reviewed provider apps and SMTP, encrypted durable storage, restricted host/Docker access, scheduled encrypted off-host backups with separately recoverable keys, delivered monitoring alerts/on-call and deployment-specific OWASP testing. Compose environment variables are visible to Docker administrators and are not an encrypted secret store. Private Docker networking is not mTLS.

`deploy/Caddyfile` terminates TLS and overwrites forwarded headers. `deploy/haq.service` controls Compose; Docker daemon access is root-equivalent. Health checks/restart policies do not automatically restart a running unhealthy container. Rate limits/password-work caps are not distributed. Generated Compose credentials must not be regenerated against a retained database volume without a coordinated credential rotation.

The live workspace uses four separate native Node processes and PostgreSQL. Compose configuration has been validated, but no Docker daemon is available for container execution here. Provider/SMTP tests are mocked; real sign-in/email delivery activation is unverified. No production security certification is implied by local test results.

## Reporting

Do not post passwords, reset/session tokens, database dumps or legal case details in issues. Use a private channel selected by the deployment operator. If a credential may have leaked: revoke/rotate it, revoke affected sessions/tokens, inspect restricted logs, remove exposure and check backups/history before redeploying. Emergency legal matters need a qualified local lawyer or the appropriate emergency service, not an application security issue.
