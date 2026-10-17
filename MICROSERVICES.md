# Haq microservices · v0.4

## What changed

Haq now runs four independently deployable Node services, with PostgreSQL owned by identity. This is a running service split, not just folders around the old server.

```text
Browser ── HTTPS/TLS terminator ── Gateway :3000
                                  ├─ Web :3101        HTML / CSS / application / account UI
                                  ├─ Identity :3102   accounts / sessions / OAuth / profile
                                  │                    └─ PostgreSQL 17 (private volume)
                                  └─ Legal :3103      public reference catalog / data.js

Browser: description → topic matching → legal guide (no description upload)
```

| Service | Public contract | Owns | Receives database credentials? |
|---|---|---|---|
| Gateway | One origin; exact allowed routes/methods; `/healthz` | Security headers, validation, global rate limit, upstream routing | No |
| Web | `/`, `/index.html`, `/style.css`, `/app.js`, `/auth-ui.js` | Website assets; browser-local guidance and account dialog | No |
| Identity | `/api/auth/*`, through gateway | Users, identities, opaque sessions, recovery/OAuth state; its PostgreSQL schema | Only a DML-only identity connection |
| Legal-reference | `/data.js`, `/api/legal/catalog` | Six public guides, official-source metadata, rental-law caveats | No |

Web, identity and legal require **different** gateway-to-service keys. Browser-supplied internal/forwarding headers are removed. Cookies and CSRF headers are forwarded only to identity. There is no question, matching, upload, chat, or AI endpoint. `services/legal/data.js` is the canonical public catalog; `npm run build` mirrors it to root `data.js` and the standalone offline file.

### Network boundaries

Compose publishes **only gateway**. Separate internal `web_rpc`, `identity_rpc` and `legal_rpc` networks prevent lateral service access. Only identity and one-shot operations jobs join the private `database` network. Web and legal have no outbound network; identity has outbound connectivity for real OAuth/SMTP. There are no database or private service host ports. Service keys add an authenticated boundary; the private Docker networks themselves are not encrypted or mTLS. Use encrypted networks/mTLS if moving this beyond one trusted host.

## Docker Compose setup

Requires Docker Engine with Compose v2, Node 24+ for local development/tests, and a protected host. No real OAuth or SMTP credentials are bundled.

```bash
npm ci --ignore-scripts
# Refuses to overwrite an existing file. Creates three distinct service keys and DB passwords.
npm run config:init -- --output .env.compose
chmod 600 .env.compose
mkdir -p private backups
chmod 700 private backups

docker compose --env-file .env.compose config --quiet
docker compose --env-file .env.compose build
docker compose --env-file .env.compose up -d postgres
docker compose --env-file .env.compose run --rm migrate
```

The `haq_admin` bootstrap credential is used only by PostgreSQL, migrations and explicit operations jobs. Migrations create `haq_owner` (NOLOGIN) and `haq_identity` (LOGIN, no superuser/database/role creation). Identity can select/insert/update/delete its five account tables, not create/drop/truncate tables or read the migration/import history. Identity readiness also rejects an administrative connection accidentally used as runtime configuration. Migrations are transactional, advisory-locked, checksum-verified and rerunnable. Changed historical migrations are rejected.

### Existing SQLite accounts: import before starting identity

1. Stop the old application. Keep `private/accounts.sqlite` **and its WAL/SHM together**, private and intact. Do not copy a live SQLite main file without a consistent snapshot. Do not delete the old database.
2. Keep the old private environment configuration separately; copy OAuth/SMTP/public-origin settings deliberately into the new protected configuration. Do not regenerate secrets against an existing PostgreSQL volume.
3. After the schema migration above, import with the legacy directory mounted read-only:

```bash
# If your old database is elsewhere, set LEGACY_DB_DIR in .env.compose to that directory.
docker compose --env-file .env.compose --profile tools run --rm ops \
  node scripts/import-sqlite.cjs --sqlite /legacy/accounts.sqlite
```

The import preserves user IDs, Argon2 password hashes, normalized emails/verification flags, optional profile fields and linked provider subjects. It verifies the imported rows inside the transaction. **Sessions, OAuth state, and verification/reset tokens are intentionally not imported. Everyone signs in again.** The source is opened read-only. A fingerprint makes an identical rerun a no-op. A different import requires an entirely empty account destination; there is no silent merge, truncate, account overwrite or session replacement. A failed import rolls back.

Bind mounts must be accessible to the operations container's UID/GID **1000:1000**; assign restricted ownership, not world-readable permissions. Imports are not run automatically on ordinary startup. A fresh installation can skip importing entirely.

```bash
docker compose --env-file .env.compose up -d --wait
curl --fail http://127.0.0.1:3000/healthz
```

`/healthz` reports web/identity/legal readiness. It discloses no database address or credentials. The container probe uses an authenticated loopback-only `/healthz` exception to public Host/TLS checks (a key derived from all three service keys, never exposed to a backend or browser). Other production requests still require the configured public host and HTTPS. Identity probes its database; unavailable dependencies produce a safe 503. Compose health checks observe readiness, while restart policies handle process exits. **An unhealthy-but-running container is not automatically restarted**: an operator/monitor must intervene.

`docker compose down` retains the PostgreSQL named volume. **Never use `down -v` on a live installation without a verified recovery plan.** Preserve private connection configuration separately from source archives. Rotate an existing database role password through an authorized database operation and update identity configuration together; editing only `IDENTITY_DB_PASSWORD` does not rotate an already-created role.

## Production configuration

Before exposing the service:

- Set `APP_ENV=production`, keep `NODE_ENV=production`, configure exact `ALLOWED_ORIGINS=https://your-domain` and matching `AUTH_BASE_URL` without a trailing slash.
- Keep `GATEWAY_BIND=127.0.0.1`. Use maintained Caddy/Nginx for a real HTTPS certificate; the supplied `deploy/Caddyfile` forwards only to gateway. Production rejects plaintext application requests.
- Set `TRUSTED_PROXIES` to the **actual exact source IP** from the local TLS terminator as seen inside the gateway container. Docker bridge/NAT may make this a bridge address rather than `127.0.0.1`. Inspect your deployment; never trust `0.0.0.0/0`, arbitrary forwarding headers, or an unverified client IP. Preserve/overwrite Host and X-Forwarded-Proto appropriately.
- Configure real Google/Facebook application credentials and exact `/api/auth/{provider}/callback` URLs. Configure real SMTP and `MAIL_FROM` for verification/recovery. Production native registration fails closed without email delivery. See `AUTH-SETUP.md`.
- Use encrypted disks/volumes, restricted host access and an operator-controlled secret store. `.env.compose` is a private development/deployment convenience, **not** an encrypted secret store. Compose environment values are visible to Docker administrators; `docker compose config` without `--quiet` may print them.
- Pin reviewed image digests, scan built OS images, recheck dependencies/advisories, use remote CI/branch protection, and conduct a deployment-specific security review. Container execution/OS image scanning were not possible in this workspace.
- Provision an off-host backup schedule, independent backup key, restore drills, readiness monitoring and alert delivery/on-call. These are not silently enabled by this source tree.

Application images run non-root with read-only filesystems, capability drops, no-new-privileges, resource limits and bounded temporary filesystems. PostgreSQL has its own persistent volume. The host systemd unit controls Compose (Docker control is root-equivalent); it is not the old single-process Node/SQLite unit.

**Scaling:** Compose intentionally runs one gateway and one identity instance. Their IP/account rate limits and expensive-password-work caps are in-process, not distributed. Do not horizontally replicate them until a shared limiter and a fleet-wide password-work budget are implemented and tested. Sessions and account uniqueness themselves live in PostgreSQL and support multiple devices.

## Encrypted PostgreSQL backups and recovery

Source ZIPs contain no database, passwords, service keys or case descriptions. `scripts/accounts-backup.cjs` is **legacy SQLite only**. Use `scripts/postgres-backup.cjs` for the running architecture.

Generate an independent 32-byte canonical base64 `AUTH_BACKUP_KEY` in your secret manager; supply it to operations jobs, not web, identity or legal. Never store the only key beside the backup. The PostgreSQL 17 operations image has matching `pg_dump`/`pg_restore` clients.

```bash
# Use a unique filename. An existing output is refused.
docker compose --env-file .env.compose --profile tools run --rm ops \
  node scripts/postgres-backup.cjs backup /backups/accounts-20261016.haqpg

docker compose --env-file .env.compose --profile tools run --rm ops \
  node scripts/postgres-backup.cjs verify /backups/accounts-20261016.haqpg
```

Backup uses a consistent custom-format `pg_dump` snapshot of the identity schema, streamed through AES-256-GCM with random nonce and authenticated envelope. Files are mode 600. Verification authenticates/decrypts before touching PostgreSQL, restores to a new isolated database, checks the required tables, revokes restored sessions/tokens, then drops that temporary database. It never replaces the live database. Wrong-key and tampering failures are tested. Verification accepts snapshots up to 1 GiB; provision sufficient protected temporary space for the decrypted dump (Compose operations tmpfs defaults to 128 MiB; increase deliberately for larger databases).

For actual disaster recovery, first provision a fresh PostgreSQL cluster/configuration and run the schema/role migration. Stop identity/gateway, restore into a **new explicitly named database**:

```bash
docker compose --env-file .env.compose --profile tools run --rm ops \
  node scripts/postgres-backup.cjs recover /backups/accounts-20261016.haqpg \
  --database haq_recovery_20261016
```

Recovery refuses an existing database. It preserves users/password hashes/provider links, revokes all restored sessions/reset/OAuth tokens, and reapplies DML-only runtime grants. Verify account counts, provider links, hashes/login and permissions; change both runtime/admin URLs to the new database and restart with readiness checks. Retain the previous database for controlled rollback. A failed recovery can leave the **new** partially restored recovery database for operator inspection; it never replaces the source/live database. Off-host retention, key escrow/rotation and the recovery decision remain operator responsibilities.

## Native development / current preview

The workspace preview uses the same four services as **separate Node processes**, with real PostgreSQL 17.11. Only gateway binds publicly on `0.0.0.0:3000`; private services bind `127.0.0.1:3101–3103`, and PostgreSQL `127.0.0.1:55432`. Docker Compose configuration was validated, but no Docker daemon is available here to execute containers.

For another native environment, create a private `.env` with `npm run config:init -- --native` (refuses existing files). Provision PostgreSQL with the generated administrative credentials, create database `haq`, then:

```bash
npm run db:migrate
# Existing SQLite only, before starting any identity requests:
npm run db:import -- --sqlite /absolute/private/accounts.sqlite
npm run build
npm start
```

`npm start` supervises four independent Node processes, passing database/provider secrets only to identity and each other service only its own key. It requires an existing migrated PostgreSQL instance; it never starts, drops or resets a database. It deliberately refuses production mode; use the hardened Compose deployment for production. `server.cjs` now exists only as a legacy in-process test harness; it is not the runtime entry point and will not start the old monolith.

## Tests and operations

```bash
npm run security           # requires real PostgreSQL; fails rather than silently mocking it
npm run test:services      # auth/provider mocks + real PG + HTTP services + migration/backup/failure tests
npm run test:browser:services
npm run compose:check      # needs Docker Compose CLI, not an engine
```

Tests create randomly named isolated databases and remove them. A privileged **test-only** connection is required (`HAQ_TEST_ADMIN_URL`/private `DATABASE_ADMIN_URL`, or `PGHOST`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`). Never run tests against a shared unmanaged cluster with conflicting `haq_*` roles. The existing 29 SQLite/HTTP/legacy-backup tests remain compatibility regressions; the separate PostgreSQL suite exercises the runtime storage and service boundary.

Security events omit request bodies, URLs/query strings, cookies, passwords and raw addresses. Gateway upstream failures emit `upstream_unavailable`; identity emits authentication events with pseudonymous client correlation. Export bounded structured logs to `scripts/monitor_logs.py`; its nonzero exit indicates an alert, not an automatically delivered notification. Monitor `/healthz` independently. OAuth/email tests use explicit mocked providers/mail, not real account-provider/SMTP activation. The GitHub workflow includes a real Compose build/start/smoke job, but has not run on a remote repository in this workspace.
