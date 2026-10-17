# Haq v0.4 security and architecture validation

**Validation date:** 16 October 2026. Scope: local source, four-service native runtime, real PostgreSQL 17.11, browser regressions, migration and restore fixtures. Not a production certification.

## Delivered architecture

- Independent gateway, web, identity and public legal-reference processes/images; private PostgreSQL account storage.
- Docker Compose with private per-service RPC/database networks, only gateway published, readiness checks, separate migration job, restricted runtime settings and persistent database volume.
- Asynchronous PostgreSQL storage with per-transaction clients, rollback, user/provider locks, atomic token consumption and DML-only runtime role. Startup rejects an administrative runtime connection.
- Public catalog service owns curated guides/source metadata. Legal description/matching stays browser-only; no backend matching/upload endpoint.
- Explicit read-only SQLite import preserves users/password hashes/verification/profile/provider identities and excludes all sessions/reset/OAuth/verification tokens. Fingerprinted reruns are idempotent; nonempty destinations are not merged or overwritten.
- Streaming AES-256-GCM PostgreSQL snapshot tool, isolated verification and new-database-only recovery with restored tokens/sessions revoked.

## Checks performed

| Check | Result |
|---|---|
| Existing Node auth/HTTP/legacy encrypted SQLite-backup regressions | **29/29 pass** |
| Real PostgreSQL auth + HTTP service integration suite | **29/29 pass** (18 auth groups plus 11 PostgreSQL/service groups) |
| Browser legal functionality | Pass: six guides, jurisdiction/province caveats, English/Urdu/Roman Urdu, save/export, emergency dialog and mobile layout |
| Browser native-account functionality through gateway/PostgreSQL | Pass: signup, optional profile, persistent cookie, reload, logout/login, escaped rendering, mobile and honest unconfigured-provider notice |
| Browser privacy/XSS/CSP/offline | Pass: legal description absent from HTTP requests; DOM-XSS probes blocked; outbound fetch blocked; offline hash-CSP bundle works |
| Concurrent registration / verification / reset | Pass: one duplicate account, single-use token consumption, revoked device sessions |
| PostgreSQL role/transaction checks | Pass: DDL/truncate/migration history access denied; rollback and simultaneous client transactions isolated |
| Gateway/private-service boundaries | Pass: distinct keys required; source/private routes absent; forged forwarding/internal headers cannot bypass limits; only identity receives cookies |
| Production readiness/Host/HTTPS regression | Pass: authenticated loopback-only health probe works; its credential does not bypass public-page Host/TLS checks |
| Legacy SQLite import fixture | Pass: two users/two provider subjects and Argon2/profile state retained; old tokens/sessions excluded; source unchanged; identical rerun no-op; different import into occupied destination refused |
| PostgreSQL encrypted backup/recovery fixture | Pass: mode 600, no plaintext account email in ciphertext, wrong key/tampering rejected, isolated restore/drop, new-database recovery retains working hashes/provider link and revokes restored sessions; source untouched |
| Service failure isolation | Pass: safe 503/readiness degradation; unaffected services continue responding |
| Python security tooling regressions | **5/5 pass** |
| Source secret-pattern scan | **0 findings**, private runtime/env stores excluded; tracked/history checks only when Git exists |
| Locked npm dependency audit | **0 vulnerabilities** reported |
| Source backup isolated restore | Pass: explicit architecture allowlist, SHA-256 manifests, private env/database/keys excluded |
| Docker Compose v2 configuration | `docker compose config --quiet` passes; only gateway published; environment/network invariants checked |
| Native multi-process preview | Four independent Node processes with real PostgreSQL; gateway public, private services/database loopback only |

The original local SQLite database was retained. It contained zero users/identities when imported, so no existing user account records needed conversion; the populated migration fixture above verifies preservation behavior. No test user account or provider identity is retained in the live account database.

## Important limits / outstanding operator work

1. **No Docker daemon:** Compose syntax/configuration was validated, but containers were not built/run here. A separate real-container build/start/smoke CI job is supplied and must be executed on a Docker-enabled host. OS/container-image vulnerability scanning is not represented by the npm audit.
2. **No real OAuth/SMTP credentials:** provider/OIDC/PKCE/linking/recovery tests use explicit mocks. Real Google/Facebook activation, provider review and SMTP delivery remain unverified. No fake email or provider success is shown.
3. **No connected Git repository/remote:** local tracked/history checks were explicitly skipped; remote history, branch protection and CI execution/enforcement were not inspected or configured remotely.
4. **No production deployment:** real domain/TLS, exact trusted reverse-proxy addresses, pinned/scanned images, host/volume encryption and production access controls remain to be provisioned.
5. **No provisioned production backup schedule/key/alerts:** encrypted fixture backup and restore drills passed. Durable off-host backups, independent key escrow, recurring restore drills, delivered monitoring alerts and on-call response are operator obligations.
6. **Single-instance limits:** gateway/identity rate limits and password-work caps are process-local. Horizontal replication requires distributed enforcement first.
7. **Private networks are not mTLS**, and Compose environment values are visible to Docker administrators. Health checks do not automatically restart an unhealthy-but-running container.

Run `npm run security` after changes and before deployment. See `MICROSERVICES.md`, `AUTH-SETUP.md`, `SECURITY.md` and `docs/validation-v0.4.txt` for operations/evidence. Historical static-only/SQLite reports are explicitly archived under `docs/` and do not describe the current runtime.
