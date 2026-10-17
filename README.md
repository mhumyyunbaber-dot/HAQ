# Haq · Pakistani legal-rights navigator

A working English, Urdu and Roman Urdu web app with six curated guides, jurisdiction caveats and optional accounts. It is not a lawyer, live AI, emergency response or an automated legal opinion. Descriptions and topic matching stay **in your browser**; no sign-up is required for legal guidance.

## v0.4: actual microservices

- **Gateway** — one public URL, routing, request validation, security headers and rate limiting.
- **Web** — website and account UI.
- **Identity** — native accounts, Google/Facebook integration, opaque multi-device sessions and optional profile fields; private **PostgreSQL 17**.
- **Legal-reference** — public curated guides/source catalog, not private questions.

Separate processes and Docker images; separate private networks/keys; no public database port. The old in-process server is now only a legacy test harness. SQLite is used only for migration/legacy tests, not the running identity service.

**[Deployment, architecture, account migration, backup and recovery → MICROSERVICES.md](MICROSERVICES.md)**

### Docker Compose

```bash
npm ci --ignore-scripts
npm run config:init -- --output .env.compose
# Private generated file; never commit or publish it.
docker compose --env-file .env.compose config --quiet
docker compose --env-file .env.compose up -d postgres
docker compose --env-file .env.compose run --rm migrate
# Import existing SQLite accounts BEFORE starting identity (see migration guide).
docker compose --env-file .env.compose up -d --build --wait
```

Existing-account imports preserve users, password hashes, profiles and provider subjects, but revoke legacy sessions/reset/OAuth tokens. The old private database is retained read-only. Imports refuse a nonempty destination; no silent merge or wipe.

### Native preview/development

Requires Node 24+, a configured real PostgreSQL instance, private `.env` and applied migrations. `npm start` launches **four independent Node processes**; it does not initialize or reset a database. `npm run config:init -- --native` creates configuration only when `.env` does not already exist. Native PostgreSQL provisioning and the current preview arrangement are documented in `MICROSERVICES.md`.

### Build and tests

```bash
npm run build                  # offline Haq.html with pinned hash CSP
npm run security               # full gate; real PostgreSQL is mandatory
npm run test:services           # PostgreSQL + HTTP service integration/backup/migration
npm run test:browser:services   # real browser through gateway and PostgreSQL
```

The standalone HTML supports offline legal guidance; online accounts are unavailable offline. Legal source content is curated, not a live law/amendment check. Coverage includes all Pakistan, with local-law and jurisdiction warnings rather than a claim that every federal/provincial remedy applies everywhere.

## Authentication and operations

Email/password works in the configured preview. Google, Facebook and real verification/recovery mail require your provider/SMTP credentials; setup notices do not fake a login or successful delivery. One provider subject maps to one account; multiple devices are allowed. Optional age range/gender includes prefer-not-to-say, with no full DOB. No email-only automatic account merge. See `AUTH-SETUP.md`.

See `SECURITY.md` for safeguards and production requirements; `SECURITY-AUDIT.md` distinguishes performed checks from deployment/remote-CI work still required. Docker Compose configuration was validated locally; the live workspace runs separate native services with PostgreSQL because no Docker daemon is available here. No real provider credentials, production TLS/domain, off-host backup schedule, delivered monitoring alerts or remote repository enforcement have been provisioned.
