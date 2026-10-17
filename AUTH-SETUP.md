# Haq account setup · PostgreSQL identity service

Accounts are optional. Browsing and matching legal topics remains anonymous and browser-only. Runtime architecture, database migration and recovery are documented in [MICROSERVICES.md](MICROSERVICES.md).

## Enable the backend honestly

Use Node 24+ and Docker Compose with PostgreSQL 17. Generate distinct internal keys and strong database passwords with `npm run config:init -- --output .env.compose`. Keep the file mode 600 and outside source control. Migrate the database before identity starts. The identity container receives only the low-privilege `AUTH_DATABASE_URL`, never `DATABASE_ADMIN_URL` or the PostgreSQL bootstrap password. Other application services receive no database credentials.

Native preview registration/login works without mail, but accounts remain visibly unverified. **Production native registration requires configured SMTP.** Recovery and resend return a setup/unavailable error without mail; tokens are never returned to the UI or written to an outbox/log. Provider buttons explain an unconfigured integration rather than reporting fake success.

Set `APP_ENV=production`, `NODE_ENV=production`, exact HTTPS `ALLOWED_ORIGINS`, and the same `AUTH_BASE_URL`. Configure the TLS terminator and its exact trusted proxy address at gateway. Cookies remain `HttpOnly`, `SameSite=Lax`; HTTPS uses the Secure `__Host-haq_session` cookie. Development loopback uses a separate local cookie. Do not weaken cookies for embedded previews; open the full preview if the browser blocks third-party cookies.

## Google / Gmail

In your Google Cloud OAuth application:

- Configure a Web application and your exact authorized public app origin.
- Register `https://YOUR_DOMAIN/api/auth/google/callback` as a redirect URI.
- Supply `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` privately to identity.
- Configure the consent screen and any required verification/test-user restrictions with Google.

Google uses PKCE, browser-bound single-use state, nonce and verified OIDC/JWKS signature/issuer/audience/expiry/email checks. `(provider, subject)` is database-unique; a transaction-scoped advisory lock serializes concurrent first logins for the same identity. A returning Google subject selects the same account across devices. Gmail dot/plus and googlemail aliases normalize to one native email account.

A matching email **does not auto-merge accounts**. Sign in to the existing account, verify its primary email and explicitly connect Google following recent authentication. Provider ownership conflicts fail closed. An explicitly linked verified Google identity can supply a missing primary email only if it is not already owned.

## Facebook

In your Meta app:

- Configure Facebook Login for a web app, your app domain and required privacy/data-deletion policies.
- Register `https://YOUR_DOMAIN/api/auth/facebook/callback`.
- Supply `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET`, and a **currently supported** `FACEBOOK_GRAPH_VERSION` (`vNN.N`) selected from your provider dashboard.
- Complete any provider app-review, business verification or live-mode requirements.

The backend validates the access token's application, validity/expiry and subject, and matches `/me` to that subject. Email is optional and is not adopted as a primary recovery credential or used for automatic merging. Missing email is handled without inventing one. The test suite mocks these provider responses; real credentials have not been supplied or activated here.

## Email delivery

Set `SMTP_HOST`, `SMTP_PORT` (normally 587 STARTTLS or 465 TLS), `SMTP_USER`, `SMTP_PASS`, and `MAIL_FROM`. Supply the exact HTTPS `AUTH_BASE_URL` for links. TLS is required for delivery. Configure SPF/DKIM/DMARC with your mail operator and verify actual delivery and recovery before launch.

Verification and recovery links use fragments so tokens are not sent in the initial HTTP URL. The UI requires explicit confirmation; the API consumes random hashed, expiring, single-use tokens. Password reset revokes all devices and tokens. Changing password requires the old password, rotates the current session and revokes other devices. Account deletion requires the current password (or recent authentication for a social-only account). There is no administrator account or admin panel.

## Account/session properties

- Argon2id password hashes: 64 MiB, 3 iterations, parallelism 1; bounded expensive-password work.
- Password length 12–128 characters, strict Zod schemas, parameterized asynchronous SQL.
- Opaque 256-bit session secrets; only hashes stored. Anonymous session 30 minutes; signed-in session seven-day absolute / 24-hour idle lifetime; at most 20 devices.
- CSRF token and same-origin gateway checks; no credentialed/wildcard CORS.
- Optional age range/gender/prefer-not-to-say; no full date of birth; demographics do not change legal guidance.
- Database row locks/transactions for session issuance, final password checks and token changes; atomic single-use verification/OAuth consumption; provider uniqueness enforced by PostgreSQL.
- Rate limits are per-process. Do not replicate gateway/identity until distributed limits/password-work budgets are implemented.

## Migration and recovery

Keep the old SQLite database and its WAL private and intact. Import explicitly before identity starts:

```bash
docker compose --env-file .env.compose --profile tools run --rm ops \
  node scripts/import-sqlite.cjs --sqlite /legacy/accounts.sqlite
```

The source mount is read-only. IDs, hashes, verification flags, profiles and provider identities are retained; active sessions and reset/verification/OAuth state are not imported. Users sign in again. No automatic merge or destructive overwrite is attempted.

Use `scripts/postgres-backup.cjs` and a separately managed `AUTH_BACKUP_KEY` for the runtime database. `scripts/accounts-backup.cjs` remains only for legacy SQLite. Source ZIPs include neither database nor credentials. See the architecture guide for authenticated-encryption backup, isolated verification, non-destructive recovery and off-host operations requirements.
