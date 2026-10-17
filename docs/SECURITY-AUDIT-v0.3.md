> Historical v0.3 SQLite/monolith report. See current SECURITY-AUDIT.md for PostgreSQL microservices.

# Haq v0.3 authentication security review

**Date:** 16 October 2026. **Scope:** workspace source, local HTTP/browser tests and simulated provider/email flows. This supersedes the static-only v0.2 report, preserved in `docs/SECURITY-AUDIT-v0.2.md`. No real provider credentials, SMTP delivery, remote repository or independent public production deployment was available.

## Implemented change

Haq now offers email/password accounts, Google/Facebook OAuth integration, optional age range/gender profiles and account/session management. Anonymous legal browsing is preserved. It now has a private SQLite database and essential authentication cookies; the previous “no accounts/database/cookies” statements no longer describe this version.

### Auth controls

- Argon2id: 64 MiB memory, iterations 3, parallelism 1; 12–128 character passwords; expensive work bounded to two simultaneous operations.
- Session cookies: opaque 256-bit random identifiers, only hashes stored, HttpOnly/Lax, Secure + `__Host-` on HTTPS; separate loopback cookie for local HTTP. Login/register/provider completion rotate identifiers. Multiple devices are allowed; current/all logout, password change/reset revocation and expiration are enforced server-side.
- Session-backed CSRF on mutating requests; same-origin/Host/Fetch Metadata checks. Strict Zod schemas, 8 KiB JSON limit, exact API methods/paths, parameterized SQLite queries and current-session ownership checks. Client `userId`/`role` properties are rejected.
- One account per provider subject and canonical email. Gmail aliases normalize; repeated Google identity maps to one user. Never auto-merge by email. Linking requires recent authentication and primary-email verification; no identity reassignment to another user.
- Google state + PKCE + nonce + RS256/JWKS and issuer/audience/expiry/iat/subject/verified-email checks. Facebook debug token validates app/expiry/subject and matches `/me`; Facebook email is not trusted as a recovery credential. Provider tokens are not retained.
- Generic credential/recovery errors, tighter account/IP rate limits, safe logging and no token return to the client/logs. Single-use hashed verification/reset tokens expire after 30 minutes. Reset links use fragments and require explicit POST confirmation.
- No privileged admin role or admin routes. Database currently only permits normal users. No session JWTs, uploads or model APIs.

### Preserved/updated hardening

The exact public asset map now has six files including auth UI code. Environment, auth source/config, `private/`, database journals, backups and dependency paths remain inaccessible. Hosted CSP was deliberately changed from `connect-src 'none'` to **`connect-src 'self'`** for auth; external network calls and inline/eval scripts are still blocked. Offline HTML retains no-network hash CSP and does not provide account functionality.

Private DB directories/files use restrictive permissions and are ignored/excluded from source archives. The service template adds a private writable StateDirectory and 512 MiB memory budget. An independent AES-256-GCM SQLite backup tool and isolated integrity/schema restore test were added. This is separate from the source-only backup drill.

## Design risks addressed during implementation

1. **Email collision takeover:** matching emails never auto-link identities. Unverified native accounts cannot attach social methods before the mailbox owner verifies the primary address.
2. **Unverified Facebook email recovery:** Facebook email assertions are not adopted as primary/recovery addresses. A verified Google identity may establish an unused primary email only after explicit, recent-authenticated linking.
3. **OAuth login CSRF/replay:** single-use state is hashed, expires after 10 minutes and is bound to the browser session/provider. A revoked browser session cannot complete a pending callback. OIDC nonce/claims are checked separately.
4. **Reset/login races:** reset tokens are consumed transactionally after hashing, and login/password changes recheck the current stored password hash after asynchronous verification/work. Password changes/resets revoke sessions.
5. **Brute force/resource exhaustion:** global/IP/canonical-email limits plus bounded Argon2 concurrency; Gmail +tags/dots cannot evade the account bucket. These are not distributed-DDoS controls.
6. **Credential/source disclosure:** server asset allowlist remains in force; `.env` and `private/` are excluded from public routes, Git and source exports. Backup encryption key is not generated into or bundled with an archive.

## Automated verification

The Node suite includes **29 test groups** across:
- Existing HTTP security controls (10 groups).
- Auth/session/profile/CSRF/password/verification/reset/linking/provider and rate-limit tests (18 groups).
- Encrypted account snapshot/restore and wrong-key/tamper rejection (1 group).

Browser checks exercise actual email signup, reload-persistent login cookie, optional profile edit, escaped markup-shaped display names, logout/login, mobile layout and truthful unconfigured social-provider messages. Existing English/Urdu/Roman Urdu legal-guide regressions, DOM-XSS/CSP probes, external-fetch blocking and offline HTML checks remain covered. Python security-tool tests and source restore drill remain part of `npm run security`.

OAuth tests use simulated network responses and locally signed test ID tokens. SMTP tests use an in-memory test mail transport. These tests **do not prove real Google/Facebook app approval or real mail delivery**. No fake provider success or verification token is exposed in the running preview.

## Current activation state

- **Email/password:** works in preview; unverified status is explicit without SMTP.
- **Google/Facebook:** implementation present, not activated; needs real protected credentials, public origin and provider callbacks.
- **Verification/recovery:** implementation present, delivery unavailable until real SMTP is configured. Production native signup fails closed without configured email delivery.
- **Account database:** local private SQLite for development. Production requires an explicit external durable private path and operational storage encryption.
- **Admin/MFA:** absent, not claimed as active.
- **Backups:** encryption/restore code tested against fixtures. A real key, schedule, off-host storage and production restore procedure still need provisioning.

## Production release blockers

1. Configure real OAuth apps/callbacks/consent settings and test live success/denial/collision/linking/multiple-device flows. Configure and verify real SMTP sender/delivery.
2. Provision durable private encrypted storage and independent backup keys; schedule encrypted off-host snapshots, choose retention and test actual service restoration.
3. Deploy/validate real HTTPS domain, certificates, trusted reverse proxy, firewall and non-root service. Arena provides preview HTTPS only.
4. Perform real remote/history/artifact secret scans, enable CI/branch protection and native secret/push protection. No user remote repository was audited or modified here.
5. Arrange external logs/alerts/incident ownership, runtime/OS/native dependency updates and shared/edge limits for replicas/abuse.
6. Review privacy/terms, optional demographics, minors handling, deletion/backup retention and legal content/translations before public onboarding. The preview is not appropriate for sensitive real case/account data.
7. Independently review the auth implementation/deployment and resolve every critical/high finding before release. A passing scoped suite is not a guarantee of absence of vulnerabilities or a compliance certificate.

See `AUTH-SETUP.md` for required environment variables and exact callback paths, and `SECURITY.md` for the current operational boundary. Never paste credentials into chat or commit `.env`/private account data.
