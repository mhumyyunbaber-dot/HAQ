# Haq security audit and remediation

**Review date:** 16 October 2026  
**Application:** Haq legal-rights navigator, version 0.2.0  
**Scope:** files in this workspace, the running preview server, installed/locked npm dependencies, local HTTP/browser tests, and source-backup/monitoring tools.  
**Result:** applicable static-app controls implemented and tested. **Not a certification of production readiness or a full penetration test.**

## Executive summary

The existing site was an anonymous browser-only navigator served by `python -m http.server` from the whole project directory. It had no authentication system, roles, JWTs, database, password reset, uploads or model API. These features have **not** been invented or presented as implemented.

The main remediated deployment risk was unrestricted project-directory serving: adding a `.env` or credentials file later could have made it publicly downloadable. The replacement Node/Express server loads only five named public paths, rejects all other paths, disables request bodies, has strict security headers and limits requests. A local `.env` now exists with restrictive permissions and configuration only; no API keys were needed or found. User descriptions remain browser-local.

The running preview was moved from the old Python directory server to the hardened server using **Node 24.22.0**. Production startup also rejects Node older than 24. The user-facing preview uses Arena-provided HTTPS; an independent production domain/certificate is **not deployed**.

## Findings and fixes

| ID | Severity / scope | Finding | Remediation | Status |
|---|---|---|---|---|
| H-01 | High deployment risk if sensitive files are present; no confirmed credential leak | Entire project root exposed by development static server; no public-asset boundary | Replaced server with an exact in-memory asset map; `.env`, `.git`, server/config/dependency/backup paths are inaccessible; stopped old process | Fixed and HTTP-tested |
| M-01 | Medium | No enforced CSP or other application security headers | Helmet CSP without inline/eval; no browser connects; nosniff, referrer/permission/resource policies; no-store; production framing restrictions and HSTS | Fixed; header/browser tests pass |
| M-02 | Medium | No request/rate/host/origin controls | Rate limits, body/method/target/header/socket bounds, exact host/origin checks, no CORS API exposure, untrusted proxy-header rejection | Fixed within a single server process; distributed protection remains an operations task |
| M-03 | Medium | No locked security workflow or dependency/secret gate | Exact dependency versions + lockfile, npm audit, local secret-pattern/history tool, read-only pinned-action CI and weekly update configuration | Local gates pass; remote workflow activation pending |
| M-04 | Medium operational gap | No application security events, monitoring hook or recovery drill | Generic errors, HMAC-tagged minimal JSON security logs, alert-evaluation script and tests, source-only backup with checksum restore drill | Local controls pass; production collector/alert/off-host scheduling pending |
| D-01 | Production release constraint | Sandbox initially used Node 20, which is not the selected supported production baseline | Preview now runs Node 24.22.0; Node 24 CI; production startup requires Node 24+ | Fixed for running app; operators must maintain runtime/OS updates |

Severity reflects the original configuration risk, not a claim that a credential, password, account or database was compromised. No original DOM-XSS exploit was established; existing escaping was retained and strengthened with CSP and regression tests.

## Requested-control checklist

| # | Requested control | Applied outcome / limitation |
|---|---|---|
| 1 | Audit existing code | Reviewed architecture, render/input/export flows, source registry, serving boundary, dependencies and deployment configuration; targeted tests added |
| 2 | Keep keys/secrets in `.env` | Server-only `.env` and redacted `.env.example`; local mode `0600`. No API/authentication secrets currently exist, so none were fabricated. Browser CSP prevents API calls |
| 3 | Do not upload credentials | `.gitignore` and export allowlist exclude secrets. No remote push/upload performed. Existing tracked-secret removal/rotation procedure documented |
| 4 | Argon2id passwords | **Not applicable:** there are no passwords/accounts. Argon2id release requirements documented for a future auth system; not falsely claimed as active |
| 5 | Proper authentication | **Not applicable to public static guides:** no sessions/login/private data APIs. Login/admin/reset routes deliberately do not exist |
| 6 | Separate admin/user roles | **Not applicable:** no accounts or privileged actions. Future server-owned RBAC requirements documented |
| 7 | Authorize every protected API | **No protected APIs exist.** `/api/*` and `/admin` denied. Authorization must be implemented before new private endpoints, not merely in UI |
| 8 | Verify JWT signature/expiry/claims | **Not applicable:** no JWTs are issued or accepted. Requirements for algorithm/signature/issuer/audience/expiry/nbf/revocation are documented, not implemented |
| 9 | Parameterized queries | **Not applicable:** no SQL, ORM, database driver or query execution. SQL-like request targets are rejected, not executed |
| 10 | Validate API requests | No API accepts input. Hosted request method/body/target/origin/host/size validation is server-side; local form validates region/text/date. Client validation is not an API security boundary |
| 11 | Rate limiting | Global per-client rate limit with 429/Retry-After; untrusted forwarding headers cannot bypass it. In-memory/single-instance limitations documented |
| 12 | Restrict CORS | No cross-origin API requirement; no wildcard/credentialed CORS headers. Same-origin checks and rejected cross-site subresources tested |
| 13 | HTTPS | Arena preview uses platform HTTPS. Production has HTTPS-only origin checks, trusted-proxy enforcement, HSTS and Caddy automatic-TLS template. **Real production TLS/DNS issuance and external validation still pending** |
| 14 | Disable production debug | Express production error mode always; debug configuration rejected; no stack traces/secret values in application errors |
| 15 | Security headers | Strict hosted CSP, hash-CSP portable HTML, no inline styles/events, nosniff, no-referrer, Permissions-Policy, CORP, no-store, production HSTS and DENY framing |
| 16 | Least-privilege database permissions | **Not applicable:** no database or DB identity. Production non-root/read-only service template and future DB privilege policy provided; host sandbox template not activated here |
| 17 | Validate file uploads | Upload feature is **disabled/nonexistent**; request bodies and upload endpoints rejected. Future quarantine/type/size/storage requirements documented |
| 18 | Scan/update dependencies | Exact current installed versions and integrity lockfile; full npm advisory audit including dev packages reports **0 known vulnerabilities**. This does not audit the OS or prove absence of unknown flaws |
| 19 | Scan repository secrets | Local source/artifact pattern scan: **0 findings**. No `.git` repository exists here, so real local history is unavailable. No accessible user remote repository: **remote/history scan not completed**. Scanner's history/redaction behaviour tested in disposable fixture repos |
| 20 | Safe errors | Fixed error text + server-generated request IDs; no stack, path, query, credential, body or header reflection; parser failures use minimal responses |
| 21 | Login/reset brute-force | **Not applicable:** no login/reset endpoints. Global limiter protects existing resources; future account-aware credential/reset protections specified |
| 22 | Admin MFA | **Not applicable:** no admin accounts. WebAuthn/reviewed TOTP and recovery requirements are a mandatory future feature gate, not an enabled MFA implementation |
| 23 | DB backups + restore | **Not applicable to a nonexistent database.** Source/config-template backup and isolated checksum restore tested; `.env` excluded. Not a production database/service restore |
| 24 | Logs/monitor suspicious activity | Minimal JSON security events enabled on running server; bounded log-analysis/alert-exit script tested. No external log collector, alert destination or on-call notification provisioned |
| 25 | OWASP Top 10 testing | Targeted access-boundary, XSS/CSP, validation, misconfiguration, dependency, request-abuse, error/privacy and logging checks; not a complete OWASP certification |
| 26 | Automated testing workflow | CI workflow and dependency-update configuration added to source. **Must be committed/enabled in real repository and made a required merge check** |
| 27 | Re-run after code changes | `npm run security` is the repeatable full gate; run again on every change. Final run evidence below |
| 28 | Fix critical/high before production | Tested H-01 risk remediated, no known npm advisory findings. Production release remains blocked on deployment/remote-scan/operations verification below; do not infer zero latent vulnerabilities |

## Targeted OWASP coverage

The following uses the familiar OWASP Top 10:2021 category names as a **coverage map**, not a claim of certification or that this is the latest OWASP edition.

| Category | Scoped evidence / applicability |
|---|---|
| Broken access control | Exact public-file boundary; denied env/config/backup/admin/API paths; no private identities or object ACLs to test |
| Cryptographic failures | No stored credentials or case database; HTTPS deployment policy, HSTS and secret-handling controls. Public production TLS not yet verified |
| Injection | User-derived HTML escaping; DOM-XSS attack strings remain text; CSP blocks injected script/style and outbound fetch; no SQL/shell execution |
| Insecure design | No unnecessary account/data-upload/API surface; privacy/local-processing boundary retained; unknown legal topics abstain |
| Security misconfiguration | Denied directory listing, safe errors, strict header policy, methods/host/origin/proxy checks; separate preview/production policy |
| Vulnerable/outdated components | Locked dependencies, advisory scan, supported Node baseline and recurring update workflow; external platform/OS scan still required |
| Identification/authentication failures | N/A for existing static service; future auth/JWT/MFA/reset requirements explicitly gated |
| Software/data integrity failures | Lockfile integrity, installs without lifecycle scripts, pinned CI action commits, source backup hashes, reviewed fixed source registry; no user code/deserialization |
| Security logging/monitoring failures | Redacted structured event tests and alert/quiet-window tool tests; operator collector/alert integration pending |
| SSRF | No server URL fetching, proxy-to-user-target or networked model endpoint; browser `connect-src 'none'` verified |

## Verification evidence

Commands executed locally against the changed code:

```text
npm run security
  build: hash-CSP standalone artifact built
  source scan: 0 supported-pattern findings; real local Git history skipped (no repo)
  npm audit: 0 known advisory vulnerabilities
  HTTP suite: 10 groups passed, 0 failed
  existing browser regression suite: passed
  browser XSS/CSP/exfiltration/offline checks: passed
  Python security-tool tests: 5 passed
  source backup: isolated restore, SHA-256 comparison passed
```

HTTP groups include many individual requests for secret/config paths, traversal/encoded/absolute/query targets, methods, body rejection, headers, arbitrary hosts/origins, forwarding-header rate-limit bypass, production HTTPS/framing and log privacy. Tests use isolated local servers and harmless attack simulations. The browser suite verifies English/Urdu/Roman Urdu behaviour, jurisdiction routing, saved/export behaviour, mobile overflow and lack of external application requests. Deliberate CSP probes are separate from normal application-policy checks.

Additional manual preview checks confirmed `/` responds 200 and `/.env` responds 404 with security headers. Raw npm evidence is stored locally as `security-dependency-audit.json`; the app server does not expose this file. CI/action jobs themselves were not executed on a remote provider.

## Release blockers and explicit limitations

1. **No remote repository audit:** provide access to the actual repository and all relevant history/artifacts, run independent secret scanning, rotate any historic leaks, and enable provider-native secret/push protection. This workspace has no local Git metadata and no remote repository was modified.
2. **Production TLS/infrastructure:** configure a real domain/DNS, validate Caddy and obtain a real certificate; verify public redirects/HSTS/origins/proxy headers, firewall and non-root service hardening. The template is not a live production deployment.
3. **Monitoring/recovery operations:** configure access-controlled durable logs, retention, alerts/on-call ownership and encrypted off-host source backups; test actual deployed-service recovery. This source restore drill does not replace database recovery if one is later added.
4. **Availability/runtime:** audit the real runtime image/OS, keep Node/Caddy patched, and add an edge or shared limiter for replicas/distributed abuse. In-process limits reset on restart and are not DDoS protection.
5. **Independent review:** run a broader deployment-specific security review before public release, address every critical/high finding, and have Pakistani lawyers review legal content/translations separately. Automated tests are scoped evidence, not proof that no vulnerability remains.
6. **Future feature gate:** accounts, admin actions, JWTs, SQL, private data or uploads cannot be enabled until the corresponding Argon2id/auth/MFA/authorization/validation/least-privilege/backup controls in `SECURITY.md` are actually implemented and tested.

**No credentials were uploaded. No authentication, JWT, MFA or database functionality is being represented as implemented.**
