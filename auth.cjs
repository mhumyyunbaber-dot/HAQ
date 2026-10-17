'use strict';

// SQLite is loaded only by the explicit legacy migration/test helper.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  hash,
  verify,
  Algorithm
} = require('@node-rs/argon2');
const {
  rateLimit
} = require('express-rate-limit');
const express = require('express');
const {
  z
} = require('zod');
const nodemailer = require('nodemailer');
const token = () => crypto.randomBytes(32).toString('base64url');
const digest = s => crypto.createHash('sha256').update(s).digest('hex');
const now = () => Date.now();
const DAY = 86400000;
const passwordPolicy = z.string().min(12).max(128).refine(s => !['passwordpassword', '123456789012', 'abcdefghijkl'].includes(s.toLowerCase()));
const age = z.enum(['under-18', '18-24', '25-34', '35-44', '45-54', '55-64', '65-plus', 'prefer-not']).nullable().optional();
const gender = z.enum(['woman', 'man', 'non-binary', 'self-described', 'prefer-not']).nullable().optional();
const profileSchema = z.object({
  name: z.string().trim().min(1).max(60).refine(s => !/[\x00-\x1f\x7f]/.test(s)),
  ageRange: age,
  gender
}).strict();
function emailKey(value) {
  let email = z.email().max(254).parse(value.trim().toLowerCase());
  let [local, domain] = email.split('@');
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.split('+')[0].replace(/\./g, '');
  if (!local) throw new Error('Invalid email');
  return local + '@' + domain;
}
function readAuthConfig(env, mode) {
  const base = env.AUTH_BASE_URL || '';
  if (base) {
    const u = new URL(base);
    if (u.origin !== base || u.username || u.password || u.protocol !== 'https:' && !(mode !== 'production' && u.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(u.hostname))) throw new Error('Invalid AUTH_BASE_URL');
  }
  const google = {
    id: env.GOOGLE_CLIENT_ID || '',
    secret: env.GOOGLE_CLIENT_SECRET || ''
  };
  const facebook = {
    id: env.FACEBOOK_APP_ID || '',
    secret: env.FACEBOOK_APP_SECRET || '',
    version: env.FACEBOOK_GRAPH_VERSION || ''
  };
  if (facebook.version && !/^v\d{2}\.\d$/.test(facebook.version)) throw new Error('Invalid Facebook API version');
  for (const provider of [google, facebook]) if (Boolean(provider.id) !== Boolean(provider.secret)) throw new Error('Incomplete OAuth credentials');
  if ((google.id || facebook.id) && !base) throw new Error('OAuth requires AUTH_BASE_URL');
  if (facebook.id && !facebook.version) throw new Error('Set a supported Facebook Graph API version');
  const mail = {
    host: env.SMTP_HOST || '',
    port: Number(env.SMTP_PORT || 587),
    user: env.SMTP_USER || '',
    pass: env.SMTP_PASS || '',
    from: env.MAIL_FROM || ''
  };
  if (mail.host && (!mail.from || !base || !Number.isInteger(mail.port) || mail.port < 1 || mail.port > 65535)) throw new Error('Incomplete SMTP configuration');
  const enabled = env.AUTH_ENABLED !== 'false';
  if (mode === 'production' && enabled) {
    if (!base || !(env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).includes(base)) throw new Error('Production auth requires a configured same-origin AUTH_BASE_URL');
    if (!env.AUTH_DATABASE_URL && (!env.AUTH_DB_PATH || !path.isAbsolute(env.AUTH_DB_PATH) || path.resolve(env.AUTH_DB_PATH).startsWith(__dirname + path.sep))) throw new Error('Use a private external persistent database path in production');
  }
  const file = mode === 'test' ? ':memory:' : env.AUTH_DB_PATH || path.join(__dirname, 'private', 'accounts.sqlite');
  return {
    base,
    google,
    facebook,
    mail,
    file,
    databaseUrl: env.AUTH_DATABASE_URL || null,
    enabled
  };
}
function openDatabase(file) {
  if (file !== ':memory:') {
    const dir = path.dirname(path.resolve(file));
    fs.mkdirSync(dir, {
      recursive: true,
      mode: 0o700
    });
    if (fs.lstatSync(dir).isSymbolicLink() || fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) throw new Error('Unsafe database location');
    fs.chmodSync(dir, 0o700);
  }
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(file);
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, email TEXT, email_key TEXT UNIQUE, email_verified INTEGER NOT NULL DEFAULT 0,
      name TEXT NOT NULL, password_hash TEXT, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user')),
      age_range TEXT, gender TEXT, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS identities (
      provider TEXT NOT NULL CHECK(provider IN ('google','facebook')), subject TEXT NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(provider, subject), UNIQUE(user_id, provider)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL, created_at INTEGER NOT NULL, auth_at INTEGER NOT NULL,
      last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS oauth_states (
      state_hash TEXT PRIMARY KEY, session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
      provider TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL, intent TEXT NOT NULL,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS email_tokens (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset')), expires_at INTEGER NOT NULL
    );
    PRAGMA user_version=1;`);
  if (file !== ':memory:') for (const f of [file, file + '-wal', file + '-shm']) if (fs.existsSync(f)) fs.chmodSync(f, 0o600);
  return db;
}
function createAuth(config, audit, options = {}) {
  const c = config.auth;
  const {
    postgresStore,
    sqliteTestStore
  } = require('./packages/storage/index.cjs');
  if (!c.databaseUrl && config.mode !== 'test') throw new Error('Runtime identity requires PostgreSQL');
  const db = c.databaseUrl ? postgresStore(c.databaseUrl) : sqliteTestStore(openDatabase(c.file));
  const sql = s => db.prepare(s);
  const transaction = fn => db.transaction(fn);
  const router = express.Router();
  const mailer = c.mail.host ? nodemailer.createTransport({
    host: c.mail.host,
    port: c.mail.port,
    secure: c.mail.port === 465,
    requireTLS: c.mail.port !== 465,
    auth: c.mail.user ? {
      user: c.mail.user,
      pass: c.mail.pass
    } : undefined,
    connectionTimeout: 8000,
    socketTimeout: 10000,
    tls: {
      minVersion: 'TLSv1.2'
    }
  }) : null;
  const sendMail = options.sendMail || (mailer ? async message => mailer.sendMail({
    from: c.mail.from,
    ...message
  }) : null);
  const mailReady = Boolean(sendMail);
  const providerReady = p => Boolean(c.base && c[p]?.id && c[p]?.secret && (p !== 'facebook' || c.facebook.version));
  const publicConfig = () => ({
    google: providerReady('google'),
    facebook: providerReady('facebook'),
    email: true,
    emailDelivery: mailReady,
    registration: config.mode !== 'production' || mailReady,
    multiDevice: true,
    optionalProfile: true
  });
  const providersFor = async id => (await sql('SELECT provider FROM identities WHERE user_id=? ORDER BY provider').all(id)).map(x => x.provider);
  const publicUser = async id => {
    const u = await sql('SELECT id,email,email_verified,name,role,age_range,gender,created_at,password_hash IS NOT NULL AS has_password FROM users WHERE id=?').get(id);
    if (!u) return null;
    return {
      id: u.id,
      email: u.email,
      emailVerified: Boolean(u.email_verified),
      name: u.name,
      role: u.role,
      ageRange: u.age_range,
      gender: u.gender,
      createdAt: u.created_at,
      hasPassword: Boolean(u.has_password),
      providers: await providersFor(id)
    };
  };
  const secureRequest = req => config.mode === 'production' || req.secure || /^3000-[a-z0-9-]+\.e2b\.app$/i.test(req.headers.host || '');
  const cookieName = req => secureRequest(req) ? '__Host-haq_session' : 'haq_session_local';
  const cookieOptions = req => ({
    httpOnly: true,
    secure: secureRequest(req),
    sameSite: 'lax',
    path: '/'
  });
  async function getSession(req) {
    const name = cookieName(req);
    const cookie = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(name + '='));
    if (!cookie) return null;
    const value = cookie.slice(name.length + 1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
    const s = await sql('SELECT * FROM sessions WHERE token_hash=?').get(digest(value));
    if (!s) return null;
    if (s.expires_at <= now() || s.last_seen < now() - (s.user_id ? DAY : 1800000)) {
      await sql('DELETE FROM sessions WHERE token_hash=?').run(s.token_hash);
      return null;
    }
    if (now() - s.last_seen > 300000) await sql('UPDATE sessions SET last_seen=? WHERE token_hash=?').run(now(), s.token_hash);
    return s;
  }
  async function newSession(req, res, userId = null) {
    return transaction(async()=>{
    if(userId)await sql('SELECT id FROM users WHERE id=? FOR UPDATE').get(userId);
    if (req.authSession) await sql('DELETE FROM sessions WHERE token_hash=?').run(req.authSession.token_hash);
    const value = token(),
      stamp = now(),
      ttl = userId ? 7 * DAY : 1800000;
    await sql('INSERT INTO sessions VALUES (?,?,?,?,?,?,?)').run(digest(value), userId, token(), stamp, userId ? stamp : 0, stamp, stamp + ttl);
    res.cookie(cookieName(req), value, {
      ...cookieOptions(req),
      maxAge: ttl
    });
    req.authSession = await sql('SELECT * FROM sessions WHERE token_hash=?').get(digest(value));
    if (userId) await sql('DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 20)').run(userId, userId);
    return req.authSession;
    });
  }
  const failure = (res, status, code, message) => res.status(status).json({
    code,
    error: message
  });
  router.use(async (req, res, next) => {
    req.authSession = await getSession(req);
    next();
  });
  const needUser = (req, res, next) => req.authSession?.user_id ? next() : failure(res, 401, 'sign_in_required', 'Please sign in again.');
  const csrf = (req, res, next) => {
    const provided = req.headers['x-csrf-token'];
    const expected = req.authSession?.csrf;
    if (typeof provided !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(provided) || !expected || provided.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) return failure(res, 403, 'csrf_failed', 'Your form expired. Please reopen it and try again.');
    next();
  };
  const limiter = (limit, event, keyGenerator) => rateLimit({
    windowMs: 900000,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    validate: {
      xForwardedForHeader: false,
      forwardedHeader: false
    },
    ...(keyGenerator ? {
      keyGenerator
    } : {}),
    handler: (req, res) => {
      audit(event, req, 429);
      failure(res, 429, 'rate_limited', 'Too many attempts. Please try again later.');
    }
  });
  router.use(['/register', '/login', '/forgot', '/reset', '/verify', '/resend', '/oauth', '/password', '/delete'], limiter(25, 'auth_rate_limit'));
  router.use(express.json({
    limit: '8kb',
    strict: true,
    type: 'application/json'
  }));
  router.use((req, res, next) => {
    if (['POST', 'PATCH', 'DELETE'].includes(req.method) && !req.is('application/json')) return failure(res, 415, 'json_required', 'Send a JSON request.');
    next();
  });
  const validate = schema => (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return failure(res, 400, 'invalid_input', 'Check the fields. Passwords must be 12–128 characters; profile fields are optional.');
    req.input = parsed.data;
    next();
  };
  const accountLimit = limiter(10, 'account_auth_rate_limit', req => digest('account:' + emailKey(req.input.email)));
  // Bound expensive password work globally as well as by account/client; no unbounded Argon2 queue.
  let hashing = 0;
  async function passwordWork(fn) {
    if (hashing >= 2) {
      const e = new Error('busy');
      e.busy = true;
      throw e;
    }
    hashing++;
    try {
      return await fn();
    } finally {
      hashing--;
    }
  }
  const hashPassword = async p => await passwordWork(() => hash(p, {
    algorithm: Algorithm.Argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1
  }));
  let dummyHash;
  const checkPassword = async (h, p) => await passwordWork(async () => verify(h || (await (dummyHash ||= hash('no-account-' + token(), {
    algorithm: Algorithm.Argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1
  }))), p));
  const recent = req => req.authSession && req.authSession.auth_at > now() - 600000;
  const prune = async () => {
    const stamp = now();
    await sql('DELETE FROM sessions WHERE expires_at<? OR last_seen<?').run(stamp, stamp - DAY);
    await sql('DELETE FROM oauth_states WHERE expires_at<?').run(stamp);
    await sql('DELETE FROM email_tokens WHERE expires_at<?').run(stamp);
  };
  let lastPrune = 0;
  router.use(async (req, res, next) => {
    if (now() - lastPrune > 600000) {
      await prune();
      lastPrune = now();
    }
    next();
  });
  const response = async (req, res) => res.json({
    user: req.authSession?.user_id ? await publicUser(req.authSession.user_id) : null,
    csrf: req.authSession?.csrf || null,
    providers: publicConfig()
  });
  router.get('/session', response);
  router.get('/bootstrap', limiter(60, 'bootstrap_rate_limit'), async (req, res) => {
    if (!req.authSession) await newSession(req, res);
    await response(req, res);
  });
  async function sendToken(user, purpose, req) {
    if (!sendMail) return;
    const raw = token();
    await transaction(async () => {
      await sql('SELECT id FROM users WHERE id=? FOR UPDATE').get(user.id);
      await sql('DELETE FROM email_tokens WHERE user_id=? AND purpose=?').run(user.id, purpose);
      await sql('INSERT INTO email_tokens VALUES (?,?,?,?)').run(digest(raw), user.id, purpose, now() + 1800000);
    });
    const url = c.base + '/#' + purpose + '=' + raw;
    // Tokens are sent only through SMTP, never returned by API responses or security logs.
    Promise.resolve(sendMail({
      to: user.email,
      subject: purpose === 'verify' ? 'Verify your Haq email' : 'Reset your Haq password',
      text: `${purpose === 'verify' ? 'Verify your email' : 'Reset your password'} using this single-use link (valid for 30 minutes):\n${url}\n\nIf you did not request this, ignore this message. Haq will never ask you to email a password or legal case details.`
    })).catch(() => audit('mail_delivery_failed', req, 503));
  }
  router.post('/register', csrf, validate(profileSchema.extend({
    email: z.email().max(254),
    password: passwordPolicy
  })), accountLimit, async (req, res) => {
    if (config.mode === 'production' && !mailReady) return failure(res, 503, 'mail_not_configured', 'Account registration needs email delivery to be configured.');
    const input = req.input,
      key = emailKey(input.email),
      passwordHash = await hashPassword(input.password);
    let id;
    try {
      id = await transaction(async () => {
        const id = crypto.randomUUID();
        await sql('INSERT INTO users(id,email,email_key,name,password_hash,age_range,gender,created_at) VALUES (?,?,?,?,?,?,?,?)').run(id, input.email.trim().toLowerCase(), key, input.name, passwordHash, input.ageRange || null, input.gender || null, now());
        return id;
      });
    } catch (e) {
      if (e.code === '23505' || e.code?.includes('SQLITE_CONSTRAINT') || String(e.message).includes('UNIQUE')) return failure(res, 409, 'account_exists', 'Unable to create this account. Try your existing sign-in method or password recovery.');
      throw e;
    }
    await newSession(req, res, id);
    await sendToken({
      id,
      email: input.email
    }, 'verify', req);
    audit('account_created', req, 201);
    res.status(201).json({
      user: await publicUser(id),
      csrf: req.authSession.csrf,
      providers: publicConfig()
    });
  });
  router.post('/login', csrf, validate(z.object({
    email: z.email().max(254),
    password: z.string().min(1).max(128)
  }).strict()), accountLimit, async (req, res) => {
    const u = await sql('SELECT * FROM users WHERE email_key=?').get(emailKey(req.input.email));
    const ok = await checkPassword(u?.password_hash, req.input.password);
    if (!u || !u.password_hash || !ok) {
      audit('login_failed', req, 401);
      return failure(res, 401, 'invalid_credentials', 'Email or password is incorrect.');
    }
    const signedIn=await transaction(async()=>{
      const current=await sql('SELECT password_hash FROM users WHERE id=? FOR UPDATE').get(u.id);
      if(current?.password_hash!==u.password_hash)return false;
      await newSession(req,res,u.id);return true;
    });
    if(!signedIn)return failure(res,401,'invalid_credentials','Email or password is incorrect.');
    audit('login_success', req, 200);
    await response(req, res);
  });
  router.patch('/profile', needUser, csrf, validate(profileSchema), async (req, res) => {
    await sql('UPDATE users SET name=?,age_range=?,gender=? WHERE id=?').run(req.input.name, req.input.ageRange || null, req.input.gender || null, req.authSession.user_id);
    await response(req, res);
  });
  router.post('/logout', csrf, validate(z.object({
    all: z.boolean().optional()
  }).strict()), async (req, res) => {
    if (req.input.all && req.authSession.user_id) await sql('DELETE FROM sessions WHERE user_id=?').run(req.authSession.user_id);else await sql('DELETE FROM sessions WHERE token_hash=?').run(req.authSession.token_hash);
    res.clearCookie(cookieName(req), cookieOptions(req));
    audit('logout', req, 200);
    res.json({
      ok: true
    });
  });
  router.post('/resend', needUser, limiter(3, 'verification_rate_limit', req => req.authSession.user_id), csrf, validate(z.object({}).strict()), async (req, res) => {
    if (!mailReady) return failure(res, 503, 'mail_not_configured', 'Email delivery is not configured.');
    const u = await sql('SELECT id,email,email_verified FROM users WHERE id=?').get(req.authSession.user_id);
    if (u.email && !u.email_verified) await sendToken(u, 'verify', req);
    res.json({
      ok: true,
      message: 'If needed, a verification email has been sent.'
    });
  });
  router.post('/forgot', csrf, validate(z.object({
    email: z.email().max(254)
  }).strict()), accountLimit, async (req, res) => {
    if (!mailReady) return failure(res, 503, 'mail_not_configured', 'Email delivery is not configured.');
    const u = await sql('SELECT id,email,password_hash,email_verified FROM users WHERE email_key=?').get(emailKey(req.input.email));
    if (u && (u.password_hash || u.email_verified)) await sendToken(u, 'reset', req);
    res.json({
      ok: true,
      message: 'If an eligible account exists, a reset link will be sent.'
    });
  });
  router.post('/verify', csrf, validate(z.object({
    token: z.string().regex(/^[A-Za-z0-9_-]{43}$/)
  }).strict()), async (req, res) => {
    const record=await transaction(async()=>{
      const found=await sql("DELETE FROM email_tokens WHERE token_hash=? AND purpose='verify' AND expires_at>? RETURNING *").get(digest(req.input.token),now());
      if(found)await sql('UPDATE users SET email_verified=1 WHERE id=?').run(found.user_id);
      return found;
    });
    if(!record)return failure(res,400,'invalid_token','This link is invalid or expired. Request another email.');
    res.json({
      ok: true,
      message: 'Email verified. You can now sign in.'
    });
  });
  router.post('/reset', csrf, validate(z.object({
    token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    password: passwordPolicy
  }).strict()), async (req, res) => {
    const h = digest(req.input.token);
    const record = await sql("SELECT * FROM email_tokens WHERE token_hash=? AND purpose='reset' AND expires_at>?").get(h, now());
    if (!record) return failure(res, 400, 'invalid_token', 'This link is invalid or expired. Request another email.');
    const passwordHash = await hashPassword(req.input.password);
    const updated = await transaction(async () => {
      const used = await sql("DELETE FROM email_tokens WHERE token_hash=? AND purpose='reset' AND expires_at>?").run(h, now());
      if (!used.changes) return false;
      await sql('UPDATE users SET password_hash=?,email_verified=1 WHERE id=?').run(passwordHash, record.user_id);
      await sql('DELETE FROM sessions WHERE user_id=?').run(record.user_id);
      await sql('DELETE FROM email_tokens WHERE user_id=?').run(record.user_id);
      return true;
    });
    if (!updated) return failure(res, 400, 'invalid_token', 'This link is invalid or expired.');
    res.clearCookie(cookieName(req), cookieOptions(req));
    audit('password_reset', req, 200);
    res.json({
      ok: true,
      message: 'Password changed. Sign in again on your devices.'
    });
  });
  router.post('/password', needUser, csrf, validate(z.object({
    currentPassword: z.string().max(128),
    password: passwordPolicy
  }).strict()), async (req, res) => {
    const u = await sql('SELECT password_hash FROM users WHERE id=?').get(req.authSession.user_id);
    if (!u.password_hash || !(await checkPassword(u.password_hash, req.input.currentPassword))) return failure(res, 401, 'invalid_credentials', 'Current password is incorrect.');
    const newHash = await hashPassword(req.input.password),
      id = req.authSession.user_id;
    const changed=await transaction(async()=>{
      const current=await sql('SELECT password_hash FROM users WHERE id=? FOR UPDATE').get(id);
      if(current?.password_hash!==u.password_hash)return false;
      await sql('UPDATE users SET password_hash=? WHERE id=?').run(newHash,id);
      await sql('DELETE FROM sessions WHERE user_id=?').run(id);
      await sql('DELETE FROM email_tokens WHERE user_id=?').run(id);
      await newSession(req,res,id);return true;
    });
    if(!changed)return failure(res,401,'reauth_required','Sign in again before changing your password.');
    await response(req, res);
  });
  router.post('/delete', needUser, csrf, validate(z.object({
    password: z.string().max(128).optional(),
    confirm: z.literal('DELETE')
  }).strict()), async (req, res) => {
    const u = await sql('SELECT password_hash FROM users WHERE id=?').get(req.authSession.user_id);
    if (u.password_hash ? !(await checkPassword(u.password_hash, req.input.password || '')) : !recent(req)) return failure(res, 401, 'reauth_required', 'Sign in again, or provide the correct current password.');
    await sql('DELETE FROM users WHERE id=?').run(req.authSession.user_id);
    res.clearCookie(cookieName(req), cookieOptions(req));
    audit('account_deleted', req, 200);
    res.json({
      ok: true
    });
  });
  async function providerJson(url, init) {
    const result = await (options.fetch || fetch)(url, {
      ...init,
      redirect: 'error',
      signal: AbortSignal.timeout(10000)
    });
    if (!result.ok) throw new Error('Provider request failed');
    const reader = result.body.getReader();
    let total = 0,
      chunks = [];
    while (true) {
      const {
        done,
        value
      } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 65536) {
        await reader.cancel();
        throw new Error('Provider response too large');
      }
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString());
  }
  let googleKeys;
  async function googleIdentity(code, record) {
    const form = new URLSearchParams({
      code,
      client_id: c.google.id,
      client_secret: c.google.secret,
      redirect_uri: c.base + '/api/auth/google/callback',
      grant_type: 'authorization_code',
      code_verifier: record.verifier
    });
    const result = await providerJson('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: form
    });
    const {
      jwtVerify,
      createRemoteJWKSet
    } = await import('jose');
    googleKeys ||= createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'), {
      timeoutDuration: 8000
    });
    const verified = await jwtVerify(result.id_token, options.googleKeys || googleKeys, {
      algorithms: ['RS256'],
      issuer: ['https://accounts.google.com', 'accounts.google.com'],
      audience: c.google.id,
      requiredClaims: ['exp', 'iat', 'sub', 'nonce', 'email', 'email_verified'],
      maxTokenAge: '10m',
      clockTolerance: 5
    });
    const p = verified.payload;
    if (p.nonce !== record.nonce || p.email_verified !== true || typeof p.sub !== 'string' || p.sub.length > 255 || !p.sub || p.azp && p.azp !== c.google.id || Array.isArray(p.aud) && p.aud.length > 1 && p.azp !== c.google.id) throw new Error('Invalid Google identity');
    return {
      subject: p.sub,
      email: z.email().max(254).parse(p.email),
      verified: true,
      name: typeof p.name === 'string' ? p.name.slice(0, 60) : 'Haq member'
    };
  }
  async function facebookIdentity(code) {
    const api = 'https://graph.facebook.com/' + c.facebook.version;
    const form = new URLSearchParams({
      client_id: c.facebook.id,
      client_secret: c.facebook.secret,
      redirect_uri: c.base + '/api/auth/facebook/callback',
      code
    });
    const result = await providerJson(api + '/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: form
    });
    if (typeof result.access_token !== 'string' || result.access_token.length > 4096) throw new Error('Invalid Facebook token');
    const check = await providerJson(api + '/debug_token?' + new URLSearchParams({
      input_token: result.access_token
    }), {
      headers: {
        Authorization: 'Bearer ' + c.facebook.id + '|' + c.facebook.secret
      }
    });
    const data = check.data;
    if (!data?.is_valid || String(data.app_id) !== c.facebook.id || typeof data.user_id !== 'string' || !data.user_id || data.expires_at * 1000 <= now() || data.data_access_expires_at && data.data_access_expires_at * 1000 <= now()) throw new Error('Invalid Facebook identity');
    const me = await providerJson(api + '/me?' + new URLSearchParams({
      fields: 'id,name,email',
      appsecret_proof: crypto.createHmac('sha256', c.facebook.secret).update(result.access_token).digest('hex')
    }), {
      headers: {
        Authorization: 'Bearer ' + result.access_token
      }
    });
    if (me.id !== data.user_id || me.id.length > 255) throw new Error('Facebook subject mismatch');
    // Email is optional. It is not sufficient proof to merge or reset another account.
    return {
      subject: me.id,
      email: null,
      verified: false,
      name: typeof me.name === 'string' ? me.name.slice(0, 60) : 'Haq member'
    };
  }
  router.post('/oauth/:provider', csrf, validate(z.object({
    intent: z.enum(['login', 'link'])
  }).strict()), async (req, res) => {
    const p = req.params.provider;
    if (!['google', 'facebook'].includes(p) || !providerReady(p)) return failure(res, 503, 'provider_unavailable', 'This provider needs deployment credentials before sign-in can be used.');
    if (req.input.intent === 'link' && (!req.authSession.user_id || !recent(req))) return failure(res, 401, 'reauth_required', 'Sign in again before connecting another login method.');
    if (req.input.intent === 'link') {
      const owner = await sql('SELECT email,email_verified FROM users WHERE id=?').get(req.authSession.user_id);
      if (owner?.email && !owner.email_verified) return failure(res, 403, 'verify_email_first', 'Verify your account email before connecting another sign-in method.');
    }
    const raw = token(),
      nonce = token(),
      verifier = token();
    await sql('DELETE FROM oauth_states WHERE session_hash=?').run(req.authSession.token_hash);
    await sql('INSERT INTO oauth_states VALUES (?,?,?,?,?,?,?,?)').run(digest(raw), req.authSession.token_hash, p, nonce, verifier, req.input.intent, req.input.intent === 'link' ? req.authSession.user_id : null, now() + 600000);
    const url = new URL(p === 'google' ? 'https://accounts.google.com/o/oauth2/v2/auth' : 'https://www.facebook.com/' + c.facebook.version + '/dialog/oauth');
    url.search = new URLSearchParams({
      client_id: c[p].id,
      redirect_uri: c.base + '/api/auth/' + p + '/callback',
      response_type: 'code',
      scope: p === 'google' ? 'openid email profile' : 'public_profile,email',
      state: raw,
      ...(p === 'google' ? {
        nonce,
        code_challenge: digestBase64(verifier),
        code_challenge_method: 'S256',
        prompt: 'select_account'
      } : {})
    }).toString();
    res.json({
      url: url.href
    });
  });
  function digestBase64(v) {
    return crypto.createHash('sha256').update(v).digest('base64url');
  }
  router.get('/:provider/callback', async (req, res) => {
    const p = req.params.provider;
    const query = new URL(req.originalUrl, 'http://local').searchParams;
    const finish = code => res.redirect(303, '/#auth=' + code);
    if (!['google', 'facebook'].includes(p) || !providerReady(p) || !req.authSession) return finish('failed');
    const raw = query.get('state');
    if (!raw || !/^[A-Za-z0-9_-]{43}$/.test(raw)) return finish('failed');
    const record=await sql('DELETE FROM oauth_states WHERE state_hash=? AND session_hash=? AND provider=? AND expires_at>? RETURNING *').get(digest(raw),req.authSession.token_hash,p,now());
    const code = query.get('code');
    if (!record || query.has('error') || !code || code.length > 4096) return finish('failed');
    try {
      const identity = p === 'google' ? await googleIdentity(code, record) : await facebookIdentity(code);
      if (!(await getSession(req))) return finish('failed');
      const result = await transaction(async () => {
        await db.lockIdentity(p,identity.subject);
        const existing = await sql('SELECT user_id FROM identities WHERE provider=? AND subject=?').get(p, identity.subject);
        if (record.intent === 'link') {
          if (req.authSession.user_id !== record.user_id || !recent(req)) return {
            error: 'reauth'
          };
          if (existing && existing.user_id !== record.user_id) return {
            error: 'conflict'
          };
          const own = await sql('SELECT subject FROM identities WHERE provider=? AND user_id=?').get(p, record.user_id);
          if (own && own.subject !== identity.subject) return {
            error: 'conflict'
          };
          const owner = await sql('SELECT email FROM users WHERE id=?').get(record.user_id);
          if (!owner.email && identity.verified && identity.email) {
            const key = emailKey(identity.email),
              taken = await sql('SELECT id FROM users WHERE email_key=?').get(key);
            if (taken && taken.id !== record.user_id) return {
              error: 'account_exists'
            };
            await sql('UPDATE users SET email=?,email_key=?,email_verified=1 WHERE id=?').run(identity.email, key, record.user_id);
          }
          if (!existing) await sql('INSERT INTO identities VALUES (?,?,?)').run(p, identity.subject, record.user_id);
          return {
            id: record.user_id
          };
        }
        if (existing) return {
          id: existing.user_id
        };
        const key = identity.email ? emailKey(identity.email) : null;
        if (key && (await sql('SELECT id FROM users WHERE email_key=?').get(key))) return {
          error: 'account_exists'
        };
        const id = crypto.randomUUID();
        await sql('INSERT INTO users(id,email,email_key,email_verified,name,created_at) VALUES (?,?,?,?,?,?)').run(id, identity.email, key, identity.verified ? 1 : 0, identity.name || 'Haq member', now());
        await sql('INSERT INTO identities VALUES (?,?,?)').run(p, identity.subject, id);
        return {
          id
        };
      });
      if (result.error) return finish(result.error);
      await newSession(req, res, result.id);
      audit('oauth_success', req, 200);
      return finish('complete');
    } catch {
      audit('oauth_failed', req, 401);
      return finish('failed');
    }
  });
  router.use((err, req, res, next) => {
    if (err instanceof z.ZodError) return failure(res, 400, 'invalid_input', 'Check the email address and fields.');
    if (err.busy) return failure(res, 503, 'busy', 'Sign-in is busy. Please try again shortly.');
    if (err.type === 'entity.too.large') return failure(res, 413, 'too_large', 'Request too large.');
    if (err.type === 'entity.parse.failed') return failure(res, 400, 'invalid_json', 'Invalid JSON.');
    audit('auth_error', req, 500);
    failure(res, 500, 'server_error', 'Your request could not be completed. Please try again.');
  });
  return {
    router,
    db: db.raw || db,
    store: db,
    ready: () => db.ready(),
    close: async () => {
      mailer?.close();
      await db.close();
    },
    publicConfig
  };
}
module.exports = {
  readAuthConfig,
  createAuth,
  emailKey,
  openDatabase
};
