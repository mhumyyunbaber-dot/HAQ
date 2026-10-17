'use strict';
// Hardened legal navigator with isolated, schema-validated authentication routes.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const net = require('node:net');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const dotenv = require('dotenv');

const ROOT = path.resolve(__dirname, '../..');
const FILES = Object.freeze({
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/data.js': ['data.js', 'application/javascript; charset=utf-8'],
  '/app.js': ['app.js', 'application/javascript; charset=utf-8'],
  '/auth-ui.js': ['auth-ui.js', 'application/javascript; charset=utf-8'],
});
const PREVIEW_HOST = /^3000-[a-z0-9-]+\.e2b\.app$/i;
function positiveInt(value, fallback, min, max) {
  const n = Number(value ?? fallback);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error('Invalid numeric server configuration');
  return n;
}
function csv(value) { return (value || '').split(',').map(s => s.trim()).filter(Boolean); }
function loadConfig(env = process.env) {
  const mode = env.APP_ENV || 'preview';
  if (!['preview', 'production', 'test'].includes(mode)) throw new Error('Invalid APP_ENV');
  // Fail closed if an operator accidentally starts production with debug options.
  if (env.DEBUG || (mode === 'production' && env.NODE_ENV !== 'production')) {
    throw new Error('Debug must be disabled and production requires NODE_ENV=production');
  }
  const origins = csv(env.ALLOWED_ORIGINS).map(value => {
    const u = new URL(value);
    if (u.origin !== value || u.username || u.password ||
        !['https:', 'http:'].includes(u.protocol) ||
        (mode === 'production' && u.protocol !== 'https:')) throw new Error('Invalid ALLOWED_ORIGINS');
    return u.origin;
  });
  if (mode === 'production' && !origins.length) throw new Error('Production requires explicit HTTPS origins');
  const trustedProxies = csv(env.TRUSTED_PROXIES);
  if (trustedProxies.some(ip => !net.isIP(ip))) throw new Error('Use exact trusted proxy IP addresses');
  if (mode === 'production' && env.HOST && !['127.0.0.1', '::1'].includes(env.HOST)) throw new Error('Production backend must bind to loopback');
  const logKey = env.SECURITY_LOG_KEY || crypto.randomBytes(32).toString('hex');
  if (env.SECURITY_LOG_KEY && env.SECURITY_LOG_KEY.length < 32) throw new Error('SECURITY_LOG_KEY is too short');
  return {
    mode, origins, trustedProxies, logKey, auth:{enabled:env.AUTH_ENABLED!=='false'},
    host: env.HOST || (mode === 'production' ? '127.0.0.1' : '0.0.0.0'),
    port: positiveInt(env.PORT, 3000, 1, 65535),
    rateWindowMs: positiveInt(env.RATE_WINDOW_MS, 60000, 1000, 3600000),
    rateMax: positiveInt(env.RATE_LIMIT_MAX, 240, 1, 10000),
    // Preview must be embeddable by Arena. Public production denies all framing.
    frameAncestors: mode === 'production' ? ["'none'"] : [
      "'self'", 'https://arena.ai', 'https://*.arena.ai',
      'https://lmarena.ai', 'https://*.lmarena.ai', 'https://*.e2b.app',
    ],
  };
}
function createApp(config, output = record => process.stdout.write(JSON.stringify(record) + '\n'), authOptions = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  app.set('env', 'production'); // Never use Express's development error responses.
  app.set('query parser', false);
  app.set('trust proxy', config.trustedProxies.length ? config.trustedProxies : false);
  const allowedHosts = new Set(config.origins.map(v => new URL(v).host.toLowerCase()));
  const publicFiles = new Map();
  for (const [route, [name, contentType]] of Object.entries(authOptions.gatewayHandler?{}:FILES)) {
    const location = path.join(ROOT, name);
    if (fs.lstatSync(location).isSymbolicLink() || fs.realpathSync(location) !== location) {
      throw new Error('Public assets must be regular files, not symbolic links');
    }
    const stat = fs.statSync(location);
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw new Error('Invalid public asset');
    // Snapshot the small, explicit public bundle at startup; no request path hits disk.
    publicFiles.set(route, { body: fs.readFileSync(location), contentType });
  }
  const audit = (event, req, status) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    output({ time: new Date().toISOString(), event, status,
      requestId: req.securityId,
      client: crypto.createHmac('sha256', config.logKey).update(ip).digest('hex').slice(0, 20) });
  };
  app.use((req, res, next) => {
    req.securityId = crypto.randomUUID();
    res.setHeader('X-Request-ID', req.securityId);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    next();
  });
  app.use(helmet({
    contentSecurityPolicy: { useDefaults: false, directives: {
      defaultSrc: ["'none'"], scriptSrc: ["'self'"], scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'"], styleSrcAttr: ["'none'"],
      imgSrc: ["'self'", 'data:'], fontSrc: ["'self'"],
      connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'none'"],
      formAction: ["'none'"], frameSrc: ["'none'"], workerSrc: ["'none'"],
      frameAncestors: config.frameAncestors,
      ...(config.mode === 'production' ? { upgradeInsecureRequests: [] } : {}),
    } },
    // Arena preview is intentionally embeddable. Production enables DENY.
    xFrameOptions: config.mode === 'production' ? { action: 'deny' } : false,
    strictTransportSecurity: config.mode === 'production' ? { maxAge: 31536000 } : false,
    referrerPolicy: { policy: 'no-referrer' },
    // COEP/COOP isolation is unnecessary for this app and breaks hosted previews.
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
  }));
  const reject = (event, req, res, status, message) => {
    audit(event, req, status);
    return res.status(status).type('application/json').send({ error: message, requestId: req.securityId });
  };
  app.use(rateLimit({
    windowMs: config.rateWindowMs, limit: config.rateMax,
    standardHeaders: 'draft-7', legacyHeaders: false,
    // Forwarded addresses are ignored unless exact proxy IPs were explicitly trusted.
    validate: { xForwardedForHeader: false, forwardedHeader: false },
    handler: (req, res) => reject('rate_limit', req, res, 429, 'Too many requests. Try again later.'),
  }));
  app.use((req, res, next) => {
    const host = (req.headers.host || '').toLowerCase();
    const healthHeader=req.headers['x-haq-health-key'];
    const localHealth=req.method==='GET'&&req.originalUrl==='/healthz'&&['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress)&&config.healthKey&&typeof healthHeader==='string'&&/^[a-f0-9]{64}$/.test(healthHeader)&&crypto.timingSafeEqual(Buffer.from(healthHeader),Buffer.from(config.healthKey));
    const validHost = localHealth || (config.mode === 'production'
      ? allowedHosts.has(host)
      : allowedHosts.has(host) || /^(localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/.test(host) || PREVIEW_HOST.test(host));
    if (!validHost) return reject('invalid_host', req, res, 421, 'Request not accepted.');
    if (config.mode === 'production' && !req.secure && !localHealth) return reject('https_required', req, res, 426, 'HTTPS is required.');
    const authPath=req.originalUrl.split('?')[0];
    const authMethods={
      '/api/auth/session':'GET','/api/auth/bootstrap':'GET','/api/auth/register':'POST',
      '/api/auth/login':'POST','/api/auth/profile':'PATCH','/api/auth/logout':'POST',
      '/api/auth/forgot':'POST','/api/auth/reset':'POST','/api/auth/verify':'POST',
      '/api/auth/resend':'POST','/api/auth/password':'POST','/api/auth/delete':'POST',
      '/api/auth/oauth/google':'POST','/api/auth/oauth/facebook':'POST',
      '/api/auth/google/callback':'GET','/api/auth/facebook/callback':'GET'
    };
    const authAllowed=config.auth.enabled&&authMethods[authPath]===req.method;
    req.isAuthRoute=authAllowed;
    if (!authAllowed && (req.headers['transfer-encoding'] || (req.headers['content-length'] && req.headers['content-length']!=='0'))) {
      res.setHeader('Connection','close');
      return reject('request_body_rejected',req,res,413,'Request bodies are not accepted.');
    }
    if ((!authAllowed&&!['GET','HEAD'].includes(req.method)) || (authMethods[authPath]&& !authAllowed)) {
      res.setHeader('Allow',authMethods[authPath]||'GET, HEAD');
      return reject('method_rejected',req,res,405,'Method not allowed.');
    }
    // Auth uses same-origin APIs only. Never emit wildcard or credentialed CORS.
    // Same-origin is allowed; arbitrary/null Origin and cross-site subresource requests are denied.
    const origin = req.headers.origin;
    const expected = `${config.mode === 'production' ? 'https' : req.protocol}://${host}`;
    const previewHttps = config.mode !== 'production' && PREVIEW_HOST.test(host) ? `https://${host}` : null;
    if (origin && origin !== expected && origin !== previewHttps) {
      return reject('origin_rejected', req, res, 403, 'Request not accepted.');
    }
    if (['cross-site', 'same-site'].includes(req.headers['sec-fetch-site']) &&
        !['navigate', 'nested-navigate'].includes(req.headers['sec-fetch-mode'])) {
      return reject('cross_site_resource', req, res, 403, 'Request not accepted.');
    }
    // Only OAuth callback routes accept a small, fixed query schema.
    const target=req.originalUrl, parts=target.split('?'), pathname=parts[0];
    const callback=/^\/api\/auth\/(google|facebook)\/callback$/.test(pathname);
    if(target.length>(callback?8192:2048))return reject('invalid_target',req,res,414,'Request target too long.');
    if(!/^\/[A-Za-z0-9._/-]*$/.test(pathname)||pathname.includes('..')||pathname.includes('//')||parts.length>2||(!callback&&parts.length>1))return reject('invalid_target',req,res,400,'Invalid request.');
    if(callback){
      const q=new URLSearchParams(parts[1]||'');const keys=[...q.keys()];
      if(keys.length>6||new Set(keys).size!==keys.length||keys.some(k=>!['code','state','error','error_description','error_reason','error_code'].includes(k)))return reject('invalid_target',req,res,400,'Invalid callback.');
    }
    next();
  });
  if(authOptions.gatewayHandler)app.use(authOptions.gatewayHandler);
  if(config.auth.enabled&&authOptions.authFactory){
    const auth=authOptions.authFactory(config,audit,authOptions);app.locals.auth=auth;
    app.use('/api/auth',(req,res,next)=>req.isAuthRoute?auth.router(req,res,next):next());
  }
  app.use((req, res) => {
    const file = publicFiles.get(req.originalUrl);
    if (!file) return reject('not_found', req, res, 404, 'Not found.');
    res.type(file.contentType).send(file.body);
  });
  // No stack traces, filesystem paths, environment values or request values in errors.
  app.use((err, req, res, next) => {
    audit('server_error', req, 500);
    if (res.headersSent) return res.end();
    res.status(500).type('application/json').send({ error: 'Request could not be completed.', requestId: req.securityId });
  });
  return app;
}
function createServer(config, output, authOptions) {
  const app=createApp(config,output,authOptions);
  const server = http.createServer({ maxHeaderSize: 8192 }, app);
  server.app=app;
  server.on('close',()=>app.locals.auth?.close());
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.timeout = 15000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 64;
  server.maxConnections = 256;
  server.maxRequestsPerSocket = 100;
  server.on('clientError', (err, socket) => {
    if (!socket.writable) return;
    const code = err.code === 'HPE_HEADER_OVERFLOW' ? 431 : 400;
    socket.end(`HTTP/1.1 ${code} Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  });
  return server;
}
module.exports = { loadConfig, createApp, createServer };
