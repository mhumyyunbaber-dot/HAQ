'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { loadConfig, createServer } = require('../server.cjs');

async function fixture(t, overrides = {}) {
  const events = [];
  const config = loadConfig({ APP_ENV: 'test', NODE_ENV: 'production', AUTH_ENABLED:'false', RATE_LIMIT_MAX: '1000', ...overrides });
  const server = createServer(config, e => events.push(e));
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const port = server.address().port;
  const request = (target = '/', options = {}) => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: target, method: options.method || 'GET', headers: options.headers || {} }, res => {
      const chunks = []; res.on('data', d => chunks.push(d)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject); if (options.body) req.write(options.body); req.end();
  });
  return { request, events, port };
}

test('only the exact public bundle is served; no directory listing', async t => {
  const { request } = await fixture(t);
  for (const route of ['/', '/index.html', '/style.css', '/app.js', '/data.js']) assert.equal((await request(route)).status, 200);
  for (const route of ['/.env', '/.env.production', '/.git/config', '/README.md', '/server.cjs', '/package.json', '/package-lock.json', '/Haq.html', '/backups/', '/deploy/Caddyfile', '/scripts/scan_secrets.py', '/node_modules/express/package.json']) {
    const r = await request(route); assert.equal(r.status, 404, route); assert.ok(!r.body.includes('/home/user'));
  }
});

test('traversal, encoded paths, SQL-like/query input and absolute targets fail closed', async t => {
  const { request } = await fixture(t);
  for (const route of ['/../.env', '/%2eenv', '/%2e%2e/.env', '/%252e%252e/.env', '//app.js', '/?token=sentinel-sensitive-query', '/?id=1%20OR%201=1', '/app.js?version=1', 'http://attacker.example/app.js', '/bad%00.js']) {
    const r = await request(route); assert.equal(r.status, 400, route); assert.ok(!r.body.includes('sentinel'));
  }
});

test('unknown APIs, admin, legacy auth paths and uploads remain unavailable', async t => {
  const { request } = await fixture(t);
  for (const route of ['/api/admin', '/api/users', '/api/login', '/api/reset-password', '/admin', '/uploads']) {
    assert.equal((await request(route)).status, 404, route);
    assert.equal((await request(route, { method: 'POST' })).status, 405, route);
  }
  for (const method of ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']) assert.equal((await request('/', { method })).status, 405, method);
});

test('body and upload payloads are refused before parsing; no reflection', async t => {
  const { request } = await fixture(t);
  const value = 'sentinel-body-secret';
  const r = await request('/', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(value) }, body: value });
  assert.equal(r.status, 413); assert.ok(!r.body.includes(value));
  assert.equal((await request('/', { method: 'GET', headers: { 'Content-Length': '99' } })).status, 413);
});

test('CSP and other headers lock down execution, network, privacy and MIME', async t => {
  const { request } = await fixture(t);
  const { headers: h } = await request('/');
  const csp = h['content-security-policy'];
  for (const directive of ["default-src 'none'", "script-src 'self'", "script-src-attr 'none'", "style-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]) assert.ok(csp.includes(directive), directive);
  assert.ok(!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'));
  assert.equal(h['x-content-type-options'], 'nosniff');
  assert.equal(h['referrer-policy'], 'no-referrer');
  assert.equal(h['cache-control'], 'no-store');
  assert.equal(h['cross-origin-resource-policy'], 'same-origin');
  assert.ok(h['permissions-policy'].includes('camera=()'));
  assert.ok(!h['x-powered-by'] && !h.server && !h['set-cookie']);
  assert.equal((await request('/', { method: 'HEAD' })).body, '');
  assert.match((await request('/app.js')).headers['content-type'], /javascript/);
  assert.ok((await request('/.env')).headers['content-security-policy']);
});

test('arbitrary hosts/origins rejected; same-origin accepted; CORS not enabled', async t => {
  const { request, port } = await fixture(t);
  assert.equal((await request('/', { headers: { Host: 'attacker.example' } })).status, 421);
  for (const origin of ['null', 'https://attacker.example', 'https://127.0.0.1.attacker.example', 'http://localhost.attacker.example']) {
    const r = await request('/', { headers: { Origin: origin } }); assert.equal(r.status, 403); assert.ok(!r.headers['access-control-allow-origin']);
  }
  assert.equal((await request('/', { headers: { Origin: `http://127.0.0.1:${port}` } })).status, 200);
  assert.equal((await request('/app.js', { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'no-cors' } })).status, 403);
  // Navigations from Arena must remain possible; they are not CORS API access.
  assert.equal((await request('/', { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate' } })).status, 200);
  assert.equal((await request('/', { headers: { Host: '3000-example.e2b.app' } })).status, 200);
});

test('per-client rate limits cannot be bypassed by untrusted forwarding headers', async t => {
  const { request, events } = await fixture(t, { RATE_LIMIT_MAX: '3' });
  for (let i = 0; i < 3; i++) assert.equal((await request('/', { headers: { 'X-Forwarded-For': `203.0.113.${i}` } })).status, 200);
  const r = await request('/', { headers: { 'X-Forwarded-For': '198.51.100.99' } });
  assert.equal(r.status, 429); assert.ok(r.headers['retry-after']); assert.ok(events.some(e => e.event === 'rate_limit'));
});

test('production rejects unsafe configuration and enforces HTTPS through a trusted terminator', async t => {
  for (const env of [
    { APP_ENV: 'production' },
    { APP_ENV: 'production', NODE_ENV: 'production', ALLOWED_ORIGINS: 'http://haq.example' },
    { APP_ENV: 'production', NODE_ENV: 'production', ALLOWED_ORIGINS: 'https://haq.example', HOST: '0.0.0.0' },
    { APP_ENV: 'production', NODE_ENV: 'production', ALLOWED_ORIGINS: 'https://haq.example', DEBUG: '*' },
    { TRUSTED_PROXIES: 'true' }, { RATE_LIMIT_MAX: 'not-a-number' },
  ]) assert.throws(() => loadConfig(env));
  const { request } = await fixture(t, { APP_ENV: 'production', ALLOWED_ORIGINS: 'https://haq.example', TRUSTED_PROXIES: '127.0.0.1,::1' });
  assert.equal((await request('/', { headers: { Host: 'haq.example' } })).status, 426);
  const r = await request('/', { headers: { Host: 'haq.example', 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.8', Origin: 'https://haq.example' } });
  assert.equal(r.status, 200); assert.match(r.headers['strict-transport-security'], /max-age=31536000/);
  assert.equal(r.headers['x-frame-options'], 'DENY'); assert.ok(r.headers['content-security-policy'].includes("frame-ancestors 'none'"));
  assert.equal((await request('/', { headers: { Host: '3000-example.e2b.app', 'X-Forwarded-Proto': 'https' } })).status, 421);
  const untrusted = await fixture(t, { APP_ENV: 'production', ALLOWED_ORIGINS: 'https://haq.example' });
  assert.equal((await untrusted.request('/', { headers: { Host: 'haq.example', 'X-Forwarded-Proto': 'https' } })).status, 426);
});

test('security logs omit addresses, query strings, credentials, cookies and request bodies', async t => {
  const { request, events } = await fixture(t);
  await request('/.env?token=sentinel-query', { headers: { Cookie: 'secret=sentinel-cookie', Authorization: 'Bearer sentinel-token' } });
  await request('/.env');
  const records = JSON.stringify(events);
  for (const v of ['sentinel', '127.0.0.1', 'Bearer', 'Cookie', '/home/', '.env']) assert.ok(!records.includes(v));
  assert.ok(events.length >= 2); assert.match(events[0].client, /^[a-f0-9]{20}$/); assert.equal(events[0].status, 400);
});

test('oversized headers fail at the HTTP parser', async t => {
  const { request } = await fixture(t);
  const r = await request('/', { headers: { 'X-Too-Large': 'x'.repeat(10000) } });
  assert.equal(r.status, 431);
});
