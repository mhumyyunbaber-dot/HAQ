'use strict';

const {
  test
} = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {
  once
} = require('node:events');
const crypto = require('node:crypto');
const {
  createServer,
  loadConfig
} = require('../server.cjs');
const {
  emailKey
} = require('../auth.cjs');
const password = 'A very unique test passphrase 2026!';
async function fixture(t, env = {}, options = {}) {
  const mails = [];
  let server, auth;
  if (process.env.HAQ_TEST_ADMIN_URL) {
    const stack = await require('./helpers/stack.cjs').stack(env, {
      sendMail: async m => {
        mails.push(m);
      },
      ...options
    });
    server = stack.server;
    auth = stack.auth;
    t.after(() => stack.close());
  } else {
    server = createServer(loadConfig({
      APP_ENV: 'test',
      NODE_ENV: 'production',
      RATE_LIMIT_MAX: '10000',
      ...env
    }), () => {}, {
      sendMail: async m => {
        mails.push(m);
      },
      ...options
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    auth = server.app.locals.auth;
    t.after(() => new Promise(r => {
      server.closeAllConnections();
      server.close(r);
    }));
  }
  const port = server.address().port;
  function client() {
    let cookie = '',
      csrf = null;
    return {
      get csrf() {
        return csrf;
      },
      get cookie() {
        return cookie;
      },
      set cookie(v) {
        cookie = v;
      },
      request(target, body, extra = {}, method) {
        return new Promise((resolve, reject) => {
          const raw = body === undefined ? null : JSON.stringify(body);
          const req = http.request({
            hostname: '127.0.0.1',
            port,
            path: '/api/auth/' + target,
            method: method || (raw ? 'POST' : 'GET'),
            headers: {
              ...(cookie ? {
                Cookie: cookie
              } : {}),
              ...(raw ? {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(raw),
                'X-CSRF-Token': csrf || ''
              } : {}),
              ...extra
            }
          }, res => {
            let data = '';
            res.on('data', d => data += d);
            res.on('end', () => {
              if (res.headers['set-cookie']) cookie = res.headers['set-cookie'][0].split(';')[0];
              let json;
              try {
                json = JSON.parse(data);
              } catch {}
              if (json && 'csrf' in json) csrf = json.csrf;
              resolve({
                status: res.statusCode,
                headers: res.headers,
                json,
                body: data
              });
            });
          });
          req.on('error', reject);
          if (raw) req.write(raw);
          req.end();
        });
      }
    };
  }
  return {
    server,
    client,
    db: auth.db,
    mails
  };
}
async function register(c, email = 'person@example.com', more = {}) {
  await c.request('bootstrap');
  return c.request('register', {
    email,
    password,
    name: 'Ayesha',
    ageRange: null,
    gender: null,
    ...more
  });
}
test('public status has no cookie; guest bootstrap has HttpOnly Lax cookie and CSRF', async t => {
  const f = await fixture(t),
    c = f.client();
  const a = await c.request('session');
  assert.equal(a.json.user, null);
  assert.ok(!a.headers['set-cookie']);
  const b = await c.request('bootstrap');
  assert.equal(b.status, 200);
  assert.match(b.headers['set-cookie'][0], /HttpOnly/);
  assert.match(b.headers['set-cookie'][0], /SameSite=Lax/);
  assert.equal(c.csrf.length, 43);
});
test('registration stores Argon2id, rotates the guest session, and never returns password hashes', async t => {
  const f = await fixture(t),
    c = f.client();
  await c.request('bootstrap');
  const guest = c.cookie;
  const r = await c.request('register', {
    email: 'one@example.com',
    password,
    name: 'Member',
    gender: 'woman',
    ageRange: '25-34'
  });
  assert.equal(r.status, 201);
  assert.notEqual(c.cookie, guest);
  assert.equal(r.json.user.gender, 'woman');
  assert.equal(r.json.user.role, 'user');
  assert.equal(r.json.user.emailVerified, false);
  const row = await f.db.prepare('SELECT * FROM users').get();
  assert.match(row.password_hash, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
  assert.ok(!r.body.includes('argon2'));
  assert.notEqual(row.password_hash, password);
  assert.equal(f.mails.length, 1);
  assert.ok(!r.body.includes(f.mails[0].text.match(/#verify=(\S+)/)[1]));
});
test('Gmail aliases normalize to one account; Google identity uniqueness is database-enforced', async t => {
  assert.equal(emailKey('First.Last+tag@GoogleMail.com'), 'firstlast@gmail.com');
  const f = await fixture(t),
    a = f.client(),
    b = f.client();
  assert.equal((await register(a, 'first.last@gmail.com')).status, 201);
  assert.equal((await register(b, 'firstlast+another@googlemail.com')).status, 409);
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 1);
});
test('login, multiple devices, current-session logout and all-device revocation', async t => {
  const f = await fixture(t),
    a = f.client(),
    b = f.client();
  const first = await register(a);
  await b.request('bootstrap');
  const login = await b.request('login', {
    email: 'person@example.com',
    password
  });
  assert.equal(login.status, 200);
  assert.equal(login.json.user.id, first.json.user.id);
  assert.equal((await a.request('session')).json.user.id, first.json.user.id);
  await b.request('logout', {
    all: false
  });
  assert.equal((await b.request('session')).json.user, null);
  assert.ok((await a.request('session')).json.user);
  await b.request('bootstrap');
  await b.request('login', {
    email: 'person@example.com',
    password
  });
  await a.request('logout', {
    all: true
  });
  assert.equal((await b.request('session')).json.user, null);
});
test('profile authorization, strict schema, CSRF, and no object/role override', async t => {
  const f = await fixture(t),
    a = f.client(),
    b = f.client();
  await register(a);
  await b.request('bootstrap');
  assert.equal((await b.request('profile', {
    name: 'X'
  }, {}, 'PATCH')).status, 401);
  assert.equal((await a.request('profile', {
    name: 'X'
  }, {
    'X-CSRF-Token': 'bad'
  }, 'PATCH')).status, 403);
  assert.equal((await a.request('profile', {
    name: 'X',
    role: 'admin'
  }, {}, 'PATCH')).status, 400);
  assert.equal((await a.request('profile', {
    name: 'X',
    userId: 'other'
  }, {}, 'PATCH')).status, 400);
  assert.equal((await a.request('profile', {
    name: '<img onerror=alert(1)>',
    gender: 'man',
    ageRange: '18-24'
  }, {}, 'PATCH')).status, 200);
  assert.equal((await a.request('profile', {
    name: 'X',
    gender: 'invented'
  }, {}, 'PATCH')).status, 400);
});
test('incorrect login uses generic errors and SQL-like email cannot query accounts', async t => {
  const f = await fixture(t),
    c = f.client();
  await register(c);
  await c.request('logout', {});
  await c.request('bootstrap');
  const wrong = await c.request('login', {
    email: 'person@example.com',
    password: 'incorrect'
  });
  const missing = await c.request('login', {
    email: 'absent@example.com',
    password: 'incorrect'
  });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.json.error, missing.json.error);
  assert.equal((await c.request('login', {
    email: "' OR 1=1 --",
    password
  })).status, 400);
});
test('verification is explicit, single-use and does not sign anyone in automatically', async t => {
  const f = await fixture(t),
    c = f.client();
  await register(c);
  const tok = f.mails[0].text.match(/#verify=(\S+)/)[1];
  assert.equal((await c.request('verify', {
    token: tok
  })).status, 200);
  assert.equal((await c.request('verify', {
    token: tok
  })).status, 400);
  assert.equal((await c.request('session')).json.user.emailVerified, true);
});
test('password recovery never returns tokens, consumes once and revokes every user session', async t => {
  const f = await fixture(t),
    a = f.client(),
    b = f.client();
  await register(a);
  await b.request('bootstrap');
  const q = await b.request('forgot', {
      email: 'person@example.com'
    }),
    n = await b.request('forgot', {
      email: 'absent@example.com'
    });
  assert.deepEqual(q.json, n.json);
  const tok = f.mails.find(m => m.subject.includes('Reset')).text.match(/#reset=(\S+)/)[1];
  assert.ok(!q.body.includes(tok));
  const nextPassword = 'Another very unique passphrase!';
  assert.equal((await b.request('reset', {
    token: tok,
    password: nextPassword
  })).status, 200);
  assert.equal((await a.request('session')).json.user, null);
  await b.request('bootstrap');
  assert.equal((await b.request('reset', {
    token: tok,
    password: nextPassword
  })).status, 400);
  assert.equal((await b.request('login', {
    email: 'person@example.com',
    password
  })).status, 401);
  assert.equal((await b.request('login', {
    email: 'person@example.com',
    password: nextPassword
  })).status, 200);
});
test('expired session and expired email tokens are rejected', async t => {
  const f = await fixture(t),
    c = f.client();
  await register(c);
  const tok = f.mails[0].text.match(/#verify=(\S+)/)[1];
  await f.db.prepare('UPDATE email_tokens SET expires_at=0').run();
  assert.equal((await c.request('verify', {
    token: tok
  })).status, 400);
  await f.db.prepare('UPDATE sessions SET expires_at=0').run();
  assert.equal((await c.request('session')).json.user, null);
});
test('unconfigured social login fails closed; account deletion requires password', async t => {
  const f = await fixture(t),
    c = f.client();
  await register(c);
  assert.equal((await c.request('oauth/google', {
    intent: 'login'
  })).status, 503);
  assert.equal((await c.request('delete', {
    confirm: 'DELETE',
    password: 'wrong'
  })).status, 401);
  assert.equal((await c.request('delete', {
    confirm: 'DELETE',
    password
  })).status, 200);
  assert.equal((await f.db.prepare('SELECT count(*) AS n FROM users').get()).n, 0);
  assert.equal((await c.request('session')).json.user, null);
});
async function googleFixture(t, overrides = {}) {
  const {
    generateKeyPair,
    SignJWT
  } = await import('jose');
  const keys = await generateKeyPair('RS256');
  let nonce = '',
    subject = 'google-person',
    email = 'verified@gmail.com',
    claims = {},
    policy = {};
  const f = await fixture(t, {
    AUTH_BASE_URL: 'http://localhost',
    GOOGLE_CLIENT_ID: 'test-client',
    GOOGLE_CLIENT_SECRET: 'test-secret'
  }, {
    googleKeys: keys.publicKey,
    fetch: async (url, init) => {
      assert.equal(url, 'https://oauth2.googleapis.com/token');
      assert.ok(init.body.get('code_verifier'));
      const jwt = await new SignJWT({
        nonce,
        email,
        email_verified: true,
        name: 'Google member',
        ...claims
      }).setProtectedHeader({
        alg: 'RS256'
      }).setIssuer(policy.issuer || 'https://accounts.google.com').setAudience(policy.audience || 'test-client').setSubject(subject).setIssuedAt().setExpirationTime(policy.expiry || '5m').sign(keys.privateKey);
      return new Response(JSON.stringify({
        id_token: jwt
      }), {
        status: 200
      });
    },
    ...overrides
  });
  async function start(c, intent = 'login') {
    const r = await c.request('oauth/google', {
      intent
    });
    assert.equal(r.status, 200);
    const url = new URL(r.json.url);
    nonce = url.searchParams.get('nonce');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    return url.searchParams.get('state');
  }
  return {
    ...f,
    start,
    set: options => {
      if (options.subject) subject = options.subject;
      if (options.email) email = options.email;
      if (options.claims) claims = options.claims;
      policy = options.policy || {};
    }
  };
}
test('Google validates OIDC + PKCE and the same subject always returns the same user across devices', async t => {
  const f = await googleFixture(t),
    a = f.client(),
    b = f.client();
  await a.request('bootstrap');
  let state = await f.start(a);
  let done = await a.request('google/callback?' + new URLSearchParams({
    state,
    code: 'test-code'
  }));
  assert.equal(done.headers.location, '/#auth=complete');
  const first = (await a.request('session')).json.user;
  assert.equal(first.emailVerified, true);
  await b.request('bootstrap');
  state = await f.start(b);
  done = await b.request('google/callback?' + new URLSearchParams({
    state,
    code: 'another-code'
  }));
  assert.equal(done.headers.location, '/#auth=complete');
  assert.equal((await b.request('session')).json.user.id, first.id);
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 1);
  assert.equal((await a.request('session')).json.user.id, first.id);
});
test('OAuth state is browser-bound and single-use; mismatched OIDC nonce fails', async t => {
  const f = await googleFixture(t),
    a = f.client(),
    b = f.client();
  await a.request('bootstrap');
  await b.request('bootstrap');
  const state = await f.start(a);
  assert.equal((await b.request('google/callback?' + new URLSearchParams({
    state,
    code: 'code'
  }))).headers.location, '/#auth=failed');
  f.set({
    claims: {
      nonce: 'wrong'
    }
  });
  assert.equal((await a.request('google/callback?' + new URLSearchParams({
    state,
    code: 'code'
  }))).headers.location, '/#auth=failed');
  f.set({
    claims: {}
  });
  assert.equal((await a.request('google/callback?' + new URLSearchParams({
    state,
    code: 'code'
  }))).headers.location, '/#auth=failed');
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 0);
});
test('matching email never auto-merges; verified existing account can explicitly link Google', async t => {
  const f = await googleFixture(t),
    a = f.client(),
    b = f.client();
  await register(a, 'verified@gmail.com');
  await b.request('bootstrap');
  let state = await f.start(b);
  assert.equal((await b.request('google/callback?' + new URLSearchParams({
    state,
    code: 'code'
  }))).headers.location, '/#auth=account_exists');
  assert.equal((await a.request('oauth/google', {
    intent: 'link'
  })).status, 403, 'Unverified native users cannot plant a social identity before email recovery');
  const tok = f.mails[0].text.match(/#verify=(\S+)/)[1];
  await a.request('verify', {
    token: tok
  });
  state = await f.start(a, 'link');
  assert.equal((await a.request('google/callback?' + new URLSearchParams({
    state,
    code: 'code'
  }))).headers.location, '/#auth=complete');
  assert.deepEqual((await a.request('session')).json.user.providers, ['google']);
});
test('Facebook validates app, expiry and subject and permits a missing email without inventing one', async t => {
  const f = await fixture(t, {
      AUTH_BASE_URL: 'http://localhost',
      FACEBOOK_APP_ID: 'test-fb',
      FACEBOOK_APP_SECRET: 'test-secret',
      FACEBOOK_GRAPH_VERSION: 'v99.0'
    }, {
      fetch: async url => {
        let data;
        if (url.endsWith('/oauth/access_token')) data = {
          access_token: 'test-token'
        };else if (url.includes('/debug_token?')) data = {
          data: {
            is_valid: true,
            app_id: 'test-fb',
            user_id: 'fb-person',
            expires_at: Math.floor(Date.now() / 1000) + 300
          }
        };else if (url.includes('/me?')) data = {
          id: 'fb-person',
          name: 'Facebook member'
        };else throw new Error('Unexpected provider URL');
        return new Response(JSON.stringify(data), {
          status: 200
        });
      }
    }),
    c = f.client();
  await c.request('bootstrap');
  const start = await c.request('oauth/facebook', {
    intent: 'login'
  });
  assert.equal(start.status, 200);
  const state = new URL(start.json.url).searchParams.get('state');
  assert.equal((await c.request('facebook/callback?' + new URLSearchParams({
    state,
    code: 'code'
  }))).headers.location, '/#auth=complete');
  const u = (await c.request('session')).json.user;
  assert.equal(u.email, null);
  assert.deepEqual(u.providers, ['facebook']);
});
test('Google rejects wrong issuer, wrong audience, expired ID tokens and unverified email', async t => {
  const f = await googleFixture(t),
    c = f.client();
  await c.request('bootstrap');
  for (const setting of [{
    policy: {
      issuer: 'https://attacker.invalid'
    }
  }, {
    policy: {
      audience: 'wrong-client'
    }
  }, {
    policy: {
      expiry: '-10m'
    }
  }, {
    claims: {
      email_verified: false
    }
  }]) {
    f.set({
      claims: {},
      ...setting
    });
    const state = await f.start(c);
    assert.equal((await c.request('google/callback?' + new URLSearchParams({
      state,
      code: 'code'
    }))).headers.location, '/#auth=failed');
  }
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM users').get()).n, 0);
});
test('Gmail aliases cannot bypass per-account brute-force limits', async t => {
  const f = await fixture(t),
    c = f.client();
  await register(c, 'first.last@gmail.com');
  await c.request('logout', {});
  await c.request('bootstrap');
  for (let i = 0; i < 9; i++) assert.equal((await c.request('login', {
    email: 'firstlast+try' + i + '@gmail.com',
    password: 'incorrect'
  })).status, 401);
  assert.equal((await c.request('login', {
    email: 'f.i.r.s.t.l.a.s.t@gmail.com',
    password: 'incorrect'
  })).status, 429);
});
test('password change requires old password, rotates session and revokes other devices', async t => {
  const f = await fixture(t),
    a = f.client(),
    b = f.client();
  await register(a);
  await b.request('bootstrap');
  await b.request('login', {
    email: 'person@example.com',
    password
  });
  const old = a.cookie;
  assert.equal((await a.request('password', {
    currentPassword: 'wrong',
    password: 'A changed very unique passphrase!'
  })).status, 401);
  assert.equal((await a.request('password', {
    currentPassword: password,
    password: 'A changed very unique passphrase!'
  })).status, 200);
  assert.notEqual(a.cookie, old);
  assert.equal((await b.request('session')).json.user, null);
  assert.equal((await a.request('profile', {
    name: 'Nope'
  }, {
    'X-CSRF-Token': 'é'.repeat(43)
  }, 'PATCH')).status, 403);
});
test('missing SMTP disables recovery and no verification tokens leak through responses', async t => {
  const f = await fixture(t, {}, {
      sendMail: null
    }),
    c = f.client();
  const r = await register(c);
  assert.equal(r.json.providers.emailDelivery, false);
  assert.equal(r.json.user.emailVerified, false);
  assert.equal((await c.request('forgot', {
    email: 'person@example.com'
  })).status, 503);
  assert.equal((await f.db.prepare('SELECT COUNT(*) AS n FROM email_tokens').get()).n, 0);
});
