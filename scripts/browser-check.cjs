'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const path = require('node:path');
const { chromium } = require('playwright');
const { loadConfig, createServer } = require('../server.cjs');

(async () => {
  let server,cleanup;
  if(process.env.HAQ_TEST_ADMIN_URL){const services=await require('../tests/helpers/stack.cjs').stack();server=services.server;cleanup=()=>services.close();}
  else{server=createServer(loadConfig({ APP_ENV: 'test', NODE_ENV: 'production', RATE_LIMIT_MAX: '1000' }),()=>{});server.listen(0,'127.0.0.1');await once(server,'listening');cleanup=()=>new Promise(r=>{server.closeAllConnections();server.close(r);});}
  const url = 'http://127.0.0.1:' + server.address().port;
  let browser;
  try {
    const child = spawn(process.execPath, [path.resolve(__dirname, '../test.cjs')], {
      env: { ...process.env, HAQ_URL: url }, stdio: 'inherit',
    });
    const [code] = await once(child, 'exit'); assert.equal(code, 0, 'Existing app behaviour must remain intact');
    browser = await chromium.launch();
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(() => {
      window.__violations = [];
      document.addEventListener('securitypolicyviolation', e => window.__violations.push(e.effectiveDirective));
    });
    const legalRequests=[];page.on('request',r=>legalRequests.push({url:r.url(),body:r.postData()}));
    await page.goto(url);
    await page.selectOption('#region', 'Punjab');
    const payload = 'I was arrested. <img src=x onerror="window.__xss=99"> <script>window.__xss=99</script>';
    await page.fill('#situation', payload);
    await page.click('button[type=submit]');
    assert.equal(await page.locator('img').count(), 0, 'Input must not create attacker-controlled markup');
    assert.equal(await page.evaluate(() => window.__xss), undefined);
    assert.equal(await page.locator('#situation').inputValue(), payload, 'Escaping preserves the anonymous description as text');
    await page.click('[data-page="library"]'); await page.click('[data-page="how"]'); await page.click('[data-page="ask"]');
    assert.deepEqual(await page.evaluate(() => window.__violations), [], 'Application itself must satisfy CSP');
    assert.deepEqual(errors, []);
    assert.ok(legalRequests.every(r=>!r.url.includes(encodeURIComponent(payload))&&!r.body?.includes(payload)), 'Legal description must never enter an HTTP request');
    assert.ok(!legalRequests.some(r=>/api\/legal\/(match|ask|query)/.test(r.url)), 'No server-side legal matching endpoint');
    // These are deliberate, controlled attack simulations. CSP must block them.
    await page.evaluate(() => {
      const s = document.createElement('script'); s.textContent = 'window.__injected = true'; document.head.append(s);
      const d = document.createElement('div'); d.setAttribute('style', 'position:fixed'); document.body.append(d);
    });
    await page.waitForFunction(() => window.__violations.length >= 2);
    assert.equal(await page.evaluate(() => window.__injected), undefined);
    assert.ok((await page.evaluate(() => window.__violations)).includes('script-src-elem'));
    await page.evaluate(async () => {
      try { await fetch('https://exfiltration-test.invalid/no-data'); window.__networkAllowed = true; }
      catch { window.__networkAllowed = false; }
    });
    assert.equal(await page.evaluate(() => window.__networkAllowed), false, 'Outbound fetch must be blocked');
    // The standalone artifact also rejects injected scripts but executes its hashed app bundle.
    const offline = await browser.newPage();
    await offline.goto('file://' + path.resolve(__dirname, '../Haq.html'));
    await offline.selectOption('#region', 'Punjab');
    await offline.fill('#situation', 'My landlord is trying to evict me.');
    await offline.click('button[type=submit]');
    assert.match(await offline.locator('#resultArea').innerText(), /Punjab Rented Premises Act/);
    await offline.evaluate(() => { const s = document.createElement('script'); s.textContent = 'window.__badOffline = true'; document.head.append(s); });
    assert.equal(await offline.evaluate(() => window.__badOffline), undefined);
    const account=await browser.newPage({viewport:{width:1440,height:1100}});
    const authErrors=[];account.on('pageerror',e=>authErrors.push(e.message));
    await account.goto(url);await account.click('#accountJoin');
    await account.fill('#auth-name','Ayesha Khan');await account.fill('#auth-email','ui-member@example.invalid');await account.fill('#auth-password','A very unique browser test passphrase!');
    await account.check('[name=consent]');await account.selectOption('#auth-ageRange','25-34');await account.selectOption('#auth-gender','woman');
    await account.click('#accountForm [type=submit]');await account.waitForSelector('.account-identity');
    assert.match(await account.locator('.account-identity').innerText(),/Ayesha Khan/);
    assert.match(await account.locator('.account-verification').innerText(),/not been verified/);
    await account.click('.account-close');await account.reload();await account.waitForSelector('.account-avatar');await account.click('#accountOpen');await account.waitForSelector('#auth-name');
    await account.fill('#auth-name','Ayesha <img onerror=alert(1)>');await account.click('#accountForm [type=submit]');await account.waitForFunction(()=>document.querySelector('#accountMessage')?.textContent.includes('Profile saved'));
    assert.equal(await account.locator('img').count(),0);assert.equal(await account.locator('#auth-gender').inputValue(),'woman');
    await account.locator('#logout').click();await account.waitForSelector('#accountJoin');await account.click('#accountOpen');
    await account.fill('#auth-email','ui-member@example.invalid');await account.fill('#auth-password','A very unique browser test passphrase!');await account.click('#accountForm [type=submit]');await account.waitForSelector('.account-identity');
    await account.setViewportSize({width:390,height:844});assert.ok(await account.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
    await account.screenshot({path:path.resolve(__dirname,'../test-results/account-mobile.png'),fullPage:true});
    await account.setViewportSize({width:1440,height:1100});await account.screenshot({path:path.resolve(__dirname,'../test-results/account-profile.png'),fullPage:true});
    await account.click('#logout');await account.click('#accountOpen');await account.locator('[data-social=google]').click();assert.match(await account.locator('#accountMessage').innerText(),/not configured/);
    await account.screenshot({path:path.resolve(__dirname,'../test-results/account-login.png'),fullPage:true});
    assert.deepEqual(authErrors,[]);
    console.log('PASS: real browser signup, optional profile, persistent cookie login, escaped profile rendering, logout/login, mobile layout and unconfigured social-provider notice.');
    console.log('PASS: browser DOM-XSS simulations, strict CSP compatibility/enforcement, no outbound fetch and standalone hash-CSP.');
  } finally {
    if (browser) await browser.close();
    await cleanup();
  }
})().catch(e => { console.error(e.stack); process.exitCode = 1; });
