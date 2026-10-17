'use strict';
// Intended for the real Docker Compose CI job. No credentials printed or persisted.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
(async()=>{const url=process.env.HAQ_URL||'http://127.0.0.1:3000';let cookie='',csrf;
 async function auth(route,body){const r=await fetch(url+'/api/auth/'+route,{method:body===undefined?'GET':'POST',headers:{...(cookie?{cookie}:{}),...(body===undefined?{}:{'content-type':'application/json','x-csrf-token':csrf||''})},body:body===undefined?undefined:JSON.stringify(body)});const json=await r.json();const c=r.headers.getSetCookie();if(c.length)cookie=c[0].split(';')[0];if('csrf'in json)csrf=json.csrf;return {status:r.status,json};}
 const health=await fetch(url+'/healthz');assert.equal(health.status,200);assert.deepEqual((await health.json()).services,{web:true,identity:true,legal:true});
 const catalog=await (await fetch(url+'/api/legal/catalog')).json();assert.equal(catalog.processing,'browser-only');assert.equal(catalog.catalog.topics.length,6);assert.equal((await fetch(url+'/.env')).status,404);
 const html=await fetch(url+'/');assert.equal(html.status,200);assert.match(html.headers.get('content-security-policy'),/connect-src 'self'/);
 await auth('bootstrap');const email='compose-'+crypto.randomBytes(8).toString('hex')+'@example.invalid',password=crypto.randomBytes(24).toString('base64url');
 const signup=await auth('register',{name:'Compose fixture',email,password});assert.equal(signup.status,201);try{assert.equal((await auth('session')).json.user.id,signup.json.user.id);await auth('logout',{});await auth('bootstrap');assert.equal((await auth('login',{email,password})).status,200);}finally{const deleted=await auth('delete',{password,confirm:'DELETE'});assert.equal(deleted.status,200);}
 console.log('PASS: real service endpoints, PostgreSQL-backed signup/login/session/delete, public reference catalog and gateway hardening.');
})().catch(()=>{console.error('Compose smoke test failed. Check service readiness and preview-only fixture registration. No credentials logged.');process.exitCode=1;});
