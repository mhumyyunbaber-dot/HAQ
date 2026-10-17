'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {Client}=require('pg'),{hash,Algorithm,verify}=require('@node-rs/argon2');
const {stack,database,stop}=require('./helpers/stack.cjs');
const {openDatabase}=require('../auth.cjs'),{importSqlite}=require('../scripts/import-sqlite.cjs'),{makeBackup,restoreBackup}=require('../scripts/postgres-backup.cjs');
const password='A unique integration passphrase!';
const enabled=Boolean(process.env.HAQ_TEST_ADMIN_URL);
const group=(name,fn)=>test(name,{skip:enabled?false:'Run npm run test:services with real PostgreSQL'},fn);
function client(url){let cookie='',csrf;return {async call(route,body,extra={}){const r=await fetch(url+'/api/auth/'+route,{method:body===undefined?'GET':'POST',headers:{...(cookie?{cookie}:{}),...(body===undefined?{}:{'content-type':'application/json','x-csrf-token':csrf||''}),...extra},body:body===undefined?undefined:JSON.stringify(body),redirect:'manual'});const raw=await r.text();let json;try{json=JSON.parse(raw);}catch{}const c=r.headers.getSetCookie();if(c.length)cookie=c[0].split(';')[0];if(json&&'csrf'in json)csrf=json.csrf;return {status:r.status,json,raw,headers:r.headers};},get cookie(){return cookie;},get csrf(){return csrf;}};}
async function member(c,email='integration@example.invalid'){await c.call('bootstrap');return c.call('register',{email,password,name:'Integration member'});}
async function fixture(t,env={},options={},output){const f=await stack(env,options,output);t.after(()=>f.close());return f;}

group('microservices: public routing, distinct private keys, and no accidental source exposure',async t=>{
 const f=await fixture(t);assert.equal((await fetch(f.url+'/healthz')).status,200);
 for(const route of ['/','/app.js','/auth-ui.js','/style.css','/data.js','/api/auth/session','/api/legal/catalog'])assert.equal((await fetch(f.url+route)).status,200,route);
 for(const route of ['/.env','/compose.yaml','/auth.cjs','/services/identity/server.cjs','/private/accounts.sqlite','/packages/storage/index.cjs'])assert.equal((await fetch(f.url+route)).status,404,route);
 for(let i=0;i<3;i++){assert.equal((await fetch(f.urls[i]+'/healthz')).status,403);assert.equal((await fetch(f.urls[i]+'/healthz',{headers:{'x-haq-service-key':f.keys[(i+1)%3]}})).status,403);assert.equal((await fetch(f.urls[i]+'/healthz',{headers:{'x-haq-service-key':f.keys[i]}})).status,200);}
 const cat=await (await fetch(f.url+'/api/legal/catalog')).json();assert.equal(cat.processing,'browser-only');assert.equal(cat.catalog.topics.length,6);assert.ok(cat.catalog.sources.constitution);assert.equal(cat.version.length,64);
 for(const key of f.keys)assert.ok(!JSON.stringify(cat).includes(key));
});

group('PostgreSQL: DML-only runtime, migration history protected, transaction rollback and client isolation',async t=>{
 const f=await fixture(t),s=f.auth.store;
 for(const statement of ['CREATE TABLE auth.forbidden(id int)','CREATE TABLE public.forbidden(id int)','TRUNCATE auth.users','SELECT * FROM auth.schema_migrations','SELECT * FROM auth.account_imports','DROP TABLE auth.users'])await assert.rejects(s.query(statement),e=>e.code==='42501');
 const role=(await s.query('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user')).rows[0];assert.deepEqual(role,{rolsuper:false,rolcreatedb:false,rolcreaterole:false});
 const insert=id=>s.prepare('INSERT INTO users(id,name,created_at) VALUES(?,?,?)').run(id,'Member',Date.now());
 const results=await Promise.allSettled([s.transaction(async()=>{await insert('rolled-back');await new Promise(r=>setTimeout(r,30));throw new Error('intentional');}),s.transaction(async()=>{await insert('committed');await new Promise(r=>setTimeout(r,10));})]);
 assert.deepEqual(results.map(x=>x.status),['rejected','fulfilled']);assert.deepEqual((await s.prepare('SELECT id FROM users ORDER BY id').all()).map(x=>x.id),['committed']);
});

group('gateway: origin/CSRF, strict JSON/body limits, read-only legal API, security headers',async t=>{
 const logs=[],f=await fixture(t,{}, {},e=>logs.push(e)),c=client(f.url);await c.call('bootstrap');
 assert.equal((await c.call('register',{name:'Member',email:'m@example.invalid',password},{origin:'https://attacker.invalid'})).status,403);
 assert.equal((await c.call('register',{name:'Member',email:'m@example.invalid',password},{'x-csrf-token':'wrong'})).status,403);
 assert.equal((await c.call('register',{name:'Member',email:'m@example.invalid',password,role:'admin'})).status,400);
 assert.equal((await fetch(f.url+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:'{"broken"'})).status,400);
 assert.equal((await c.call('register',{name:'x'.repeat(9000),email:'m@example.invalid',password})).status,413);
 const marker='private_case_marker_'+crypto.randomBytes(8).toString('hex');
 assert.equal((await fetch(f.url+'/api/legal/catalog',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({description:marker})})).status,413);
 assert.equal((await fetch(f.url+'/api/legal/match')).status,404);
 assert.equal((await fetch(f.url+'/api/legal/catalog?description='+marker)).status,400);
 const r=await fetch(f.url+'/');assert.match(r.headers.get('content-security-policy'),/connect-src 'self'/);assert.equal(r.headers.get('referrer-policy'),'no-referrer');assert.equal(r.headers.get('x-content-type-options'),'nosniff');assert.equal(r.headers.get('access-control-allow-origin'),null);assert.ok(!JSON.stringify(logs).includes(marker));
});

group('gateway: forged forwarding/service headers cannot bypass IP limits or select an upstream',async t=>{
 const events=[],f=await fixture(t,{RATE_LIMIT_MAX:'4'}, {},e=>events.push(e));
 for(let i=0;i<4;i++)assert.equal((await fetch(f.url+'/api/auth/session',{headers:{'x-forwarded-for':'203.0.113.'+i,'x-haq-service-key':'attacker','x-haq-user-id':'other','x-forwarded-host':'attacker.invalid'}})).status,200);
 assert.equal((await fetch(f.url+'/api/auth/session',{headers:{'x-forwarded-for':'198.51.100.20'}})).status,429);assert.equal(events.filter(x=>x.event==='rate_limit').length,1);assert.ok(!JSON.stringify(events).includes('203.0.113'));
});

group('gateway: cookies stay with identity; forwarded headers are edge-owned; preview cookie remains Secure',async t=>{
 const f=await fixture(t),captured=[];
 for(let i=0;i<3;i++){const server=f.servers[i],listeners=server.listeners('request');server.removeAllListeners('request');server.on('request',(req,res)=>{captured.push({i,url:req.url,headers:{...req.headers}});for(const fn of listeners)fn(req,res);});}
 const forged={cookie:'haq_session_local=private-cookie','x-forwarded-for':'203.0.113.99','x-forwarded-proto':'https','x-haq-service-key':'attacker','x-haq-user-id':'target'};
 for(const route of ['/','/data.js','/api/auth/session'])assert.equal((await fetch(f.url+route,{headers:forged})).status,200);
 assert.equal(captured.find(x=>x.i===0).headers.cookie,undefined);assert.equal(captured.find(x=>x.i===2).headers.cookie,undefined);
 const identity=captured.find(x=>x.i===1);assert.equal(identity.headers.cookie,forged.cookie);assert.equal(identity.headers['x-forwarded-for'],'127.0.0.1');assert.equal(identity.headers['x-forwarded-proto'],'http');assert.equal(identity.headers['x-haq-user-id'],undefined);assert.equal(identity.headers['x-haq-service-key'],f.keys[1]);
 const local=await fetch(f.url+'/api/auth/bootstrap',{headers:forged});assert.match(local.headers.get('set-cookie'),/^haq_session_local=/);
 const preview=await new Promise((resolve,reject)=>{const req=require('node:http').get(f.url+'/api/auth/bootstrap',{headers:{host:'3000-test-preview.e2b.app','x-forwarded-proto':'http'}},res=>{res.resume();res.on('end',()=>resolve(res.headers['set-cookie'][0]));});req.on('error',reject);});assert.match(preview,/^__Host-haq_session=/);assert.match(preview,/Secure/);
});

group('PostgreSQL concurrency: duplicate registrations create exactly one account',async t=>{
 const f=await fixture(t),a=client(f.url),b=client(f.url);await Promise.all([a.call('bootstrap'),b.call('bootstrap')]);
 const payload={email:'same@example.invalid',password,name:'Member'};const results=await Promise.all([a.call('register',payload),b.call('register',payload)]);assert.deepEqual(results.map(x=>x.status).sort(),[201,409]);assert.equal((await f.auth.store.query('SELECT count(*) AS n FROM users')).rows[0].n,1);
});

group('PostgreSQL concurrency: verification/reset tokens consumed once and reset revokes devices',async t=>{
 const mails=[],f=await fixture(t,{}, {sendMail:async m=>mails.push(m)}),a=client(f.url),b=client(f.url);assert.equal((await member(a)).status,201);
 const verification=mails[0].text.match(/#verify=(\S+)/)[1];const vr=await Promise.all([a.call('verify',{token:verification}),a.call('verify',{token:verification})]);assert.deepEqual(vr.map(x=>x.status).sort(),[200,400]);
 await b.call('bootstrap');assert.equal((await b.call('login',{email:'integration@example.invalid',password})).status,200);await a.call('forgot',{email:'integration@example.invalid'});
 const reset=mails.find(x=>x.subject.includes('Reset')).text.match(/#reset=(\S+)/)[1];const rr=await Promise.all([a.call('reset',{token:reset,password:'A changed recovery passphrase!'}),a.call('reset',{token:reset,password:'Another changed passphrase!'})]);assert.deepEqual(rr.map(x=>x.status).sort(),[200,400]);assert.equal((await b.call('session')).json.user,null);assert.equal((await f.auth.store.query('SELECT count(*) AS n FROM sessions WHERE user_id IS NOT NULL')).rows[0].n,0);
});

group('migration: preserve users, Argon2 hashes, profiles and provider subjects; revoke all legacy tokens; never overwrite',async t=>{
 const db=await database();let connection;t.after(async()=>{await connection?.end();await db.close();});const temp=fs.mkdtempSync(path.join(os.tmpdir(),'haq-import-test-'));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));const source=path.join(temp,'legacy.sqlite');const sqlite=openDatabase(source);
 const passwordHash=await hash(password,{algorithm:Algorithm.Argon2id,memoryCost:65536,timeCost:3,parallelism:1});
 sqlite.prepare('INSERT INTO users(id,email,email_key,email_verified,name,password_hash,age_range,gender,created_at) VALUES(?,?,?,?,?,?,?,?,?)').run('native-id','legacy@example.invalid','legacy@example.invalid',1,'Legacy',passwordHash,'25-34','woman',1234567);
 sqlite.prepare('INSERT INTO users(id,name,created_at) VALUES(?,?,?)').run('social-id','Social',1234568);sqlite.prepare('INSERT INTO identities VALUES(?,?,?)').run('google','stable-google-subject','native-id');sqlite.prepare('INSERT INTO identities VALUES(?,?,?)').run('facebook','stable-facebook-subject','social-id');
 sqlite.prepare('INSERT INTO sessions VALUES(?,?,?,?,?,?,?)').run('old-session','native-id','old-csrf',0,0,0,9999999999999);sqlite.prepare('INSERT INTO email_tokens VALUES(?,?,?,?)').run('old-reset','native-id','reset',9999999999999);sqlite.prepare('INSERT INTO oauth_states VALUES(?,?,?,?,?,?,?,?)').run('old-oauth','old-session','google','nonce','verifier','login',null,9999999999999);sqlite.close();
 const before=crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex');const result=await importSqlite(source,db.adminUrl);assert.deepEqual(result,{alreadyImported:false,users:2,identities:2,revokedSessions:1});
 const c=new Client({connectionString:db.adminUrl});await c.connect();connection=c;const row=(await c.query("SELECT * FROM auth.users WHERE id='native-id'")).rows[0];assert.equal(row.password_hash,passwordHash);assert.ok(await verify(row.password_hash,password));assert.equal(row.age_range,'25-34');assert.equal(row.email_verified,1);
 assert.deepEqual((await c.query('SELECT provider,subject FROM auth.identities ORDER BY provider')).rows,[{provider:'facebook',subject:'stable-facebook-subject'},{provider:'google',subject:'stable-google-subject'}]);
 for(const table of ['sessions','email_tokens','oauth_states'])assert.equal(Number((await c.query(`SELECT count(*) AS n FROM auth.${table}`)).rows[0].n),0);
 assert.equal(crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex'),before);assert.equal((await importSqlite(source,db.adminUrl)).alreadyImported,true);
 const changed=openDatabase(source);changed.prepare('UPDATE users SET name=? WHERE id=?').run('Changed','native-id');changed.close();await assert.rejects(importSqlite(source,db.adminUrl));assert.equal((await c.query("SELECT name FROM auth.users WHERE id='native-id'")).rows[0].name,'Legacy');
});

group('PostgreSQL backup: authenticated encryption, wrong-key/tamper rejection, isolated restore and non-destructive recovery',async t=>{
 const f=await fixture(t),c=client(f.url),account=await member(c);assert.equal(account.status,201);await f.auth.store.prepare('INSERT INTO identities VALUES(?,?,?)').run('google','backup-subject',account.json.user.id);
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'haq-pg-backup-test-'));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));const file=path.join(temp,'accounts.haqpg'),key=crypto.randomBytes(32);await makeBackup(f.db.adminUrl,key,file);
 assert.equal(fs.statSync(file).mode&0o777,0o600);assert.ok(!fs.readFileSync(file).includes(Buffer.from('integration@example.invalid')));
 await assert.rejects(restoreBackup(file,crypto.randomBytes(32),f.db.adminUrl));const tampered=path.join(temp,'tampered.haqpg'),bytes=fs.readFileSync(file);bytes[bytes.length-25]^=1;fs.writeFileSync(tampered,bytes);await assert.rejects(restoreBackup(tampered,key,f.db.adminUrl));
 const restored=await restoreBackup(file,key,f.db.adminUrl);assert.equal(restored.users,1);assert.equal(restored.identities,1);assert.equal(restored.isolatedDatabaseDropped,true);assert.ok((await c.call('session')).json.user,'Source live session must remain untouched');
 const name='haq_recovery_'+crypto.randomBytes(8).toString('hex'),maintenance=new URL(f.db.adminUrl);maintenance.pathname='/postgres';const admin=new Client({connectionString:maintenance.href});await admin.connect();t.after(async()=>{await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);await admin.end();});
 assert.equal((await restoreBackup(file,key,f.db.adminUrl,{keep:true,database:name})).database,name);const u=new URL(f.db.adminUrl);u.pathname='/'+name;const recovery=new Client({connectionString:u.href});await recovery.connect();
 try{const row=(await recovery.query('SELECT password_hash FROM auth.users')).rows[0];assert.ok(await verify(row.password_hash,password));assert.equal(Number((await recovery.query('SELECT count(*) AS n FROM auth.sessions')).rows[0].n),0);await assert.rejects(restoreBackup(file,key,f.db.adminUrl,{keep:true,database:name}));assert.equal(Number((await recovery.query('SELECT count(*) AS n FROM auth.users')).rows[0].n),1);}finally{await recovery.end();}
});

group('failure isolation: stopped reference or identity service yields safe 503, other services stay available',async t=>{
 const f=await fixture(t);await stop(f.servers[2]);let health=await fetch(f.url+'/healthz');assert.equal(health.status,503);assert.equal((await health.json()).services.legal,false);
 assert.equal((await fetch(f.url+'/api/auth/session')).status,200);assert.equal((await fetch(f.url+'/')).status,200);const unavailable=await fetch(f.url+'/data.js');assert.equal(unavailable.status,503);assert.ok(!(await unavailable.text()).includes('127.0.0.1'));
 await stop(f.servers[1]);assert.equal((await fetch(f.url+'/api/auth/session')).status,503);assert.equal((await fetch(f.url+'/')).status,200);
});


group('production: authenticated loopback readiness works without weakening public Host/HTTPS checks',async t=>{
 const f=await fixture(t,{APP_ENV:'production',NODE_ENV:'production',ALLOWED_ORIGINS:'https://haq.example.invalid',AUTH_BASE_URL:'https://haq.example.invalid'});
 assert.equal((await fetch(f.url+'/healthz')).status,421);
 assert.equal((await fetch(f.url+'/healthz',{headers:{'x-haq-health-key':f.keys[0]}})).status,421);
 assert.equal((await fetch(f.url+'/healthz',{headers:{'x-haq-health-key':f.config.healthKey}})).status,200);
 assert.equal((await fetch(f.url+'/',{headers:{'x-haq-health-key':f.config.healthKey}})).status,421);
});
