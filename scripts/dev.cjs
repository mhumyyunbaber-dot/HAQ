'use strict';
// Native multi-process preview; PostgreSQL must already be running and migrated.
const {spawn}=require('node:child_process'),path=require('node:path');
require('dotenv').config({quiet:true});process.umask(0o077);
const commonNames=['NODE_ENV','APP_ENV','ALLOWED_ORIGINS','SECURITY_LOG_KEY','DEBUG'];
const authNames=['AUTH_DATABASE_URL','AUTH_BASE_URL','GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET','FACEBOOK_APP_ID','FACEBOOK_APP_SECRET','FACEBOOK_GRAPH_VERSION','SMTP_HOST','SMTP_PORT','SMTP_USER','SMTP_PASS','MAIL_FROM'];
const select=names=>Object.fromEntries(names.filter(x=>process.env[x]!==undefined).map(x=>[x,process.env[x]]));
const base={...select(['PATH','HOME','LANG','TZ']),...select(commonNames)};const children=[];let stopping=false;
function stop(code=0){if(stopping)return;stopping=true;for(const c of children)c.kill('SIGTERM');setTimeout(()=>{for(const c of children)c.kill('SIGKILL');process.exit(code);},5500).unref();Promise.all(children.map(c=>new Promise(r=>c.exitCode!==null?r():c.once('exit',r)))).then(()=>process.exit(code));}
async function ready(url,key){const end=Date.now()+15000;while(Date.now()<end){try{const r=await fetch(url+'/healthz',{headers:{'x-haq-service-key':key},signal:AbortSignal.timeout(1500)});if(r.ok)return;}catch{}await new Promise(r=>setTimeout(r,200));}throw new Error('Service did not become ready');}
function start(name,port,env){const c=spawn(process.execPath,[path.resolve(__dirname,'../services/'+name+'/server.cjs')],{env:{...base,...env,SERVICE_NAME:name,PORT:String(port),SERVICE_HOST:'127.0.0.1'},stdio:'inherit'});children.push(c);c.on('error',()=>stop(1));c.on('exit',()=>{if(!stopping){console.error('A service stopped; shutting down the native stack.');stop(1);}});return c;}
(async()=>{
 if(process.env.APP_ENV==='production')throw new Error('Use hardened Compose deployment for production');
 const keys=['WEB_SERVICE_KEY','IDENTITY_SERVICE_KEY','LEGAL_SERVICE_KEY'].map(x=>process.env[x]);if(keys.some(x=>!x||x.length<43)||new Set(keys).size!==3||!process.env.AUTH_DATABASE_URL)throw new Error('Initialize private PostgreSQL configuration first');
 for(const [name,port,key,extra]of [['web',3101,keys[0],{}],['identity',3102,keys[1],select(authNames)],['legal',3103,keys[2],{}]])start(name,port,{...extra,SERVICE_KEY:key});
 await Promise.all([ready('http://127.0.0.1:3101',keys[0]),ready('http://127.0.0.1:3102',keys[1]),ready('http://127.0.0.1:3103',keys[2])]);
 start('gateway',Number(process.env.PORT||3000),{...select(['WEB_SERVICE_KEY','IDENTITY_SERVICE_KEY','LEGAL_SERVICE_KEY','TRUSTED_PROXIES','RATE_WINDOW_MS','RATE_LIMIT_MAX']),HOST:'0.0.0.0',WEB_URL:'http://127.0.0.1:3101',IDENTITY_URL:'http://127.0.0.1:3102',LEGAL_URL:'http://127.0.0.1:3103'});
})().catch(()=>{console.error('Native stack startup failed. Check configuration, PostgreSQL, schema migrations, and private service ports. No credentials logged.');stop(1);});
for(const s of ['SIGINT','SIGTERM'])process.on(s,()=>stop());
