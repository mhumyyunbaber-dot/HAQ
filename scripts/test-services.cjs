'use strict';
const {spawn}=require('node:child_process'),crypto=require('node:crypto');require('dotenv').config({quiet:true});
let adminUrl=process.env.HAQ_TEST_ADMIN_URL||process.env.DATABASE_ADMIN_URL;
if(!adminUrl&&process.env.PGHOST){const u=new URL('postgresql://localhost');u.hostname=process.env.PGHOST;u.port=process.env.PGPORT||'5432';u.username=process.env.PGUSER||'postgres';u.password=process.env.PGPASSWORD||'';u.pathname='/'+(process.env.PGDATABASE||'postgres');adminUrl=u.href;}
if(!adminUrl){console.error('Real PostgreSQL tests require HAQ_TEST_ADMIN_URL, a private DATABASE_ADMIN_URL, or PGHOST/PGUSER/PGPASSWORD/PGDATABASE. No silent database mock or skip.');process.exitCode=1;}
else{
 const env={...process.env,HAQ_TEST_ADMIN_URL:adminUrl,HAQ_TEST_IDENTITY_PASSWORD:process.env.HAQ_TEST_IDENTITY_PASSWORD||process.env.IDENTITY_DB_PASSWORD||crypto.randomBytes(32).toString('base64url')};
 const args=process.argv.includes('--browser')?['scripts/browser-check.cjs']:['--test','--test-concurrency=1','tests/auth.test.cjs','tests/postgres-services.test.cjs'];
 const c=spawn(process.execPath,args,{env,stdio:'inherit'});c.on('error',()=>{process.exitCode=1;});c.on('exit',code=>{process.exitCode=code??1;});
}
