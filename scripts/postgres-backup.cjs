'use strict';
// pg_dump snapshot -> streaming AES-256-GCM. No raw dump in source archives or logs.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {spawn}=require('node:child_process'),{pipeline}=require('node:stream/promises'),{Client}=require('pg');
const MAGIC=Buffer.from('HAQPG01\n'),HEADER=20,TAG=16;
function decodeKey(value){const key=Buffer.from(value||'','base64');if(key.length!==32||key.toString('base64')!==value)throw new Error('Invalid private backup key');return key;}
function pgEnv(url){const u=new URL(url);if(!['postgres:','postgresql:'].includes(u.protocol))throw new Error('Invalid database URL');return {...process.env,PGHOST:u.hostname,PGPORT:u.port||'5432',PGUSER:decodeURIComponent(u.username),PGPASSWORD:decodeURIComponent(u.password),PGDATABASE:decodeURIComponent(u.pathname.slice(1)),PGSSLMODE:u.searchParams.get('sslmode')||'prefer',PGCONNECT_TIMEOUT:'5'};}
function command(bin,args,url){const child=spawn(bin,args,{env:pgEnv(url),stdio:['ignore','pipe','pipe']});child.stderr.resume();const done=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>code===0?resolve():reject(new Error('PostgreSQL operation failed')));});done.catch(()=>{});return {child,done};}
async function makeBackup(url,key,output){
 if(!Buffer.isBuffer(key)||key.length!==32)throw new Error('Invalid key');output=path.resolve(output);const dir=path.dirname(output);fs.mkdirSync(dir,{recursive:true,mode:0o700});if(fs.realpathSync(dir)!==dir||fs.existsSync(output))throw new Error('Unsafe or existing output');
 const temp=output+'.'+crypto.randomUUID()+'.tmp',nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(MAGIC);fs.writeFileSync(temp,Buffer.concat([MAGIC,nonce]),{mode:0o600,flag:'wx'});
 const {child,done}=command(process.env.PG_DUMP_BIN||'pg_dump',['--format=custom','--no-owner','--no-acl','--schema=auth'],url);
 try{await Promise.all([done,pipeline(child.stdout,cipher,fs.createWriteStream(temp,{flags:'r+',start:HEADER}))]);fs.appendFileSync(temp,cipher.getAuthTag());fs.linkSync(temp,output);return output;}finally{child.kill();fs.rmSync(temp,{force:true});}
}
async function decrypt(file,key,target){
 const size=fs.statSync(file).size;if(size<HEADER+TAG||size>1024*1024*1024)throw new Error('Invalid backup size');
 const fd=fs.openSync(file,'r');const header=Buffer.alloc(HEADER),tag=Buffer.alloc(TAG);try{fs.readSync(fd,header,0,HEADER,0);fs.readSync(fd,tag,0,TAG,size-TAG);}finally{fs.closeSync(fd);}
 if(!header.subarray(0,MAGIC.length).equals(MAGIC))throw new Error('Invalid backup envelope');const decipher=crypto.createDecipheriv('aes-256-gcm',key,header.subarray(MAGIC.length));decipher.setAAD(MAGIC);decipher.setAuthTag(tag);
 await pipeline(fs.createReadStream(file,{start:HEADER,end:size-TAG-1}),decipher,fs.createWriteStream(target,{flags:'wx',mode:0o600}));
}
async function restoreBackup(file,key,adminUrl,{database,keep=false}={}){
 if(keep&&!/^haq_recovery_[a-z0-9]{8,40}$/.test(database||''))throw new Error('Explicit new recovery database required');
 const name=keep?database:'haq_restore_'+crypto.randomBytes(8).toString('hex');const temp=fs.mkdtempSync(path.join(os.tmpdir(),'haq-pg-restore-'));fs.chmodSync(temp,0o700);
 const admin=new Client({connectionString:adminUrl,connectionTimeoutMillis:5000});let connected=false,created=false,target;
 try{
  const dump=path.join(temp,'snapshot.dump');await decrypt(file,key,dump); // Authenticate before touching PostgreSQL.
  await admin.connect();connected=true;await admin.query(`CREATE DATABASE "${name}" OWNER haq_owner TEMPLATE template0`);created=true;
  const u=new URL(adminUrl);u.pathname='/'+name;const url=u.href;
  const {child,done}=command(process.env.PG_RESTORE_BIN||'pg_restore',['--dbname='+name,'--no-owner','--no-acl','--exit-on-error','--role=haq_owner',dump],url);child.stdout.resume();await done;
  target=new Client({connectionString:url,connectionTimeoutMillis:5000});await target.connect();
  for(const table of ['users','identities','sessions','oauth_states','email_tokens','schema_migrations','account_imports'])await target.query(`SELECT 1 FROM auth.${table} LIMIT 0`);
  const users=Number((await target.query('SELECT count(*) AS n FROM auth.users')).rows[0].n),identities=Number((await target.query('SELECT count(*) AS n FROM auth.identities')).rows[0].n);
  await target.query('BEGIN');await target.query('SET LOCAL ROLE haq_owner');
  await target.query('DELETE FROM auth.oauth_states');await target.query('DELETE FROM auth.email_tokens');await target.query('DELETE FROM auth.sessions');
  await target.query('GRANT USAGE ON SCHEMA auth TO haq_identity');for(const table of ['users','identities','sessions','email_tokens','oauth_states'])await target.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON auth.${table} TO haq_identity`);await target.query('COMMIT');
  await target.end();target=null;return {ok:true,users,identities,sessionsRevoked:true,...(keep?{database:name}:{isolatedDatabaseDropped:true})};
 }finally{await target?.end().catch(()=>{});if(connected){if(created&&!keep)await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);await admin.end();}fs.rmSync(temp,{recursive:true,force:true});}
}
if(require.main===module){require('dotenv').config({quiet:true});(async()=>{const [action,file]=process.argv.slice(2);if(!file||!['backup','verify','recover'].includes(action))throw new Error('Usage');const key=decodeKey(process.env.AUTH_BACKUP_KEY),url=process.env.DATABASE_ADMIN_URL;if(!url)throw new Error('Admin connection required');
 if(action==='backup'){await makeBackup(url,key,file);console.log('Encrypted PostgreSQL snapshot created (mode 600). Run verify for an isolated restore drill.');}
 else{const i=process.argv.indexOf('--database');console.log(JSON.stringify(await restoreBackup(file,key,url,{keep:action==='recover',database:i>=0?process.argv[i+1]:undefined})));}
 })().catch(()=>{console.error('PostgreSQL backup/restore failed. Check private key, matching PG client major, permissions, and database settings. Source and live database were not replaced; inspect a failed new recovery database before reuse.');process.exitCode=1;});}
module.exports={decodeKey,makeBackup,restoreBackup};
