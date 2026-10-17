'use strict';
const {Pool}=require('pg'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
async function migrate(adminUrl,password){
 if(!adminUrl||!password||password.length<32)throw new Error('Migration configuration required');
 const pool=new Pool({connectionString:adminUrl,max:1,connectionTimeoutMillis:5000});const c=await pool.connect();
 try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(6610221)');
  const roles=(await c.query("SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolcanlogin FROM pg_roles WHERE rolname IN ('haq_owner','haq_identity')")).rows;
  const owner=roles.find(x=>x.rolname==='haq_owner'),runtime=roles.find(x=>x.rolname==='haq_identity');
  if(owner&&(owner.rolsuper||owner.rolcreatedb||owner.rolcreaterole||owner.rolcanlogin)||runtime&&(runtime.rolsuper||runtime.rolcreatedb||runtime.rolcreaterole))throw new Error('Unsafe pre-existing database role');
  if(!owner)await c.query('CREATE ROLE haq_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE');
  if(!runtime){const {ddl}=(await c.query("SELECT format('CREATE ROLE haq_identity LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', $1::text) AS ddl",[password])).rows[0];await c.query(ddl);}
  await c.query('CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION haq_owner');
  await c.query('REVOKE ALL ON SCHEMA auth FROM PUBLIC');await c.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
  await c.query('SET LOCAL ROLE haq_owner');await c.query('SET LOCAL search_path=auth,pg_catalog');
  await c.query('CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())');
  for(const name of fs.readdirSync(path.join(__dirname,'../migrations')).filter(x=>/^\d+_[a-z_]+\.sql$/.test(x)).sort()){
   const body=fs.readFileSync(path.join(__dirname,'../migrations',name),'utf8'),sum=crypto.createHash('sha256').update(body).digest('hex');
   const previous=(await c.query('SELECT checksum FROM schema_migrations WHERE version=$1',[name])).rows[0];
   if(previous){if(previous.checksum!==sum)throw new Error('Migration checksum changed');continue;}
   await c.query(body);await c.query('INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)',[name,sum]);
  }
  await c.query('GRANT USAGE ON SCHEMA auth TO haq_identity');
  for(const table of ['users','identities','sessions','email_tokens','oauth_states'])await c.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON auth.${table} TO haq_identity`);
  await c.query('RESET ROLE');await c.query('COMMIT');
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();await pool.end();}
}
if(require.main===module){require('dotenv').config({quiet:true});migrate(process.env.DATABASE_ADMIN_URL,process.env.IDENTITY_DB_PASSWORD).then(()=>console.log('Identity schema migrations applied.')).catch(()=>{console.error('Migration failed; verify database credentials, role safety, and migration checksums. No credentials logged.');process.exitCode=1;});}
module.exports={migrate};
