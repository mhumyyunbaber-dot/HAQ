'use strict';
const {DatabaseSync}=require('node:sqlite'),{Pool}=require('pg'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const userColumns=['id','email','email_key','email_verified','name','password_hash','role','age_range','gender','created_at'];
const identityColumns=['provider','subject','user_id'];
async function importSqlite(source,adminUrl){
 if(!path.isAbsolute(source)||!adminUrl||fs.lstatSync(source).isSymbolicLink()||!fs.statSync(source).isFile())throw new Error('Explicit regular legacy database required');
 // Read-only: preserve the original database and its WAL. Take a consistent SQLite snapshot.
 const sqlite=new DatabaseSync(source,{readOnly:true});let users,identities,revoked;
 try{sqlite.exec('BEGIN');users=sqlite.prepare(`SELECT ${userColumns.join(',')} FROM users ORDER BY id`).all();identities=sqlite.prepare(`SELECT ${identityColumns.join(',')} FROM identities ORDER BY provider,subject`).all();revoked=sqlite.prepare('SELECT count(*) AS n FROM sessions').get().n;sqlite.exec('COMMIT');}finally{sqlite.close();}
 const canonical=JSON.stringify({users,identities});const fingerprint=crypto.createHash('sha256').update(canonical).digest('hex');
 const pool=new Pool({connectionString:adminUrl,max:1,connectionTimeoutMillis:5000}),c=await pool.connect();
 try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(6610221)');await c.query('SET LOCAL ROLE haq_owner');await c.query('SET LOCAL search_path=auth,pg_catalog');
  const previous=(await c.query('SELECT * FROM account_imports WHERE fingerprint=$1',[fingerprint])).rows[0];
  if(previous){await c.query('COMMIT');return {alreadyImported:true,users:previous.user_count,identities:previous.identity_count,revokedSessions:previous.revoked_session_count};}
  await c.query('LOCK TABLE users,identities,sessions,oauth_states,email_tokens IN ACCESS EXCLUSIVE MODE');
  for(const table of ['users','identities','sessions','oauth_states','email_tokens'])if((await c.query(`SELECT EXISTS(SELECT 1 FROM ${table}) AS occupied`)).rows[0].occupied)throw new Error('Destination must be empty; no automatic merge, delete, or overwrite');
  for(const [table,columns,rows]of [['users',userColumns,users],['identities',identityColumns,identities]])for(const row of rows)await c.query(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map((_,i)=>'$'+(i+1)).join(',')})`,columns.map(k=>row[k]));
  const restored={users:(await c.query(`SELECT ${userColumns.join(',')} FROM users ORDER BY id`)).rows,identities:(await c.query(`SELECT ${identityColumns.join(',')} FROM identities ORDER BY provider,subject`)).rows};
  if(JSON.stringify(restored)!==canonical)throw new Error('Imported account verification failed');
  await c.query('INSERT INTO account_imports(fingerprint,user_count,identity_count,revoked_session_count) VALUES($1,$2,$3,$4)',[fingerprint,users.length,identities.length,revoked]);await c.query('COMMIT');
  return {alreadyImported:false,users:users.length,identities:identities.length,revokedSessions:revoked};
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();await pool.end();}
}
if(require.main===module){require('dotenv').config({quiet:true});const i=process.argv.indexOf('--sqlite');if(i<0){console.error('Usage: node scripts/import-sqlite.cjs --sqlite /absolute/private/accounts.sqlite');process.exitCode=1;}else importSqlite(process.argv[i+1],process.env.DATABASE_ADMIN_URL).then(result=>console.log(JSON.stringify({event:'legacy_accounts_imported',...result,notice:'Sessions, OAuth states and email/reset tokens were not imported. Sign in again.'}))).catch(()=>{console.error('Import refused or failed. Source preserved. Destination must be empty and schema migrated; no credentials logged.');process.exitCode=1;});}
module.exports={importSqlite};
