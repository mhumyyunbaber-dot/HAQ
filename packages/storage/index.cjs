'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
const {Pool,types}=require('pg');
types.setTypeParser(20,value=>{const n=Number(value);if(!Number.isSafeInteger(n))throw new Error('Database integer out of range');return n;});
function postgresStore(url,{max=8}={}){
 const parsed=new URL(url);if(!['postgres:','postgresql:'].includes(parsed.protocol))throw new Error('Invalid database configuration');
 const pool=new Pool({connectionString:url,max,connectionTimeoutMillis:5000,idleTimeoutMillis:10000,statement_timeout:8000,query_timeout:9000,options:'-c search_path=auth,pg_catalog',application_name:'haq-identity'});
 pool.on('error',()=>{}); // No database URLs or provider errors in logs.
 const context=new AsyncLocalStorage();
 const query=(text,values=[])=>{let i=0;const sql=text.replace(/\?/g,()=>'$'+(++i));return (context.getStore()||pool).query(sql,values);};
 const store={
  prepare(text){return {async get(...v){return (await query(text,v)).rows[0];},async all(...v){return (await query(text,v)).rows;},async run(...v){const r=await query(text,v);return {changes:r.rowCount};}};},
  query,
  async transaction(fn){if(context.getStore())return fn();const client=await pool.connect();try{await client.query('BEGIN');const value=await context.run(client,fn);await client.query('COMMIT');return value;}catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}},
  async ready(){await query('SELECT id FROM users LIMIT 0');const r=(await query("SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,has_schema_privilege(current_user,'auth','CREATE') AS can_create,has_table_privilege(current_user,'auth.users','TRUNCATE') AS can_truncate FROM pg_roles WHERE rolname=current_user")).rows[0];if(r.rolname!=='haq_identity'||r.rolsuper||r.rolcreatedb||r.rolcreaterole||r.can_create||r.can_truncate)throw new Error('Unsafe runtime database role');},async lockIdentity(provider,subject){if(!context.getStore())throw new Error('Identity lock requires a transaction');await query('SELECT pg_advisory_xact_lock(hashtextextended(?,0))',[provider+':'+subject]);},async close(){await pool.end();},pool
 };
 return store;
}
// Kept exclusively for isolated legacy/unit tests. Running services require PostgreSQL.
function sqliteTestStore(raw){
 const context=new AsyncLocalStorage();let queue=Promise.resolve();
 const exclusive=fn=>{const result=queue.then(fn);queue=result.catch(()=>{});return result;};
 const execute=fn=>context.getStore()?Promise.resolve().then(fn):exclusive(fn);
 return {prepare(text){const stmt=raw.prepare(text.replace(/\s+FOR UPDATE\b/gi,''));return {get:(...v)=>execute(()=>stmt.get(...v)),all:(...v)=>execute(()=>stmt.all(...v)),run:(...v)=>execute(()=>stmt.run(...v))};},
 async transaction(fn){if(context.getStore())return fn();return exclusive(async()=>{raw.exec('BEGIN IMMEDIATE');try{const value=await context.run(true,fn);raw.exec('COMMIT');return value;}catch(e){raw.exec('ROLLBACK');throw e;}});},async ready(){},async lockIdentity(){},async close(){await queue;raw.close();},raw};
}
module.exports={postgresStore,sqliteTestStore};
