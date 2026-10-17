'use strict';
const crypto=require('node:crypto'),http=require('node:http'),{once}=require('node:events'),{Client}=require('pg');
const {migrate}=require('../../scripts/migrate.cjs');
const {createIdentity}=require('../../services/identity/server.cjs');
const {createWeb}=require('../../services/web/server.cjs');
const {createLegal}=require('../../services/legal/server.cjs');
const {readGatewayConfig,createGateway}=require('../../services/gateway/server.cjs');
async function database(){
 const adminUrl=process.env.HAQ_TEST_ADMIN_URL;if(!adminUrl)throw new Error('Real PostgreSQL test configuration required');
 const admin=new Client({connectionString:adminUrl});await admin.connect();const name='haq_test_'+crypto.randomBytes(8).toString('hex');await admin.query('CREATE DATABASE "'+name+'"');const url=new URL(adminUrl);url.pathname='/'+name;
 const password=process.env.HAQ_TEST_IDENTITY_PASSWORD||crypto.randomBytes(32).toString('base64url');
 try{await migrate(url.href,password);}catch(e){await admin.query('DROP DATABASE "'+name+'" WITH (FORCE)');await admin.end();throw e;}
 const runtime=new URL(url);runtime.username='haq_identity';runtime.password=password;
 return {adminUrl:url.href,runtimeUrl:runtime.href,password,name,async close(){await admin.query('DROP DATABASE "'+name+'" WITH (FORCE)');await admin.end();}};
}
async function listen(app){const s=http.createServer(app);s.listen(0,'127.0.0.1');await once(s,'listening');return s;}
async function stop(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
async function stack(env={},authOptions={},output=()=>{}){
 const db=await database(),keys=Array.from({length:3},()=>crypto.randomBytes(32).toString('base64url'));let identity,servers=[];
 try{
  identity=await createIdentity({key:keys[1],env:{APP_ENV:'test',NODE_ENV:'production',...env,AUTH_DATABASE_URL:db.runtimeUrl},audit:()=>{},authOptions});
  const web=await listen(createWeb({key:keys[0]})),id=await listen(identity.app),legal=await listen(createLegal({key:keys[2]}));servers=[web,id,legal];
  const urls=servers.map(s=>'http://127.0.0.1:'+s.address().port);
  const config=readGatewayConfig({APP_ENV:'test',NODE_ENV:'production',RATE_LIMIT_MAX:'10000',...env,WEB_SERVICE_KEY:keys[0],IDENTITY_SERVICE_KEY:keys[1],LEGAL_SERVICE_KEY:keys[2],WEB_URL:urls[0],IDENTITY_URL:urls[1],LEGAL_URL:urls[2]});
  const server=createGateway(config,output);server.listen(0,'127.0.0.1');await once(server,'listening');
  return {server,config,auth:identity.auth,db,keys,servers,urls,url:'http://127.0.0.1:'+server.address().port,async close(){await stop(server);for(const s of servers)await stop(s);await identity.close();await db.close();}};
 }catch(e){for(const s of servers)await stop(s);await identity?.close();await db.close();throw e;}
}
module.exports={database,stack,stop};
