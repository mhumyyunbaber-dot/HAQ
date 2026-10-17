'use strict';
const {createProxyServer}=require('httpxy');
const crypto=require('node:crypto');
const {loadConfig,createServer}=require('../../packages/http/edge.cjs');
const {failure}=require('../../packages/http/internal.cjs');
function readGatewayConfig(env=process.env){
 const config=loadConfig({...env,AUTH_ENABLED:'true',HOST:undefined});config.host=env.HOST||'0.0.0.0';
 const names=['web','identity','legal'];config.upstreams={};const seen=new Set();
 for(const name of names){const key=env[name.toUpperCase()+'_SERVICE_KEY'];const url=env[name.toUpperCase()+'_URL'];if(!key||!/^[A-Za-z0-9_-]{43,128}$/.test(key)||seen.has(key))throw new Error('Separate private service keys required');seen.add(key);const u=new URL(url);if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw new Error('Invalid private upstream');config.upstreams[name]={url:u.origin,key};}
 config.healthKey=crypto.createHash('sha256').update('health:'+names.map(n=>config.upstreams[n].key).join(':')).digest('hex');
 return config;
}
function createGateway(config,output){
 const emit=output||(record=>process.stdout.write(JSON.stringify(record)+'\n'));
 const proxy=createProxyServer({xfwd:false,changeOrigin:false,followRedirects:false,timeout:15000,proxyTimeout:12000});
 const headersFor=(upstream)=>({'x-haq-service-key':upstream.key});
 const handler=async(req,res)=>{
  const pathname=req.originalUrl.split('?')[0];
  if(pathname==='/healthz'){
   const statuses=await Promise.all(Object.entries(config.upstreams).map(async([name,upstream])=>{try{const r=await fetch(upstream.url+'/healthz',{headers:headersFor(upstream),signal:AbortSignal.timeout(2000),redirect:'error'});return [name,r.ok];}catch{return [name,false];}}));
   const services=Object.fromEntries(statuses);return res.status(statuses.every(([,ok])=>ok)?200:503).json({status:statuses.every(([,ok])=>ok)?'ready':'degraded',services});
  }
  const name=pathname.startsWith('/api/auth/')?'identity':pathname==='/data.js'||pathname.startsWith('/api/legal/')?'legal':'web';
  const upstream=config.upstreams[name];
  // Capture only the edge-validated address/protocol; ignore all user-supplied internal headers.
  const client=req.ip,proto=config.mode==='production'||req.secure||/^3000-[a-z0-9-]+\.e2b\.app$/i.test(req.headers.host||'')?'https':'http';
  for(const header of Object.keys(req.headers))if(header.startsWith('x-haq-')||header.startsWith('x-forwarded-')||['forwarded','authorization','proxy-authorization'].includes(header))delete req.headers[header];
  if(name!=='identity'){delete req.headers.cookie;delete req.headers['x-csrf-token'];}
  req.headers['x-haq-service-key']=upstream.key;req.headers['x-forwarded-for']=client;req.headers['x-forwarded-proto']=proto;
  // Connection-nominated headers cannot erase the authenticated hop or introduce smuggling ambiguities.
  req.headers.connection='close';
  try{await proxy.web(req,res,{target:upstream.url});}catch{emit({time:new Date().toISOString(),event:'upstream_unavailable',service:name,status:503,requestId:req.securityId});if(res.headersSent)return res.end();res.status(503).json({error:'Service temporarily unavailable.',requestId:req.securityId});}
 };
 const server=createServer(config,output,{gatewayHandler:handler});return server;
}
if(require.main===module){try{const config=readGatewayConfig();const server=createGateway(config);server.listen(config.port,config.host,()=>console.log(JSON.stringify({event:'gateway_started',port:config.port,mode:config.mode})));server.on('error',failure);for(const s of ['SIGINT','SIGTERM'])process.on(s,()=>{server.close(()=>process.exit(0));server.closeIdleConnections();setTimeout(()=>process.exit(1),5000).unref();});}catch{failure();}}
module.exports={readGatewayConfig,createGateway};
