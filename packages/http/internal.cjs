'use strict';
const express=require('express'),crypto=require('node:crypto'),http=require('node:http');
function internalApp(key,service,ready=async()=>{}){
 if(!key||!/^[A-Za-z0-9_-]{43,128}$/.test(key))throw new Error('Private service key required');
 const app=express();app.disable('x-powered-by');app.disable('etag');app.set('env','production');app.set('query parser',false);app.set('trust proxy',1);
 app.use((req,res,next)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  const provided=req.headers['x-haq-service-key'];
  if(typeof provided!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(provided)||provided.length!==key.length||!crypto.timingSafeEqual(Buffer.from(provided),Buffer.from(key)))return res.status(403).json({error:'Request not accepted.'});
  req.securityId=crypto.randomUUID();next();
 });
 app.get('/healthz',async(req,res)=>{try{await ready();res.json({service,status:'ready'});}catch{res.status(503).json({service,status:'unavailable'});}});
 return app;
}
function finish(app){
 app.use((req,res)=>res.status(404).json({error:'Not found.'}));
 app.use((err,req,res,next)=>{if(res.headersSent)return res.end();res.status(500).json({error:'Request could not be completed.'});});return app;
}
function listen(app,port,onClose=async()=>{},host=process.env.SERVICE_HOST||'0.0.0.0'){
 const server=http.createServer({maxHeaderSize:8192},app);server.headersTimeout=10000;server.requestTimeout=15000;server.timeout=15000;server.maxConnections=256;server.maxHeadersCount=64;
 server.listen(port,host,()=>console.log(JSON.stringify({event:'service_started',service:process.env.SERVICE_NAME,port})));
 server.on('error',()=>{console.error('Service could not start. Check configuration and port.');process.exit(1);});
 let stopping=false;for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{if(stopping)return;stopping=true;server.close(async()=>{await onClose();process.exit(0);});server.closeIdleConnections();setTimeout(()=>process.exit(1),5000).unref();});return server;
}
function failure(){console.error('Service configuration or startup failed. No credentials logged.');process.exitCode=1;}
module.exports={internalApp,finish,listen,failure};
