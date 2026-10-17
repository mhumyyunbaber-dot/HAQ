'use strict';
const crypto=require('node:crypto');
const {createAuth,readAuthConfig}=require('../../auth.cjs');
const {internalApp,finish,listen,failure}=require('../../packages/http/internal.cjs');
async function createIdentity({key=process.env.SERVICE_KEY,env=process.env,audit,authOptions={}}={}){
 const mode=env.APP_ENV||'preview';if(!['preview','production','test'].includes(mode)||env.DEBUG||mode==='production'&&env.NODE_ENV!=='production')throw new Error('Unsafe identity mode');
 const authConfig=readAuthConfig(env,mode);if(!authConfig.databaseUrl)throw new Error('Identity requires PostgreSQL');
 const config={mode,auth:authConfig};const logKey=env.SECURITY_LOG_KEY||crypto.randomBytes(32).toString('hex');
 const log=audit||((event,req,status)=>console.log(JSON.stringify({time:new Date().toISOString(),event,status,requestId:req.securityId,client:crypto.createHmac('sha256',logKey).update(req.ip||'unknown').digest('hex').slice(0,20)})));
 const auth=createAuth(config,log,authOptions);try{await auth.ready();}catch(e){await auth.close();throw e;}
 const app=internalApp(key,'identity',()=>auth.ready());app.locals.auth=auth;
 app.use('/api/auth',auth.router);return {app:finish(app),close:()=>auth.close(),auth};
}
if(require.main===module){(async()=>{const service=await createIdentity();listen(service.app,Number(process.env.PORT||3102),service.close);})().catch(failure);}
module.exports={createIdentity};
