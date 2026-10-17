'use strict';
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),path=require('node:path');
const {internalApp,finish,listen,failure}=require('../../packages/http/internal.cjs');
function createLegal({key=process.env.SERVICE_KEY,file=path.join(__dirname,'data.js')}={}){
 const body=fs.readFileSync(file,'utf8');const data=vm.runInNewContext(body+';({sources:SOURCES,topics:TOPICS,rentalLaws:RENT_LAWS})',{URL}, {timeout:1000});
 if(!data||!Array.isArray(data.topics)||data.topics.length!==6)throw new Error('Invalid public reference catalog');
 const catalog=JSON.parse(JSON.stringify(data));const version=crypto.createHash('sha256').update(body).digest('hex');
 const app=internalApp(key,'legal-reference');
 app.use((req,res,next)=>{if(!['GET','HEAD'].includes(req.method))return res.status(405).json({error:'Read-only public references.'});if(req.headers['transfer-encoding']||Number(req.headers['content-length']||0)>0)return res.status(413).end();next();});
 app.get('/data.js',(req,res)=>{if(req.originalUrl!=='/data.js')return res.status(400).end();res.type('js').send(body);});
 app.get('/api/legal/catalog',(req,res)=>{if(req.originalUrl!=='/api/legal/catalog')return res.status(400).end();res.json({version,processing:'browser-only',catalog});});
 return finish(app);
}
if(require.main===module){try{listen(createLegal(),Number(process.env.PORT||3103));}catch{failure();}}
module.exports={createLegal};
