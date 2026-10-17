'use strict';
const fs=require('node:fs'),path=require('node:path');
const {internalApp,finish,listen,failure}=require('../../packages/http/internal.cjs');
function createWeb({key=process.env.SERVICE_KEY,root=process.env.WEB_ASSET_DIR||path.resolve(__dirname,'../..')}={}){
 const app=internalApp(key,'web');const assets=new Map();
 for(const [route,name,type]of [['/','index.html','html'],['/index.html','index.html','html'],['/app.js','app.js','js'],['/auth-ui.js','auth-ui.js','js'],['/style.css','style.css','css']]){
  const file=path.join(root,name);if(fs.lstatSync(file).isSymbolicLink()||!fs.statSync(file).isFile()||fs.statSync(file).size>2*1024*1024)throw new Error('Invalid public asset');assets.set(route,{body:fs.readFileSync(file),type});
 }
 app.use((req,res,next)=>{const file=assets.get(req.originalUrl);if(!file)return next();if(!['GET','HEAD'].includes(req.method))return res.status(405).end();if(req.headers['transfer-encoding']||Number(req.headers['content-length']||0)>0)return res.status(413).end();res.type(file.type).send(file.body);});
 return finish(app);
}
if(require.main===module){try{listen(createWeb(),Number(process.env.PORT||3101));}catch{failure();}}
module.exports={createWeb};
