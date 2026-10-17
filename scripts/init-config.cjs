'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
function initConfig(destination,mode='compose'){
 if(!['compose','native'].includes(mode))throw new Error('Choose compose or native');
 if(fs.existsSync(destination))throw new Error('Configuration already exists; refusing to overwrite');
 const key=()=>crypto.randomBytes(32).toString('base64url');const admin=key(),identity=key(),docker=mode==='compose',dbHost=docker?'postgres:5432':'127.0.0.1:55432';
 const dbUrl=(user,password)=>{const u=new URL('postgresql://'+dbHost);u.username=user;u.password=password;u.pathname='/haq';return u.href;};
 const values={POSTGRES_PASSWORD:admin,IDENTITY_DB_PASSWORD:identity,DATABASE_ADMIN_URL:dbUrl('haq_admin',admin),AUTH_DATABASE_URL:dbUrl('haq_identity',identity),WEB_SERVICE_KEY:key(),IDENTITY_SERVICE_KEY:key(),LEGAL_SERVICE_KEY:key(),WEB_URL:`http://${docker?'web':'127.0.0.1'}:3101`,IDENTITY_URL:`http://${docker?'identity':'127.0.0.1'}:3102`,LEGAL_URL:`http://${docker?'legal':'127.0.0.1'}:3103`};
 let text=fs.readFileSync(path.join(__dirname,'../.env.example'),'utf8');for(const [name,value]of Object.entries(values))text=text.replace(new RegExp('^'+name+'=.*$','m'),name+'='+value);
 fs.writeFileSync(destination,text,{mode:0o600,flag:'wx'});console.log('Private configuration created. Keep it out of source control and backups; configure real production HTTPS, providers and SMTP separately.');
}
if(require.main===module){try{const args=process.argv.slice(2),mode=args.includes('--native')?'native':'compose',i=args.indexOf('--output');initConfig(path.resolve(i>=0?args[i+1]:'.env'),mode);}catch{console.error('Configuration not created: output already exists or parameters are invalid. Existing file was not changed.');process.exitCode=1;}}
module.exports={initConfig};
