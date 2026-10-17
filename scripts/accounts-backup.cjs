'use strict';
// Encrypted SQLite snapshots. Key is operator-owned, not bundled or stored with backups.
const {backup,DatabaseSync}=require('node:sqlite');
const fs=require('node:fs');const path=require('node:path');const os=require('node:os');const crypto=require('node:crypto');
const AAD=Buffer.from('haq-account-backup-v1');
function decodeKey(value){const key=Buffer.from(value||'','base64');if(key.length!==32||key.toString('base64')!==value)throw new Error('Set AUTH_BACKUP_KEY to a canonical base64-encoded 32-byte key in protected server configuration.');return key;}
async function makeEncryptedBackup(db,key,output){
 if(!Buffer.isBuffer(key)||key.length!==32)throw new Error('Invalid backup key');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'haq-db-backup-'));fs.chmodSync(temp,0o700);
 try{
  const snapshot=path.join(temp,'snapshot.sqlite');await backup(db,snapshot);fs.chmodSync(snapshot,0o600);
  const plain=fs.readFileSync(snapshot),nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(AAD);
  const data=Buffer.concat([cipher.update(plain),cipher.final()]);
  const envelope={version:1,nonce:nonce.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:data.toString('base64')};
  const dir=path.dirname(output);fs.mkdirSync(dir,{recursive:true,mode:0o700});
  const target=output+'.'+crypto.randomUUID()+'.tmp';fs.writeFileSync(target,JSON.stringify(envelope),{mode:0o600,flag:'wx'});fs.renameSync(target,output);return output;
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
function verifyBackup(file,key){
 if(fs.statSync(file).size>100*1024*1024)throw new Error('Backup too large for this verification tool');
 const e=JSON.parse(fs.readFileSync(file,'utf8'));if(e.version!==1||typeof e.nonce!=='string'||typeof e.tag!=='string'||typeof e.data!=='string')throw new Error('Invalid envelope');
 const nonce=Buffer.from(e.nonce,'base64'),tag=Buffer.from(e.tag,'base64');if(nonce.length!==12||tag.length!==16)throw new Error('Invalid envelope');
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,nonce);decipher.setAAD(AAD);decipher.setAuthTag(tag);
 const plain=Buffer.concat([decipher.update(Buffer.from(e.data,'base64')),decipher.final()]);
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'haq-db-restore-'));fs.chmodSync(temp,0o700);let db;
 try{const file=path.join(temp,'restore.sqlite');fs.writeFileSync(file,plain,{mode:0o600});db=new DatabaseSync(file,{readOnly:true});
  if(db.prepare('PRAGMA integrity_check').get().integrity_check!=='ok')throw new Error('Database integrity check failed');
  const tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(x=>x.name);if(!['users','sessions','identities','email_tokens','oauth_states'].every(x=>tables.includes(x)))throw new Error('Incomplete account database');
  return {ok:true,users:Number(db.prepare('SELECT COUNT(*) AS n FROM users').get().n)};
 }finally{db?.close();fs.rmSync(temp,{recursive:true,force:true});}
}
async function main(){
 require('dotenv').config({path:path.join(__dirname,'../.env'),quiet:true});
 const {readAuthConfig}=require('../auth.cjs');const config=readAuthConfig(process.env,process.env.APP_ENV||'preview');
 const key=decodeKey(process.env.AUTH_BACKUP_KEY);const file=process.argv[2]||path.join(__dirname,'../private/backups/accounts.encrypted.json');
 const db=new DatabaseSync(config.file,{readOnly:true});try{await makeEncryptedBackup(db,key,path.resolve(file));verifyBackup(path.resolve(file),key);console.log('Encrypted account backup created; isolated SQLite integrity/schema restore test passed. No live database was replaced.');}finally{db.close();}
}
if(require.main===module)main().catch(()=>{console.error('Account backup failed. Check the protected backup key, database path and destination. No key or account data was logged.');process.exitCode=1;});
module.exports={decodeKey,makeEncryptedBackup,verifyBackup};
