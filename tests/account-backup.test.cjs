'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const crypto=require('node:crypto');const fs=require('node:fs');const path=require('node:path');const os=require('node:os');
const {openDatabase}=require('../auth.cjs');const {decodeKey,makeEncryptedBackup,verifyBackup}=require('../scripts/accounts-backup.cjs');
test('account backup is authenticated encryption; correct-key restore works and tampering/wrong keys fail',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'haq-backup-test-')),db=openDatabase(':memory:');const key=crypto.randomBytes(32);const out=path.join(dir,'accounts.encrypted.json');
 try{
  db.prepare('INSERT INTO users(id,email,email_key,name,created_at) VALUES (?,?,?,?,?)').run('test-user','private-person@example.invalid','private-person@example.invalid','Private name',Date.now());
  assert.deepEqual(decodeKey(key.toString('base64')),key);assert.throws(()=>decodeKey('invalid'));
  await makeEncryptedBackup(db,key,out);const encoded=fs.readFileSync(out,'utf8');assert.ok(!encoded.includes('private-person'));assert.equal(verifyBackup(out,key).users,1);assert.throws(()=>verifyBackup(out,crypto.randomBytes(32)));
  const changed=JSON.parse(encoded);changed.tag=crypto.randomBytes(16).toString('base64');fs.writeFileSync(out,JSON.stringify(changed));assert.throws(()=>verifyBackup(out,key));
 }finally{db.close();fs.rmSync(dir,{recursive:true,force:true});}
});
