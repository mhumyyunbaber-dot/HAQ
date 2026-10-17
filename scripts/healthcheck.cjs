'use strict';
const headers=process.env.SERVICE_KEY?{'x-haq-service-key':process.env.SERVICE_KEY}:{'x-haq-health-key':require('node:crypto').createHash('sha256').update('health:'+['WEB_SERVICE_KEY','IDENTITY_SERVICE_KEY','LEGAL_SERVICE_KEY'].map(n=>process.env[n]).join(':')).digest('hex')};
fetch('http://127.0.0.1:'+process.env.PORT+'/healthz',{headers,signal:AbortSignal.timeout(4000),redirect:'error'}).then(r=>{if(!r.ok)process.exitCode=1;}).catch(()=>{process.exitCode=1;});
