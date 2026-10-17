"use strict";
// Legacy in-process test harness only. Runtime entry point: scripts/dev.cjs (four services).
const edge=require('./packages/http/edge.cjs');
const {readAuthConfig,createAuth}=require('./auth.cjs');
function loadConfig(env=process.env){return {...edge.loadConfig(env),auth:readAuthConfig(env,env.APP_ENV||'preview')};}
const createApp=(config,output,options={})=>edge.createApp(config,output,{...options,authFactory:createAuth});
const createServer=(config,output,options={})=>edge.createServer(config,output,{...options,authFactory:createAuth});
if(require.main===module){console.error('Use npm start for the microservice runtime; this module is a legacy test harness.');process.exitCode=1;}
module.exports={loadConfig,createApp,createServer};
