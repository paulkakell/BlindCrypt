import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile, readdir } from "node:fs/promises";
import { createHash, webcrypto } from "node:crypto";
const source=await readFile(new URL("../sw.js",import.meta.url),"utf8");
const files={"index.html":"<html>app</html>","VERSION":"02.00.00","assets/app.js":"app","assets/crypto.js":"crypto","manifest.webmanifest":"{}"};
const sha=(value)=>createHash("sha256").update(value).digest("hex");
function worker({built=true,corrupt=false,prior=false}={}){
  const handlers=new Map(),stores=new Map(),requests=[];let activated=0,claimed=0;
  const prefix="blindcrypt:https://example.test/BlindCrypt/:";
  if(prior)stores.set(prefix+"old",new Map());stores.set("unrelated",new Map());
  const caches={async open(key){if(!stores.has(key))stores.set(key,new Map());const map=stores.get(key);return{async put(url,response){map.set(url,response.clone());},async match(url){return map.get(url)?.clone();}};},async delete(key){return stores.delete(key);},async keys(){return[...stores.keys()];}};
  const self={registration:{scope:"https://example.test/BlindCrypt/"},clients:{async claim(){claimed++;}},async skipWaiting(){activated++;},addEventListener(name,handler){handlers.set(name,handler);}};
  const manifest=Object.fromEntries(Object.entries(files).map(([name,value])=>[name,sha(value)]));
  const script=built?source.replace('/* BUILD_ID */ "unbuilt"','"testbuild"').replace("/* ASSET_MANIFEST */ {}",JSON.stringify(manifest)):source;
  vm.runInNewContext(script,{self,caches,URL,Response,Request,crypto:webcrypto,Uint8Array,fetch:async(url,options)=>{
    requests.push({url,options});const name=new URL(url).pathname.slice("/BlindCrypt/".length);
    return new Response(corrupt?"tampered":files[name],{status:files[name]===undefined?404:200});
  }});
  async function lifecycle(name,event={}){const pending=[];handlers.get(name)({...event,waitUntil(value){pending.push(value);}});await Promise.all(pending);}
  async function get(path,method="GET"){let response;handlers.get("fetch")({request:new Request(new URL(path,"https://example.test/BlindCrypt/"),{method}),respondWith(value){response=value;}});return response?await response:null;}
  return{lifecycle,get,stores,requests,prefix,activated:()=>activated,claimed:()=>claimed};
}
test("unbuilt worker refuses installation",async()=>{const w=worker({built:false});await assert.rejects(w.lifecycle("install"),/verified build/u);assert.equal(w.requests.length,0);});
test("offline install caches only hash-verified fixed application URLs",async()=>{
  const w=worker({prior:true});await w.lifecycle("install");assert.equal(w.requests.length,Object.keys(files).length);
  for(const request of w.requests){assert.equal(request.options.credentials,"omit");assert.equal(request.options.redirect,"error");}
  assert.ok(w.stores.has(w.prefix+"old"));await w.lifecycle("activate");assert.ok(!w.stores.has(w.prefix+"old"));assert.ok(w.stores.has("unrelated"));assert.equal(w.claimed(),1);
  assert.equal(await(await w.get("./")).text(),files["index.html"]);
  assert.equal(await(await w.get("VERSION")).text(),"02.00.00");
});
test("corrupt asset aborts new cache installation and preserves previous cache",async()=>{
  const w=worker({corrupt:true,prior:true});await assert.rejects(w.lifecycle("install"),/integrity mismatch/u);
  assert.deepEqual([...w.stores.keys()].sort(),[w.prefix+"old","unrelated"].sort());
});
test("offline worker never caches user paths, query data, POSTs, or arbitrary runtime requests",async()=>{
  const w=worker();await w.lifecycle("install");const before=w.requests.length;
  for(const path of["private.blindcrypt","document.txt","?secret=x","assets/app.js?file=private","cli/blindcrypt.mjs"])assert.equal((await w.get(path)).status,404);
  assert.equal((await w.get("index.html","POST")).status,404);
  assert.equal(await w.get("https://other.test/"),null);assert.equal(w.requests.length,before);
});
test("worker activation requires an explicit in-scope client control message",async()=>{
  const w=worker();await w.lifecycle("message",{origin:"https://example.test",data:{type:"OTHER"},source:{url:"https://example.test/BlindCrypt/"}});
  await w.lifecycle("message",{origin:"https://example.test",data:{type:"ACTIVATE"},source:{url:"https://attacker.test/"}});assert.equal(w.activated(),0);
  await w.lifecycle("message",{origin:"https://example.test",data:{type:"ACTIVATE"},source:{url:"https://example.test/BlindCrypt/"}});assert.equal(w.activated(),1);
});
test("offline activation rejects missing, foreign and lookalike origins even with a forged source URL",async()=>{
  const w=worker();
  for(const origin of[undefined,"null","https://attacker.test","https://example.test.attacker.test"]){
    await w.lifecycle("message",{origin,data:{type:"ACTIVATE"},source:{url:"https://example.test/BlindCrypt/"}});
  }
  for(const url of["https://example.test/BlindCrypt-other/","https://example.test.attacker.test/BlindCrypt/","not a URL"]){
    await w.lifecycle("message",{origin:"https://example.test",data:{type:"ACTIVATE"},source:{url}});
  }
  assert.equal(w.activated(),0);
});
test("production JavaScript has no persistent secret stores, unsafe HTML, dynamic code, or random Math",async()=>{
  for(const name of await readdir(new URL("../assets/",import.meta.url))){
    if(!name.endsWith(".js")||name==="wordlist.js")continue;
    const text=await readFile(new URL(`../assets/${name}`,import.meta.url),"utf8");
    assert.doesNotMatch(text,/localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML|outerHTML|insertAdjacentHTML|Math\.random\(|\beval\(/u,name);
  }
});
