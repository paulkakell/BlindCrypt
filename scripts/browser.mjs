// Real Chromium end-to-end tests using private child-process DevTools pipes.
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { join, resolve, extname } from "node:path";
import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import { createLegacyV1 } from "../tests/helpers.mjs";
import { APP_VERSION } from "../assets/crypto-core.js";
import { createPipeTransport } from "./browser-pipe.mjs";
import { createPageActions } from "./browser-actions.mjs";

const root=resolve(new URL("..",import.meta.url).pathname),dist=join(root,"dist");
const temp=await mkdtemp(join(tmpdir(),"blindcrypt-browser-")),downloads=join(temp,"downloads");await mkdir(downloads);
const sums=await readFile(join(dist,"SHA256SUMS"),"utf8");
const routes=new Map(sums.trim().split("\n").map((line)=>{const path=line.slice(66);return[`/${path}`,path];}));routes.set("/","index.html");
const mime={".html":"text/html",".js":"text/javascript",".css":"text/css",".webmanifest":"application/manifest+json",".png":"image/png"};
const server=createServer(async(req,res)=>{
  const path=routes.get(new URL(req.url||"/","http://127.0.0.1").pathname);
  if(req.method!=="GET"||!path){res.writeHead(404).end();return;}
  try{res.writeHead(200,{"Content-Type":mime[extname(path)]||"application/octet-stream","Cache-Control":"no-store"});res.end(await readFile(join(dist,path)));}catch{res.writeHead(404).end();}
});
await new Promise((r)=>server.listen(0,"127.0.0.1",r));const base=`http://127.0.0.1:${server.address().port}/`;
const browser=spawn(process.env.CHROME_BIN||"/usr/bin/chromium",["--headless=new","--remote-debugging-pipe",`--user-data-dir=${join(temp,"profile")}`,"--no-first-run","--no-default-browser-check","--no-proxy-server",...(process.getuid?.()===0?["--no-sandbox"]:[]),"about:blank"],{stdio:["ignore","ignore","ignore","pipe","pipe"]});
let closed=false;const passed=[],errors=[],completed=[],requests=[];
const transport = createPipeTransport(browser.stdio[3], browser.stdio[4], { onEvent(message) {
  if(message.method==="Runtime.exceptionThrown")errors.push(message.params.exceptionDetails.text+" "+(message.params.exceptionDetails.exception?.description||""));
  if(message.method==="Browser.downloadWillBegin")completed.push(message.params);
  if(message.method==="Network.requestWillBeSent")requests.push(message.params.request.url);
} });
browser.once("error", (error) => transport.close(error));
browser.once("exit", () => transport.close(new Error("Chromium exited")));
const send = transport.send;
const sleep=(ms)=>new Promise((r)=>setTimeout(r,ms));
async function until(check,description,limit=20000){const start=Date.now();while(Date.now()-start<limit){try{if(await check())return;}catch{/* Navigation can replace the execution context. */}await sleep(50);}throw new Error(`Timed out: ${description}`);}
try{
  await send("Browser.getVersion");
  const target=await send("Target.createTarget",{url:"about:blank"});const attached=await send("Target.attachToTarget",{targetId:target.targetId,flatten:true});
  const command=(method,params={})=>send(method,params,attached.sessionId);
  const evaluate=async(expression)=>{const result=await command("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});if(result.exceptionDetails)throw new Error(result.exceptionDetails.exception?.description||result.exceptionDetails.text);return result.result.value;};
  await command("Runtime.enable");await command("Network.enable");await command("Page.enable");
  await send("Browser.setDownloadBehavior",{behavior:"allow",downloadPath:downloads,eventsEnabled:true});
  const navigation=await command("Page.navigate",{url:base});
  if(navigation.errorText)throw new Error(`Browser navigation blocked: ${navigation.errorText}`);
  const callPage = createPageActions(command);
  await until(()=>callPage("ready", APP_VERSION, false),"application initialization");
  const fill=(name,value)=>callPage("fill",name,value);
  const click=(name)=>callPage("click",name);
  const tab=(name)=>callPage("tab",name);
  const upload=(name,files)=>callPage("upload",name,files);
  const file=(name,data,type="text/plain")=>({name,data:Buffer.from(data).toString("base64"),type});
  const done=(name)=>until(async()=>!(await callPage("state",name)).disabled,name+" completion");
  const success=async(name)=>{const state=await callPage("state",name);assert.equal(state.kind,"good",state.text);};
  const download=async(index)=>{await until(()=>completed.length>index,"download event");const name=completed[index].suggestedFilename;await until(async()=>{try{await readFile(join(downloads,name));return true;}catch{return false;}} ,"download file");return{name,bytes:await readFile(join(downloads,name))};};
  const literal = "quotes \" ' \\ line\u2028paragraph\u2029 <tag> & 😀";
  await fill("textPlain", literal);
  assert.equal(await evaluate("document.getElementById('textPlain').value"), literal);
  await upload("encFile", [file("quoted-\"-name.txt", literal)]);
  assert.equal(await evaluate("document.getElementById('encFile').files[0].name"), "quoted-\"-name.txt");
  assert.equal(await evaluate("document.getElementById('encFile').files[0].text()"), literal);
  await click("clearText");
  passed.push("fixture values remain data over private DevTools pipes");
  const secret="abandon ability able about above absent absorb abstract",other="access accident account accuse achieve acid acoustic acquire";
  await upload("encFile",[file("private.txt","first document"),file("second.txt","second document")]);await fill("encPass",secret);await fill("encConfirm",secret);await click("doEncrypt");await done("doEncrypt");await success("encStatus");
  const first=await download(0),second=await download(1);assert.match(first.name,/^[a-f0-9]{32}\.blindcrypt$/u);assert.notEqual(first.name,second.name);assert.equal(await evaluate("document.querySelectorAll('#encResults li').length"),2);passed.push("opaque filenames and sequential browser downloads");
  await tab("decrypt");await upload("decFile",[file(first.name,first.bytes)]);await fill("decPass",secret);const count=completed.length;await click("doVerify");await done("doVerify");await success("decStatus");assert.equal(completed.length,count);passed.push("verify has no plaintext download");
  await fill("decPass",secret);await click("doDecrypt");await done("doDecrypt");await success("decStatus");const restored=await download(2);assert.equal(restored.name,"private.txt");assert.equal(restored.bytes.toString(),"first document");passed.push("authenticated filename restoration");
  await tab("text");await evaluate("document.querySelector('[data-generate-for=textPass]').click()");assert.equal(await evaluate("document.getElementById('textPass').type"),"text");assert.equal((await evaluate("document.getElementById('textPass').value")).split(" ").length,8);
  const message="<img src=x onerror=alert(1)> 😀 日本語";await fill("textPlain",message);await fill("textPass",secret);await fill("textConfirm",secret);await click("encryptText");await done("encryptText");await success("textStatus");assert.equal(await evaluate("document.getElementById('textPlain').value"),"");await fill("textPass",secret);await click("decryptText");await done("decryptText");await success("textStatus");assert.equal(await evaluate("document.getElementById('textPlain').value"),message);assert.equal(await evaluate("document.getElementById('textPass').value"),"");passed.push("text round trip, literal HTML, visible generation, cleared secrets");
  await tab("upgrade");await upload("upgradeFile",[file(first.name,first.bytes)]);await fill("upgradeOld",secret);await fill("upgradeNew",other);await fill("upgradeConfirm",other);await click("doUpgrade");await done("doUpgrade");await success("upgradeStatus");const upgraded=await download(3);
  await tab("decrypt");await upload("decFile",[file(upgraded.name,upgraded.bytes)]);await fill("decPass",other);await click("doVerify");await done("doVerify");await success("decStatus");passed.push("guided re-encryption with new passphrase");
  await tab("large");await evaluate("globalThis.streamState={parts:[],closed:false,aborted:false};globalThis.showSaveFilePicker=async()=>({createWritable:async()=>({write(bytes){streamState.parts.push(Array.from(bytes));},close(){streamState.closed=true;},abort(){streamState.aborted=true;streamState.parts=[];}})});");
  await upload("largeFile",[file("large.txt","transactional browser output")]);await fill("largePass",secret);await fill("largeConfirm",secret);await click("largeEncrypt");await done("largeEncrypt");await success("largeStatus");assert.equal(await evaluate("streamState.closed"),true);const streamed=Buffer.from((await evaluate("streamState.parts")).flat());
  await evaluate("streamState={parts:[],closed:false,aborted:false}");await upload("largeFile",[file("stream.blindcrypt",streamed)]);await fill("largePass",secret);await click("largeDecrypt");await done("largeDecrypt");await success("largeStatus");assert.equal(Buffer.from((await evaluate("streamState.parts")).flat()).toString(),"transactional browser output");passed.push("large-file UI transaction adapter (picker mocked)");
  await tab("recipients");await fill("identityPass",secret);await fill("identityConfirm",secret);await click("createIdentity");await done("createIdentity");await success("recipientStatus");const backup=await download(4),pub=await download(5);const fingerprint=await evaluate("document.getElementById('identityFingerprint').textContent");assert.equal(fingerprint.length,43);
  await upload("recipientPublic",[file(pub.name,pub.bytes)]);await fill("expectedFingerprint",fingerprint);await upload("recipientFile",[file("recipient.txt","public key browser flow")]);await click("recipientEncrypt");await done("recipientEncrypt");await success("recipientStatus");const envelope=await download(6);
  await upload("recipientEnvelope",[file(envelope.name,envelope.bytes)]);await upload("identityBackup",[file(backup.name,backup.bytes)]);await fill("identityUnlock",secret);await click("recipientVerify");await done("recipientVerify");await success("recipientStatus");assert.equal(completed.length,7);
  await fill("identityUnlock",secret);await click("recipientDecrypt");await done("recipientDecrypt");await success("recipientStatus");assert.equal((await download(7)).bytes.toString(),"public key browser flow");passed.push("recipient identity, encryption, verification, and decryption UI");
  await tab("encrypt");await upload("encFile",[file("cancel.txt","cancel me")]);await fill("encPass",secret);await fill("encConfirm",secret);await click("doEncrypt");await click("cancelOperation");await done("doEncrypt");assert.equal(completed.length,8);assert.match(await evaluate("document.getElementById('encStatus').textContent"),/cancelled/u);passed.push("browser cancellation blocks export");
  await tab("decrypt");const legacy=await createLegacyV1(new TextEncoder().encode("legacy UI"),"old");await upload("decFile",[file("old.blindcrypt",new Uint8Array(await legacy.arrayBuffer()))]);await fill("decPass","old");await click("doDecrypt");await done("doDecrypt");assert.match(await evaluate("document.getElementById('decStatus').textContent"),/legacy metadata/u);assert.equal((await download(8)).name,"legacy-decrypted.bin");passed.push("legacy warning and neutral download");
  assert.equal(errors.length,0,errors.join("\n"));assert.ok(requests.filter((url)=>!url.startsWith("blob:")&&!url.startsWith(base)).length===0,"unexpected page network origin");
  await click("enableOffline");await until(()=>evaluate("navigator.serviceWorker.controller !== null"),"offline controller activation");
  const cachePaths=await evaluate("(async()=>{const keys=await caches.keys();return(await Promise.all(keys.map(async key=>(await(await caches.open(key)).keys()).map(r=>new URL(r.url).pathname)))).flat();})()");
  assert.ok(cachePaths.includes("/index.html"));assert.ok(!cachePaths.some((path)=>/private|recipient\.txt|\.blindcrypt|\.bckey/u.test(path)));
  await new Promise((r)=>server.close(r));closed=true;
  await evaluate("globalThis.reloadMarker = 'before'");
  await command("Page.reload");await until(()=>callPage("ready", APP_VERSION, true),"offline reload with server stopped");await sleep(200);assert.equal(errors.length,0,errors.join("\n"));passed.push("offline asset-only cache and reload with HTTP server stopped");
  console.log(JSON.stringify({browser:"Chromium",version:await evaluate("navigator.userAgent"),passed:passed.length,checks:passed,consoleExceptions:errors,manualGate:"Native OS picker and additional browser/device matrix remain manual."},null,2));
}catch(error){
  console.error(JSON.stringify({error:String(error),exceptions:errors,requests:requests.map((url)=>url.slice(0,150)),checksPassed:passed}));throw error;
}finally{
  transport.close();browser.kill("SIGTERM");await sleep(300);if(!closed)await new Promise((r)=>server.close(r));await rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});
}
