import test from "node:test";
import assert from "node:assert/strict";
import { encryptedFilename, processQueue, encryptText, decryptText, reencrypt, MAX_TEXT_BYTES, TEXT_PREFIX } from "../assets/features.js";
import { encryptBlobV3, decryptBlobAny, verifyV3 } from "../assets/crypto.js";
import { createLegacyV1, createLegacyV2 } from "./helpers.mjs";
const secret = "abandon ability able about above absent absorb abstract";
const other = "access accident account accuse achieve acid acoustic acquire";
const options = {name: "private.txt", type: "text/plain", levelKey: "standard"};

test("opaque filenames conceal originals and opt-in names are sanitized", () => {
  const names = Array.from({length:1000}, () => encryptedFilename("merger-plans.pdf"));
  assert.equal(new Set(names).size,1000);
  for (const name of names) assert.match(name,/^[a-f0-9]{32}\.blindcrypt$/u);
  assert.equal(encryptedFilename("report.txt",true),"report.txt.blindcrypt");
  assert.doesNotMatch(encryptedFilename("../../bad\\x.txt",true),/[\/\\]/u);
});
test("batch work is sequential, contains failures, and retains only status", async () => {
  let active=0, maximum=0; const order=[];
  const results=await processQueue([1,2,3],async (value)=>{
    maximum=Math.max(maximum,++active); order.push(value);
    await new Promise((resolve)=>setTimeout(resolve,5)); active--;
    if(value===2)throw new Error("synthetic private detail");
  });
  assert.equal(maximum,1); assert.deepEqual(order,[1,2,3]);
  assert.deepEqual(results.map((r)=>r.state),["complete","failed","complete"]);
  assert.doesNotMatch(JSON.stringify(results),/synthetic|private detail/u);
  await assert.rejects(processQueue([],async()=>{}));
  await assert.rejects(processQueue(Array(101).fill(1),async()=>{}));
});
test("cancellation stops subsequent batch operations",async()=>{
  const controller=new AbortController(); let calls=0;
  const results=await processQueue([1,2,3],async()=>{calls++;controller.abort();},{signal:controller.signal});
  assert.equal(calls,1); assert.deepEqual(results.map((r)=>r.state),["complete","cancelled","cancelled"]);
});
test("text supports Unicode and HTML as literal text; does not normalize content",async()=>{
  const plain="<script>alert('no')</script>\nCafe\u0301 😀 日本語";
  const armor=await encryptText(plain,secret,"standard");
  assert.ok(armor.startsWith(TEXT_PREFIX)); assert.equal(await decryptText(armor,secret),plain);
  await assert.rejects(decryptText(armor,other));
  for(const value of [armor+"=",armor+"\n","other."+armor])await assert.rejects(decryptText(value,secret));
});
test("text empty and exact UTF-8 limits round trip; oversize fails",async()=>{
  assert.equal(await decryptText(await encryptText("",secret,"standard"),secret),"");
  const plain="x".repeat(MAX_TEXT_BYTES);
  assert.equal((await decryptText(await encryptText(plain,secret,"standard"),secret)).length,MAX_TEXT_BYTES);
  await assert.rejects(encryptText(plain+"x",secret));
  await assert.rejects(encryptText("😀".repeat(MAX_TEXT_BYTES/2),secret));
  await assert.rejects(encryptText("x","weak"));
});
test("re-encryption changes secret and settings, retaining authenticated metadata",async()=>{
  const original=await encryptBlobV3(new Blob(["original"]),secret,options);
  const changed=await reencrypt(original.blob,secret,other,{levelKey:"high"});
  assert.equal((await decryptBlobAny(changed.blob,other)).metadata.name,"private.txt");
  assert.equal((await verifyV3(changed.blob,other)).publicHeader.iter,1200000);
  await assert.rejects(decryptBlobAny(changed.blob,secret));
  assert.equal(await (await decryptBlobAny(original.blob,secret)).blob.text(),"original");
});
for(const [version,writer]of[[1,createLegacyV1],[2,createLegacyV2]])test(`legacy v${version} upgrade retains warnings and uses neutral metadata`,async()=>{
  const original=await writer(new TextEncoder().encode("old document"),"old-secret",{name:"../../unsafe.html",type:"text/html"});
  const changed=await reencrypt(original,"old-secret",other,{levelKey:"standard"});
  const result=await decryptBlobAny(changed.blob,other);
  assert.equal(changed.sourceFormat,version); assert.ok(changed.legacyWarning);
  assert.equal(result.metadata.name,"legacy-decrypted.bin");
  assert.equal(result.metadata.type,"application/octet-stream");
  assert.equal(await result.blob.text(),"old document");
  await assert.rejects(verifyV3(original,"old-secret"));
});
