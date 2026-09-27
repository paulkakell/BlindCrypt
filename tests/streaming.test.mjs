import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, open, rm } from "node:fs/promises";
import { openAsBlob } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { encryptBlobV3, decryptBlobAny, encryptV3ToSink, decryptV3ToSink, verifyV3, CHUNK_SIZE, MAX_STREAM_PLAINTEXT_SIZE } from "../assets/crypto.js";
import { atomicSink } from "../cli/io.mjs";
const secret="abandon ability able about above absent absorb abstract";
const options={name:"stream.bin",type:"application/octet-stream",levelKey:"standard"};
function memorySink(failAt=Infinity){
  const sink={parts:[],writes:0,closed:false,aborted:false,max:0,
    async write(bytes){sink.max=Math.max(sink.max,bytes.length);if(++sink.writes===failAt)throw new Error("synthetic IO error");sink.parts.push(new Uint8Array(bytes));},
    async close(){sink.closed=true;},async abort(){sink.aborted=true;sink.parts=[];}};
  return sink;
}
for(const length of[0,1,CHUNK_SIZE,CHUNK_SIZE+1])test(`stream/buffer format compatibility at ${length} bytes`,async()=>{
  const source=new Blob([new Uint8Array(length).fill(91)]);const sink=memorySink();
  await encryptV3ToSink(source,secret,options,sink); assert.ok(sink.closed);assert.ok(sink.max<=CHUNK_SIZE+16);
  const container=new Blob(sink.parts);
  assert.equal((await verifyV3(container,secret)).verified,true);
  const opened=await decryptBlobAny(container,secret);assert.deepEqual(await opened.blob.arrayBuffer(),await source.arrayBuffer());
  const buffered=await encryptBlobV3(source,secret,options);const plain=memorySink();
  await decryptV3ToSink(buffered.blob,secret,plain);assert.ok(plain.closed);assert.deepEqual(await new Blob(plain.parts).arrayBuffer(),await source.arrayBuffer());
});
test("verify never constructs a plaintext Blob",async()=>{
  const encrypted=await encryptBlobV3(new Blob(["private"]),secret,options);
  const Original=globalThis.Blob;
  globalThis.Blob=class extends Original{constructor(){throw new Error("Unexpected output allocation");}static[Symbol.hasInstance](value){return value instanceof Original;}};
  try{const result=await verifyV3(encrypted.blob,secret);assert.equal(result.verified,true);assert.ok(!Object.hasOwn(result,"blob"));}
  finally{globalThis.Blob=Original;}
});
test("failed authentication never commits partial streamed plaintext",async()=>{
  const result=await encryptBlobV3(new Blob([new Uint8Array(CHUNK_SIZE+1)]),secret,options);
  const bytes=new Uint8Array(await result.blob.arrayBuffer());bytes[bytes.length-1]^=1;const sink=memorySink();
  await assert.rejects(decryptV3ToSink(new Blob([bytes]),secret,sink),{code:"AUTHENTICATION_FAILED"});
  assert.equal(sink.writes,1);assert.equal(sink.closed,false);assert.equal(sink.aborted,true);assert.equal(sink.parts.length,0);
});
test("sink errors preserve their cause and trigger abort; close failure also aborts",async()=>{
  const encrypted=await encryptBlobV3(new Blob(["private"]),secret,options);const sink=memorySink(1);
  await assert.rejects(decryptV3ToSink(encrypted.blob,secret,sink),/synthetic IO error/u);assert.ok(sink.aborted);
  const closing=memorySink();closing.close=async()=>{throw new Error("close failed");};
  await assert.rejects(encryptV3ToSink(new Blob(["x"]),secret,options,closing),/close failed/u);assert.ok(closing.aborted);
});
test("cancellation before work and during output aborts without commit",async()=>{
  const pre=new AbortController();pre.abort();const one=memorySink();
  await assert.rejects(encryptV3ToSink(new Blob(["x"]),secret,{...options,signal:pre.signal},one),{code:"CANCELLED"});assert.ok(one.aborted);
  const mid=new AbortController();const two=memorySink();const write=two.write;two.write=async(bytes)=>{await write(bytes);mid.abort();};
  await assert.rejects(encryptV3ToSink(new Blob([new Uint8Array(CHUNK_SIZE+1)]),secret,{...options,signal:mid.signal},two),{code:"CANCELLED"});assert.ok(two.aborted);assert.ok(!two.closed);
});
test("plaintext chunks are wiped after the sink consumes them",async()=>{
  const encrypted=await encryptBlobV3(new Blob(["secret bytes"]),secret,options);const references=[];
  await decryptV3ToSink(encrypted.blob,secret,{write(bytes){assert.ok(bytes.some(Boolean));references.push(bytes);},close(){},abort(){}});
  assert.ok(references.every((bytes)=>bytes.every((byte)=>byte===0)));
});
test("65 MiB file streams through disk without whole-file allocation; buffered reader refuses it",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"blindcrypt-large-"));
  try{
    const path=join(dir,"large.bin");const file=await open(path,"wx");await file.truncate(65*1024*1024);await file.close();
    const source=await openAsBlob(path);const output=join(dir,"encrypted");
    await encryptV3ToSink(source,secret,options,await atomicSink(output));const encrypted=await openAsBlob(output);
    await assert.rejects(decryptBlobAny(encrypted,secret),{code:"FILE_TOO_LARGE"});
    const hash=createHash("sha256");let bytes=0,max=0,closed=false;
    await decryptV3ToSink(encrypted,secret,{write(chunk){hash.update(chunk);bytes+=chunk.length;max=Math.max(max,chunk.length);},close(){closed=true;},abort(){throw new Error("unexpected abort");}});
    const expected=createHash("sha256");for(let i=0;i<130;i++)expected.update(new Uint8Array(CHUNK_SIZE));
    assert.equal(hash.digest("hex"),expected.digest("hex"));assert.equal(bytes,source.size);assert.equal(max,CHUNK_SIZE);assert.ok(closed);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test("oversized stream declarations are rejected before reading or deriving keys",async()=>{
  class Oversized extends Blob{get size(){return MAX_STREAM_PLAINTEXT_SIZE+1;}slice(){throw new Error("must not read");}}
  const sink=memorySink();await assert.rejects(encryptV3ToSink(new Oversized(),secret,options,sink),{code:"FILE_TOO_LARGE"});assert.ok(sink.aborted);
});
