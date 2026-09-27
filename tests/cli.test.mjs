import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, readdir, rm, symlink, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
import { parseArgs, secretFromStream } from "../cli/blindcrypt.mjs";
import { atomicSink } from "../cli/io.mjs";
import { encryptBlobV3, decryptBlobAny, APP_VERSION } from "../assets/crypto.js";
import { createLegacyV1 } from "./helpers.mjs";
const secret="abandon ability able about above absent absorb abstract";
const script=resolve("cli/blindcrypt.mjs");
function command(args,input="",cwd){return new Promise((resolveResult,reject)=>{
  const child=spawn(process.execPath,[script,...args],{cwd,stdio:["pipe","pipe","pipe"]});let stdout="",stderr="";
  child.stdout.on("data",(bytes)=>stdout+=bytes);child.stderr.on("data",(bytes)=>stderr+=bytes);child.once("error",reject);
  child.once("close",(code)=>resolveResult({code,stdout,stderr}));child.stdin.on("error",()=>{});child.stdin.end(input);
});}
test("CLI arguments reject secrets, unknown/duplicate options, and unsupported combinations",()=>{
  for(const args of[["encrypt","--passphrase",secret],["encrypt","--input","x","--input","y"],["verify","--input","x","--output","y"],["encrypt","--input","x","--level","invalid"],["encrypt","--input","x","--recipient","key"],["keygen","--output","x"]])assert.throws(()=>parseArgs(args));
  assert.equal(parseArgs(["encrypt","--input","x"]).command,"encrypt");
});
test("secret stdin preserves spaces and accepts only one bounded UTF-8 line",async()=>{
  assert.equal(await secretFromStream(Readable.from([Buffer.from("  value  \r\n") ])),"  value  ");
  for(const bytes of[Buffer.from("two\nlines\n"),Buffer.from("\n"),Buffer.from("x".repeat(1027)),Buffer.from([255]),Buffer.from("bad\0value")])await assert.rejects(secretFromStream(Readable.from([bytes])));
});
test("CLI browser interoperability, verify, legacy reading, and no overwrite",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"blindcrypt-cli-"));
  try{
    const input=join(dir,"private document.txt"),encrypted=join(dir,"encrypted"),out=join(dir,"plain");await writeFile(input,"CLI browser shared bytes");
    let result=await command(["encrypt","--input",input,"--output",encrypted,"--level","standard","--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);assert.doesNotMatch(result.stdout,/private document|abandon/u);
    const blob=new Blob([await readFile(encrypted)]);assert.equal(await (await decryptBlobAny(blob,secret)).blob.text(),"CLI browser shared bytes");
    result=await command(["verify","--input",encrypted,"--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);assert.match(result.stdout,/integrity-verified/u);
    result=await command(["decrypt","--input",encrypted,"--output",out,"--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);assert.equal(await readFile(out,"utf8"),"CLI browser shared bytes");assert.equal((await stat(out)).mode&0o777,0o600);
    result=await command(["decrypt","--input",encrypted,"--output",out,"--passphrase-stdin"],secret+"\n");assert.equal(result.code,1);assert.match(result.stderr,/OUTPUT_EXISTS/u);
    const browser=await encryptBlobV3(new Blob(["browser producer"]),secret,{name:"safe.txt",type:"text/plain",levelKey:"standard"});await writeFile(encrypted,new Uint8Array(await browser.blob.arrayBuffer()));
    result=await command(["decrypt","--input",encrypted,"--output",join(dir,"browser-out"),"--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);assert.equal(await readFile(join(dir,"browser-out"),"utf8"),"browser producer");
    const legacy=await createLegacyV1(new TextEncoder().encode("legacy"),"old");await writeFile(join(dir,"legacy"),new Uint8Array(await legacy.arrayBuffer()));
    result=await command(["decrypt","--input",join(dir,"legacy"),"--output",join(dir,"legacy-out"),"--passphrase-stdin"],"old\n");assert.equal(result.code,0,result.stderr);assert.match(result.stdout,/LEGACY_INTEGRITY_LIMITATIONS/u);
    result=await command(["verify","--input",join(dir,"legacy"),"--passphrase-stdin"],"old\n");assert.equal(result.code,1);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test("atomic output refuses races and symlinks, abort removes partial files",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"blindcrypt-atomic-"));
  try{
    const output=join(dir,"output"),sink=await atomicSink(output);await sink.write(new Uint8Array([1,2,3]));await writeFile(output,"existing");
    await assert.rejects(sink.close(),{code:"EEXIST"});await sink.abort();assert.equal(await readFile(output,"utf8"),"existing");
    assert.deepEqual(await readdir(dir),["output"]);
    await symlink(output,join(dir,"link"));await assert.rejects(atomicSink(join(dir,"link")),{code:"OUTPUT_EXISTS"});
    const partial=await atomicSink(join(dir,"partial"));await partial.write(new Uint8Array([1]));await partial.abort();assert.deepEqual((await readdir(dir)).sort(),["link","output"]);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test("wrong passphrase leaves neither destination nor temporary plaintext",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"blindcrypt-failed-"));
  try{
    const encrypted=await encryptBlobV3(new Blob(["secret content"]),secret,{name:"x",type:"",levelKey:"standard"});await writeFile(join(dir,"input"),new Uint8Array(await encrypted.blob.arrayBuffer()));
    const result=await command(["decrypt","--input",join(dir,"input"),"--output",join(dir,"output"),"--passphrase-stdin"],"wrong\n");assert.equal(result.code,1);assert.deepEqual(await readdir(dir),["input"]);assert.doesNotMatch(result.stderr,/secret content|wrong|abandon/u);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test("CLI recipient keygen, fingerprint confirmation, encrypt/decrypt/verify",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"blindcrypt-recipient-cli-"));
  try{
    const backup=join(dir,"identity.bckey"),publicKey=join(dir,"public.json"),source=join(dir,"document"),encrypted=join(dir,"recipient.jwe"),out=join(dir,"restored");
    let result=await command(["keygen","--output",backup,"--public-output",publicKey,"--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);const fingerprint=JSON.parse(result.stdout).fingerprint;
    await writeFile(source,"recipient CLI interop");
    result=await command(["encrypt","--input",source,"--output",encrypted,"--recipient",publicKey,"--fingerprint",fingerprint]);assert.equal(result.code,0,result.stderr);
    result=await command(["verify","--input",encrypted,"--identity",backup,"--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);
    result=await command(["decrypt","--input",encrypted,"--output",out,"--identity",backup,"--passphrase-stdin"],secret+"\n");assert.equal(result.code,0,result.stderr);assert.equal(await readFile(out,"utf8"),"recipient CLI interop");
    assert.equal(JSON.parse(result.stdout).senderAuthenticated,false);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test("CLI version and usage are deterministic",async()=>{
  assert.equal((await command(["--version"])).stdout,APP_VERSION+"\n");
  assert.equal((await command(["unknown"])).code,2);
});
