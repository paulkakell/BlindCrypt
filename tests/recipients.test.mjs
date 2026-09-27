import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, privateDecrypt, publicEncrypt, constants, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { generateIdentity, importRecipient, unlockIdentity, encryptForRecipient, decryptForRecipient, recipientFingerprint, MAX_RECIPIENT_BYTES } from "../assets/recipients.js";
import { createMetadataBlock, concatBytes } from "../assets/crypto.js";
const secret="abandon ability able about above absent absorb abstract";
const other="access accident account accuse achieve acid acoustic acquire";
const generated=await generateIdentity(secret);
const recipient=await importRecipient(generated.publicKey);
const identity=await unlockIdentity(generated.privateBackup,secret);

test("identity exports public-only JWK and encrypted private backup; fingerprint is RFC7638",async()=>{
  const jwk=JSON.parse(generated.publicKey);assert.deepEqual(Object.keys(jwk).sort(),["e","kty","n"]);
  const expected=createHash("sha256").update(JSON.stringify({e:jwk.e,kty:jwk.kty,n:jwk.n})).digest("base64url");
  assert.equal(expected,generated.fingerprint);assert.equal(recipient.fingerprint,expected);assert.equal(identity.fingerprint,expected);
  assert.equal(identity.key.extractable,false);assert.equal(recipient.key.extractable,false);
  assert.ok(generated.privateBackup.size<16384);await assert.rejects(unlockIdentity(generated.privateBackup,other));
  await assert.rejects(generateIdentity("weak"));
});
test("recipient files round trip Unicode metadata and empty files; verification has no output",async()=>{
  for(const plain of["","private 😀"]){
    const encrypted=await encryptForRecipient(new Blob([plain]),recipient,{name:"日本語.txt",type:"text/plain"});
    const result=await decryptForRecipient(encrypted,identity);
    assert.equal(await result.blob.text(),plain);assert.equal(result.metadata.name,"日本語.txt");assert.equal(result.senderAuthenticated,false);
    assert.equal((await decryptForRecipient(encrypted,identity,{verifyOnly:true})).blob,null);
  }
});
test("JWE corruption, alternate algorithms, wrong keys, and noncanonical framing fail",async()=>{
  const encrypted=await encryptForRecipient(new Blob(["secret"]),recipient,{name:"x.txt",type:"text/plain"});
  const original=(await encrypted.text()).split(".");
  for(const index of[1,2,3,4]){
    const changed=[...original];changed[index]=(changed[index][0]==="A"?"B":"A")+changed[index].slice(1);
    await assert.rejects(decryptForRecipient(new Blob([changed.join(".")]),identity));
  }
  for(const alg of["RSA1_5","none","RSA-OAEP"]){
    const header=JSON.parse(Buffer.from(original[0],"base64url"));header.alg=alg;
    const changed=[Buffer.from(JSON.stringify(header)).toString("base64url"),...original.slice(1)];
    await assert.rejects(decryptForRecipient(new Blob([changed.join(".")]),identity));
  }
  await assert.rejects(decryptForRecipient(new Blob([await encrypted.text()+".extra"]),identity));
  await assert.rejects(decryptForRecipient(new Blob([await encrypted.text()+"="]),identity));
  await assert.rejects(decryptForRecipient(encrypted,{...identity,fingerprint:"different"}));
  const wrong=await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},false,["encrypt","decrypt"]);
  await assert.rejects(decryptForRecipient(encrypted,{...identity,key:wrong.privateKey}));
});
test("key and size restrictions fail before expensive encryption",async()=>{
  const jwk=JSON.parse(generated.publicKey);
  for(const altered of[{...jwk,d:"private"},{...jwk,e:"Aw"},{...jwk,kty:"EC"},{...jwk,n:"AA"}])await assert.rejects(importRecipient(JSON.stringify(altered)));
  await assert.rejects(importRecipient("x".repeat(2049)));
  class Large extends Blob{get size(){return MAX_RECIPIENT_BYTES+1;}arrayBuffer(){throw new Error("must not allocate");}}
  await assert.rejects(encryptForRecipient(new Large(),recipient,{name:"x",type:""}),{code:"FILE_TOO_LARGE"});
  const aborted=new AbortController();aborted.abort();
  await assert.rejects(encryptForRecipient(new Blob(["x"]),recipient,{name:"x",type:"",signal:aborted.signal}),{code:"CANCELLED"});
});
test("JWE is independently decryptable with Node classic crypto",async()=>{
  const pair=generateKeyPairSync("rsa",{modulusLength:3072,publicExponent:65537});
  const jwk=pair.publicKey.export({format:"jwk"});const external=await importRecipient(JSON.stringify({e:jwk.e,kty:jwk.kty,n:jwk.n}));
  const encoded=await encryptForRecipient(new Blob(["independent decryption"]),external,{name:"interop.txt",type:"text/plain"});
  const [protectedHeader,wrapped,iv,cipher,tag]=(await encoded.text()).split(".");
  const cek=privateDecrypt({key:pair.privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:"sha256"},Buffer.from(wrapped,"base64url"));
  const decipher=createDecipheriv("aes-256-gcm",cek,Buffer.from(iv,"base64url"));
  decipher.setAAD(Buffer.from(protectedHeader,"ascii"));decipher.setAuthTag(Buffer.from(tag,"base64url"));
  const plain=Buffer.concat([decipher.update(Buffer.from(cipher,"base64url")),decipher.final()]);
  assert.equal(plain.subarray(0,4).toString(),"BCR1");assert.equal(plain.subarray(1028).toString(),"independent decryption");cek.fill(0);plain.fill(0);
});
test("independently encrypted Node JWE opens in the browser implementation",async()=>{
  const jwk=JSON.parse(generated.publicKey);const key={key:jwk,format:"jwk",padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:"sha256"};
  const cek=randomBytes(32),iv=randomBytes(12);const header=Buffer.from(JSON.stringify({alg:"RSA-OAEP-256",enc:"A256GCM",cty:"application/vnd.blindcrypt.recipient-v1",kid:await recipientFingerprint(jwk)})).toString("base64url");
  const {block}=createMetadataBlock("external.txt","text/plain");const payload=concatBytes(Buffer.from("BCR1"),block,Buffer.from("outside producer"));
  const cipher=createCipheriv("aes-256-gcm",cek,iv);cipher.setAAD(Buffer.from(header));
  const encrypted=Buffer.concat([cipher.update(payload),cipher.final()]);
  const compact=[header,publicEncrypt(key,cek).toString("base64url"),iv.toString("base64url"),encrypted.toString("base64url"),cipher.getAuthTag().toString("base64url")].join(".");
  const result=await decryptForRecipient(new Blob([compact]),identity);assert.equal(await result.blob.text(),"outside producer");assert.equal(result.metadata.name,"external.txt");cek.fill(0);payload.fill(0);
});
