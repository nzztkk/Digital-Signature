"use strict";

const el = (id) => document.getElementById(id);
const messageInput = el("messageInput");
const shaInput = el("shaInput");

const hashOutput = el("hashOutput");
const signatureOutput = el("signatureOutput");
const publicKeyOutput = el("publicKeyOutput");
const verifyProcessOutput = el("verifyProcessOutput");
const verifyStatus = el("verifyStatus");
const aesOutput = el("aesOutput");
const rsaEncryptOutput = el("rsaEncryptOutput");

const cellsOutput = el("cellsOutput");
const blocksOutput = el("blocksOutput");
const scheduleOutput = el("scheduleOutput");
const roundsOutput = el("roundsOutput");
const digestOutput = el("digestOutput");

const flowNodes = [...document.querySelectorAll(".flow-node")];
const flowLog = el("flowLog");

let signatureKeys = null;
let signatureBuffer = null;
let signedHash = "";
let rsaOaepKeys = null;
let flowIndex = 0;

const rsaPssAlgo = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

function textToBytes(text) {
  return new TextEncoder().encode(text);
}
function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}
function setStatus(text, mode = "neutral") {
  verifyStatus.textContent = text;
  verifyStatus.className = `status ${mode}`;
}
function setFlowState(idx) {
  flowIndex = idx;
  const names = ["raw", "hashed", "signed", "transmitted", "verified"];
  flowNodes.forEach((n, i) => n.classList.toggle("active", i === idx));
  flowLog.textContent = `Состояние: ${names[idx]}`;
}
function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}
function add32(...nums) {
  return nums.reduce((acc, n) => (acc + n) >>> 0, 0);
}
function toHex32(n) {
  return (n >>> 0).toString(16).padStart(8, "0");
}
async function sha256(text) {
  return crypto.subtle.digest("SHA-256", textToBytes(text));
}

function sha256Detailed(message) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const input = textToBytes(message);
  const bitLen = input.length * 8;
  const bytes = [...input, 0x80];
  while (bytes.length % 64 !== 56) bytes.push(0);
  const hi = Math.floor(bitLen / 2 ** 32);
  const lo = bitLen >>> 0;
  bytes.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255);
  bytes.push((lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);

  const wPreview = [];
  const rounds = [];
  for (let offset = 0; offset < bytes.length; offset += 64) {
    const chunk = bytes.slice(offset, offset + 64);
    const w = Array(64).fill(0);
    for (let t = 0; t < 16; t += 1) {
      const i = t * 4;
      w[t] = (chunk[i] << 24) | (chunk[i + 1] << 16) | (chunk[i + 2] << 8) | chunk[i + 3];
    }
    for (let t = 16; t < 64; t += 1) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = add32(w[t - 16], s0, w[t - 7], s1);
    }
    if (offset === 0) for (let i = 0; i < 16; i += 1) wPreview.push(`W[${i}] = 0x${toHex32(w[i])}`);

    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = add32(h, s1, ch, K[t], w[t]);
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = add32(s0, maj);
      h = g; g = f; f = e; e = add32(d, temp1); d = c; c = b; b = a; a = add32(temp1, temp2);
      if (offset === 0 && (t < 5 || t > 58)) rounds.push(`t=${t} a=${toHex32(a)} e=${toHex32(e)} T1=${toHex32(temp1)}`);
    }
    H = [add32(H[0], a), add32(H[1], b), add32(H[2], c), add32(H[3], d), add32(H[4], e), add32(H[5], f), add32(H[6], g), add32(H[7], h)];
  }
  return { input, bytes, bitLen, blocks: bytes.length / 64, wPreview, rounds, hashHex: H.map(toHex32).join("") };
}

async function runShaModule() {
  const msg = shaInput.value;
  const d = sha256Detailed(msg);
  const native = toHex(await sha256(msg));
  cellsOutput.textContent = `UTF-8 bytes (${d.input.length}):\n${toHex(d.input).slice(0, 256)}...`;
  blocksOutput.textContent = `Битовая длина: ${d.bitLen}\nПосле padding: ${d.bytes.length} bytes\n512-битных блоков: ${d.blocks}`;
  scheduleOutput.textContent = d.wPreview.join("\n");
  roundsOutput.textContent = d.rounds.join("\n");
  digestOutput.textContent = `manual: ${d.hashHex}\nwebcrypto: ${native}\nсовпадение: ${d.hashHex === native}`;
}

async function generateSignatureKeys() {
  setStatus("Генерация RSA-PSS ключей...", "neutral");
  signatureKeys = await crypto.subtle.generateKey(rsaPssAlgo, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", signatureKeys.publicKey);
  publicKeyOutput.textContent = JSON.stringify(pub, null, 2);
  el("signBtn").disabled = false;
  setStatus("Ключи готовы. Подпишите сообщение.", "neutral");
}

async function signMessage() {
  const msg = messageInput.value;
  const data = textToBytes(msg);
  const digest = await sha256(msg);
  signedHash = toHex(digest);
  signatureBuffer = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, signatureKeys.privateKey, data);
  hashOutput.textContent = signedHash;
  signatureOutput.textContent = toBase64(signatureBuffer);
  verifyProcessOutput.textContent = "Подпись создана: s = Sign(sk, H(m))";
  el("verifyBtn").disabled = false;
  el("tamperBtn").disabled = false;
}

async function verifySignature() {
  const msg = messageInput.value;
  const data = textToBytes(msg);
  const currentHash = toHex(await sha256(msg));
  const valid = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, signatureKeys.publicKey, signatureBuffer, data);
  hashOutput.textContent = currentHash;
  verifyProcessOutput.textContent = `signed hash: ${signedHash}\ncurrent hash: ${currentHash}\nverify: ${valid}`;
  setStatus(valid ? "VALID: подпись корректна." : "INVALID: данные изменены или подпись чужая.", valid ? "ok" : "bad");
}

function tamperBit() {
  const t = messageInput.value || "x";
  const c = t.charCodeAt(0) ^ 1;
  messageInput.value = String.fromCharCode(c) + t.slice(1);
  setStatus("Изменен 1 бит первого символа. Проверьте подпись повторно.", "neutral");
}

async function runAes() {
  const msg = messageInput.value;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textToBytes(msg));
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, enc);
  aesOutput.textContent = `iv: ${toHex(iv)}\ncipher(base64): ${toBase64(enc)}\nplain: ${new TextDecoder().decode(dec)}`;
}

async function runRsaOaep() {
  const msg = messageInput.value;
  if (!rsaOaepKeys) {
    rsaOaepKeys = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["encrypt", "decrypt"]
    );
  }
  const enc = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaOaepKeys.publicKey, textToBytes(msg));
  const dec = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaOaepKeys.privateKey, enc);
  rsaEncryptOutput.textContent = `cipher(base64): ${toBase64(enc)}\nplain: ${new TextDecoder().decode(dec)}`;
}

function flowStep() {
  setFlowState(Math.min(flowIndex + 1, flowNodes.length - 1));
}
function flowReset() {
  setFlowState(0);
}
async function flowPlay() {
  flowReset();
  for (let i = 1; i < flowNodes.length; i += 1) {
    await new Promise((r) => setTimeout(r, 450));
    setFlowState(i);
  }
}
function resetAll() {
  messageInput.value = "Exam answer v1: cryptography report";
  hashOutput.textContent = "Ожидание...";
  signatureOutput.textContent = "Ожидание...";
  publicKeyOutput.textContent = "Ожидание...";
  verifyProcessOutput.textContent = "Ожидание...";
  aesOutput.textContent = "Ожидание...";
  rsaEncryptOutput.textContent = "Ожидание...";
  digestOutput.textContent = "Ожидание...";
  cellsOutput.textContent = "Ожидание...";
  blocksOutput.textContent = "Ожидание...";
  scheduleOutput.textContent = "Ожидание...";
  roundsOutput.textContent = "Ожидание...";
  setStatus("Ожидание...", "neutral");
  flowReset();
  el("signBtn").disabled = true;
  el("verifyBtn").disabled = true;
  el("tamperBtn").disabled = true;
  signatureKeys = null;
  signatureBuffer = null;
  signedHash = "";
}

el("shaAnimateBtn").addEventListener("click", () =>
  runShaModule().catch((e) => {
    digestOutput.textContent = e.message;
  })
);
el("flowPlayBtn").addEventListener("click", flowPlay);
el("flowStepBtn").addEventListener("click", flowStep);
el("flowResetBtn").addEventListener("click", flowReset);
el("generateKeysBtn").addEventListener("click", () => generateSignatureKeys().catch((e) => setStatus(e.message, "bad")));
el("signBtn").addEventListener("click", () => signMessage().catch((e) => setStatus(e.message, "bad")));
el("verifyBtn").addEventListener("click", () => verifySignature().catch((e) => setStatus(e.message, "bad")));
el("tamperBtn").addEventListener("click", tamperBit);
el("runAesBtn").addEventListener("click", () => runAes().catch((e) => (aesOutput.textContent = e.message)));
el("runRsaEncryptBtn").addEventListener("click", () => runRsaOaep().catch((e) => (rsaEncryptOutput.textContent = e.message)));
el("resetBtn").addEventListener("click", resetAll);

resetAll();
