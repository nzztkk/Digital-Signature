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
const stateTableBody = el("stateTableBody");
const memoryGrid = el("memoryGrid");
const diffuseLog = el("diffuseLog");
const dbgBase = el("dbgBase");
const dbgExp = el("dbgExp");
const dbgMod = el("dbgMod");
const dbgRegisters = el("dbgRegisters");
const dbgTraceBody = el("dbgTraceBody");
const dbgOp = el("dbgOp");
const dbgResult = el("dbgResult");
const dbgBaseReg = el("dbgBaseReg");
const dbgExpReg = el("dbgExpReg");
const dbgModReg = el("dbgModReg");

const flowNodes = [...document.querySelectorAll(".flow-node")];
const flowLog = el("flowLog");

let signatureKeys = null;
let signatureBuffer = null;
let signedHash = "";
let rsaOaepKeys = null;
let flowIndex = 0;
let stateStep = 0;
let memoryBits = [];
let diffusionRound = 0;
let dbgSteps = [];
let dbgIndex = 0;
let dbgTimer = null;

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
function chunkHex(hex, chunkSize = 8, lineChunks = 4) {
  const chunks = [];
  for (let i = 0; i < hex.length; i += chunkSize) chunks.push(hex.slice(i, i + chunkSize));
  const lines = [];
  for (let i = 0; i < chunks.length; i += lineChunks) lines.push(chunks.slice(i, i + lineChunks).join(" "));
  return lines.join("\n");
}
function previewText(text, max = 120) {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}...`;
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
function addStateRow(object, state, key, result) {
  stateStep += 1;
  const tr = document.createElement("tr");
  tr.innerHTML = `<td>${stateStep}</td><td>${object}</td><td>${state}</td><td>${key}</td><td>${result}</td>`;
  stateTableBody.appendChild(tr);
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
  const inputHex = toHex(d.input);
  const inputPreviewHex = inputHex.length > 256 ? `${inputHex.slice(0, 256)}...` : inputHex;

  cellsOutput.textContent =
    `Исходный текст (${msg.length} симв.):\n"${previewText(msg)}"\n\n` +
    `UTF-8 размер: ${d.input.length} байт\n` +
    `Первые байты (hex):\n${chunkHex(inputPreviewHex, 8, 3)}`;

  blocksOutput.textContent =
    `Битовая длина сообщения: ${d.bitLen}\n` +
    `После padding: ${d.bytes.length} байт\n` +
    `Количество 512-битных блоков: ${d.blocks}\n\n` +
    `Что сделано:\n` +
    `- Добавлен бит "1"\n` +
    `- Добавлены нули до 448 mod 512\n` +
    `- Добавлена исходная длина (64 бита)`;

  scheduleOutput.textContent =
    `Первые слова расписания первой порции:\n\n` +
    d.wPreview.join("\n");

  roundsOutput.textContent =
    `Показаны контрольные раунды (первые и последние):\n\n` +
    d.rounds.join("\n");

  digestOutput.textContent =
    `Digest (ручная реализация):\n${chunkHex(d.hashHex, 8, 4)}\n\n` +
    `Digest (WebCrypto):\n${chunkHex(native, 8, 4)}\n\n` +
    `Совпадение: ${d.hashHex === native ? "ДА" : "НЕТ"}`;
  addStateRow("SHA Engine", "raw bytes -> padded blocks -> digest", "none", d.hashHex);
}

async function generateSignatureKeys() {
  setStatus("Генерация RSA-PSS ключей...", "neutral");
  signatureKeys = await crypto.subtle.generateKey(rsaPssAlgo, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", signatureKeys.publicKey);
  publicKeyOutput.textContent = JSON.stringify(pub, null, 2);
  el("signBtn").disabled = false;
  setStatus("Ключи готовы. Подпишите сообщение.", "neutral");
  addStateRow("KeyGen", "generated RSA-PSS keypair", "entropy + rsa-pss", "pk/sk created");
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
  addStateRow("Signature", `h=${signedHash.slice(0, 16)}...`, "private key (sk)", "signature s created");
}

async function verifySignature() {
  const msg = messageInput.value;
  const data = textToBytes(msg);
  const currentHash = toHex(await sha256(msg));
  const valid = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, signatureKeys.publicKey, signatureBuffer, data);
  hashOutput.textContent = currentHash;
  verifyProcessOutput.textContent = `signed hash: ${signedHash}\ncurrent hash: ${currentHash}\nverify: ${valid}`;
  setStatus(valid ? "VALID: подпись корректна." : "INVALID: данные изменены или подпись чужая.", valid ? "ok" : "bad");
  addStateRow("Verify", `recomputed h=${currentHash.slice(0, 16)}...`, "public key (pk)", valid ? "valid" : "invalid");
}

function tamperBit() {
  const t = messageInput.value || "x";
  const c = t.charCodeAt(0) ^ 1;
  messageInput.value = String.fromCharCode(c) + t.slice(1);
  setStatus("Изменен 1 бит первого символа. Проверьте подпись повторно.", "neutral");
  addStateRow("Tamper", "bit flip applied to payload", "none", "payload mutated");
}

async function runAes() {
  const msg = messageInput.value;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textToBytes(msg));
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, enc);
  aesOutput.textContent = `iv: ${toHex(iv)}\ncipher(base64): ${toBase64(enc)}\nplain: ${new TextDecoder().decode(dec)}`;
  addStateRow("AES-GCM", "plaintext -> ciphertext -> plaintext", "AES session key", "confidentiality + integrity");
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
  addStateRow("RSA-OAEP", "plaintext -> ciphertext -> plaintext", "pk then sk", "asymmetric encryption OK");
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
    await new Promise((r) => setTimeout(r, 700));
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
  stateTableBody.innerHTML = "";
  stateStep = 0;
  memoryGrid.innerHTML = "";
  diffuseLog.textContent = "Ожидание инициализации...";
  dbgOp.textContent = "-";
  dbgResult.textContent = "-";
  dbgBaseReg.textContent = "-";
  dbgExpReg.textContent = "-";
  dbgModReg.textContent = "-";
  dbgTraceBody.innerHTML = "";
  setStatus("Ожидание...", "neutral");
  flowReset();
  el("signBtn").disabled = true;
  el("verifyBtn").disabled = true;
  el("tamperBtn").disabled = true;
  signatureKeys = null;
  signatureBuffer = null;
  signedHash = "";
  if (dbgTimer) {
    clearInterval(dbgTimer);
    dbgTimer = null;
  }
  dbgSteps = [];
  dbgIndex = 0;
}

function renderMemoryBits() {
  memoryGrid.innerHTML = "";
  memoryBits.forEach((bit) => {
    const div = document.createElement("div");
    div.className = `mem-cell ${bit ? "one" : ""}`;
    div.textContent = bit ? "1" : "0";
    memoryGrid.appendChild(div);
  });
}

function initDiffusion() {
  const src = textToBytes(messageInput.value || "A");
  const first8 = [...src.slice(0, 8)];
  while (first8.length < 8) first8.push(0);
  memoryBits = [];
  first8.forEach((byte) => {
    for (let i = 7; i >= 0; i -= 1) memoryBits.push((byte >> i) & 1);
  });
  diffusionRound = 0;
  renderMemoryBits();
  diffuseLog.textContent = "Round 0: исходное распределение битов в 64 ячейках.";
}

function diffusionStep() {
  if (!memoryBits.length) initDiffusion();
  const next = new Array(memoryBits.length).fill(0);
  for (let i = 0; i < memoryBits.length; i += 1) {
    const srcIdx = (i * 13 + 7) % memoryBits.length;
    const neighbor = memoryBits[(srcIdx + 1) % memoryBits.length];
    next[i] = memoryBits[srcIdx] ^ neighbor ^ (i % 3 === 0 ? 1 : 0);
  }
  memoryBits = next;
  diffusionRound += 1;
  renderMemoryBits();
  const ones = memoryBits.reduce((a, b) => a + b, 0);
  diffuseLog.textContent = `Round ${diffusionRound}: активных бит= ${ones}, визуально структура становится шумоподобной.`;
}

async function diffusionAuto() {
  for (let i = 0; i < 6; i += 1) {
    diffusionStep();
    await new Promise((r) => setTimeout(r, 420));
  }
}

function buildModExpTrace(base, exp, mod) {
  const steps = [];
  let result = 1 % mod;
  let b = base % mod;
  let e = exp;
  steps.push({ op: "init", result, b, e });
  while (e > 0) {
    steps.push({ op: "check-bit", result, b, e, bit: e & 1 });
    if (e & 1) {
      result = (result * b) % mod;
      steps.push({ op: "mul", result, b, e });
    }
    b = (b * b) % mod;
    e = Math.floor(e / 2);
    steps.push({ op: "square-shift", result, b, e });
  }
  return steps;
}

function renderDbgStep() {
  if (!dbgSteps.length) return;
  const s = dbgSteps[Math.min(dbgIndex, dbgSteps.length - 1)];
  dbgOp.textContent = s.op;
  dbgResult.textContent = String(s.result);
  dbgBaseReg.textContent = String(s.b);
  dbgExpReg.textContent = String(s.e);
  dbgModReg.textContent = String(dbgMod.value);

  dbgTraceBody.innerHTML = "";
  dbgSteps.slice(0, dbgIndex + 1).forEach((st, i) => {
    const tr = document.createElement("tr");
    if (i === dbgIndex) tr.classList.add("active-step");
    tr.innerHTML = `
      <td>${i}</td>
      <td>${st.op}</td>
      <td>${st.result}</td>
      <td>${st.b}</td>
      <td>${st.e}</td>
      <td>${st.bit !== undefined ? st.bit : "-"}</td>
    `;
    dbgTraceBody.appendChild(tr);
  });
}

function dbgInit() {
  const base = Number(dbgBase.value);
  const exp = Number(dbgExp.value);
  const mod = Number(dbgMod.value);
  if (!Number.isFinite(base) || !Number.isFinite(exp) || !Number.isFinite(mod) || mod <= 1 || exp < 0) {
    dbgOp.textContent = "ошибка";
    dbgResult.textContent = "Некорректные параметры";
    return;
  }
  dbgSteps = buildModExpTrace(base, exp, mod);
  dbgIndex = 0;
  renderDbgStep();
}

function dbgStep() {
  if (!dbgSteps.length) dbgInit();
  dbgIndex = Math.min(dbgIndex + 1, dbgSteps.length - 1);
  renderDbgStep();
}

function dbgPlayPause() {
  if (dbgTimer) {
    clearInterval(dbgTimer);
    dbgTimer = null;
    return;
  }
  if (!dbgSteps.length) dbgInit();
  dbgTimer = setInterval(() => {
    if (dbgIndex >= dbgSteps.length - 1) {
      clearInterval(dbgTimer);
      dbgTimer = null;
      return;
    }
    dbgStep();
  }, 460);
}

function dbgReset() {
  if (dbgTimer) {
    clearInterval(dbgTimer);
    dbgTimer = null;
  }
  dbgSteps = [];
  dbgIndex = 0;
  dbgOp.textContent = "-";
  dbgResult.textContent = "-";
  dbgBaseReg.textContent = "-";
  dbgExpReg.textContent = "-";
  dbgModReg.textContent = "-";
  dbgTraceBody.innerHTML = "";
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
el("diffuseInitBtn").addEventListener("click", initDiffusion);
el("diffuseStepBtn").addEventListener("click", diffusionStep);
el("diffuseAutoBtn").addEventListener("click", () => diffusionAuto().catch(() => {}));
el("dbgInitBtn").addEventListener("click", dbgInit);
el("dbgStepBtn").addEventListener("click", dbgStep);
el("dbgPlayBtn").addEventListener("click", dbgPlayPause);
el("dbgResetBtn").addEventListener("click", dbgReset);

resetAll();
