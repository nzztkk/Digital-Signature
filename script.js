"use strict";

const generateKeysBtn = document.getElementById("generateKeysBtn");
const signBtn = document.getElementById("signBtn");
const verifyBtn = document.getElementById("verifyBtn");
const tamperBtn = document.getElementById("tamperBtn");
const resetBtn = document.getElementById("resetBtn");

const messageInput = document.getElementById("messageInput");
const hashOutput = document.getElementById("hashOutput");
const signatureOutput = document.getElementById("signatureOutput");
const publicKeyOutput = document.getElementById("publicKeyOutput");
const verifyStatus = document.getElementById("verifyStatus");

const algo = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

let keyPair = null;
let signatureBuffer = null;

function textToArrayBuffer(text) {
  return new TextEncoder().encode(text);
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

async function sha256(text) {
  const data = textToArrayBuffer(text);
  return crypto.subtle.digest("SHA-256", data);
}

function setStatus(text, mode = "neutral") {
  verifyStatus.textContent = text;
  verifyStatus.className = `status ${mode}`;
}

function setControls({
  canSign = false,
  canVerify = false,
  canTamper = false,
} = {}) {
  signBtn.disabled = !canSign;
  verifyBtn.disabled = !canVerify;
  tamperBtn.disabled = !canTamper;
}

async function generateKeys() {
  setStatus("Генерируем ключи... Это может занять пару секунд.", "neutral");
  keyPair = await crypto.subtle.generateKey(algo, true, ["sign", "verify"]);
  const exportedPublicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  publicKeyOutput.textContent = JSON.stringify(exportedPublicKey, null, 2);
  signatureOutput.textContent = "Подпись пока не создана";
  hashOutput.textContent = "Хеш пока не вычислен";
  signatureBuffer = null;

  setControls({ canSign: true, canVerify: false, canTamper: false });
  setStatus("Ключи готовы. Теперь подпиши сообщение.", "neutral");
}

async function signMessage() {
  if (!keyPair) {
    setStatus("Сначала нужно сгенерировать ключи.", "bad");
    return;
  }

  const message = messageInput.value;
  const digest = await sha256(message);
  const data = textToArrayBuffer(message);

  signatureBuffer = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    keyPair.privateKey,
    data
  );

  hashOutput.textContent = toHex(digest);
  signatureOutput.textContent = toBase64(signatureBuffer);
  setControls({ canSign: true, canVerify: true, canTamper: true });
  setStatus("Подпись создана. Нажми «Проверить подпись».", "neutral");
}

async function verifySignature() {
  if (!keyPair || !signatureBuffer) {
    setStatus("Сначала создай ключи и подпись.", "bad");
    return;
  }

  const message = messageInput.value;
  const data = textToArrayBuffer(message);
  const digest = await sha256(message);

  const isValid = await crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    keyPair.publicKey,
    signatureBuffer,
    data
  );

  hashOutput.textContent = toHex(digest);
  if (isValid) {
    setStatus("Подпись ВЕРНА. Сообщение не меняли.", "ok");
  } else {
    setStatus("Подпись НЕВЕРНА. Текст изменен или подпись чужая.", "bad");
  }
}

function tamperMessage() {
  messageInput.value = `${messageInput.value.trim()} [добавили лишний текст]`;
  setStatus("Сообщение изменено. Попробуй снова проверить подпись.", "neutral");
}

function resetDemo() {
  keyPair = null;
  signatureBuffer = null;
  messageInput.value = "Привет! Это мое важное сообщение.";
  hashOutput.textContent = "Пока не вычислен";
  signatureOutput.textContent = "Пока не создана";
  publicKeyOutput.textContent = "Пока не создан";
  setControls({ canSign: false, canVerify: false, canTamper: false });
  setStatus("Ожидание...", "neutral");
}

generateKeysBtn.addEventListener("click", async () => {
  try {
    await generateKeys();
  } catch (error) {
    setStatus(`Ошибка генерации ключей: ${error.message}`, "bad");
  }
});

signBtn.addEventListener("click", async () => {
  try {
    await signMessage();
  } catch (error) {
    setStatus(`Ошибка подписи: ${error.message}`, "bad");
  }
});

verifyBtn.addEventListener("click", async () => {
  try {
    await verifySignature();
  } catch (error) {
    setStatus(`Ошибка проверки: ${error.message}`, "bad");
  }
});

tamperBtn.addEventListener("click", () => {
  tamperMessage();
});

resetBtn.addEventListener("click", () => {
  resetDemo();
});

resetDemo();
