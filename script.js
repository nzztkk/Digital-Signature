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
const processInputOutput = document.getElementById("processInputOutput");
const processBytesOutput = document.getElementById("processBytesOutput");
const processHashOutput = document.getElementById("processHashOutput");
const processSignOutput = document.getElementById("processSignOutput");
const processVerifyOutput = document.getElementById("processVerifyOutput");

const algo = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

let keyPair = null;
let signatureBuffer = null;
let signedHashHex = "";

function textToArrayBuffer(text) {
  return new TextEncoder().encode(text);
}

function formatHexPreview(hex, maxLen = 160) {
  if (hex.length <= maxLen) return hex;
  return `${hex.slice(0, maxLen)}...`;
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
  signedHashHex = "";
  processSignOutput.textContent =
    "Ключи готовы. Подпись еще не создана (ждем шаг «Подписать сообщение»).";
  processVerifyOutput.textContent = "Проверка еще не запускалась.";

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
  const dataHex = toHex(data);
  signedHashHex = toHex(digest);

  signatureBuffer = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    keyPair.privateKey,
    data
  );

  hashOutput.textContent = toHex(digest);
  signatureOutput.textContent = toBase64(signatureBuffer);
  processInputOutput.textContent = message || "(пустая строка)";
  processBytesOutput.textContent = formatHexPreview(dataHex);
  processHashOutput.textContent = signedHashHex;
  processSignOutput.textContent =
    "Подпись создана: S = Sign(privateKey, SHA-256(message)).\n\nBase64:\n" +
    toBase64(signatureBuffer);
  processVerifyOutput.textContent =
    "Подпись создана. Теперь нажми «Проверить подпись», чтобы увидеть итог.";
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
  const currentHashHex = toHex(digest);

  const isValid = await crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    keyPair.publicKey,
    signatureBuffer,
    data
  );

  hashOutput.textContent = currentHashHex;
  processInputOutput.textContent = message || "(пустая строка)";
  processBytesOutput.textContent = formatHexPreview(toHex(data));
  processHashOutput.textContent = currentHashHex;
  if (isValid) {
    processVerifyOutput.textContent =
      "Результат: VALID (подпись верна).\nТекущий хеш совпадает с подписанными данными.";
    setStatus("Подпись ВЕРНА. Сообщение не меняли.", "ok");
  } else {
    processVerifyOutput.textContent =
      "Результат: INVALID (подпись неверна).\nХеш при подписи: " +
      (signedHashHex || "неизвестно") +
      "\nХеш сейчас: " +
      currentHashHex +
      "\nВывод: данные изменились или подпись не от этого ключа.";
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
  processInputOutput.textContent = "Ожидание ввода сообщения...";
  processBytesOutput.textContent = "Пока не вычислено";
  processHashOutput.textContent = "Пока не вычислено";
  processSignOutput.textContent = "Пока не создано";
  processVerifyOutput.textContent = "Пока не проверено";
  signedHashHex = "";
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

messageInput.addEventListener("input", () => {
  processInputOutput.textContent = messageInput.value || "(пустая строка)";
});

resetDemo();
