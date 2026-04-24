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
const advancedInput = document.getElementById("advancedInput");
const analyzeShaBtn = document.getElementById("analyzeShaBtn");
const runAesBtn = document.getElementById("runAesBtn");
const runRsaEncryptBtn = document.getElementById("runRsaEncryptBtn");
const shaPrepOutput = document.getElementById("shaPrepOutput");
const shaScheduleOutput = document.getElementById("shaScheduleOutput");
const shaRoundsOutput = document.getElementById("shaRoundsOutput");
const shaFinalOutput = document.getElementById("shaFinalOutput");
const aesOutput = document.getElementById("aesOutput");
const rsaEncryptOutput = document.getElementById("rsaEncryptOutput");

const algo = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

let keyPair = null;
let signatureBuffer = null;
let signedHashHex = "";
let rsaEncryptPair = null;

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

function formatBytesHex(bytes, group = 4) {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0"));
  const grouped = [];
  for (let i = 0; i < hex.length; i += group) {
    grouped.push(hex.slice(i, i + group).join(" "));
  }
  return grouped.join("\n");
}

function toHex32(num) {
  return (num >>> 0).toString(16).padStart(8, "0");
}

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function add32(...nums) {
  return nums.reduce((acc, n) => (acc + n) >>> 0, 0);
}

function sha256Detailed(message) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const inputBytes = new TextEncoder().encode(message);
  const bitLen = inputBytes.length * 8;
  const bytes = [...inputBytes, 0x80];
  while ((bytes.length % 64) !== 56) bytes.push(0x00);
  const high = Math.floor(bitLen / 2 ** 32);
  const low = bitLen >>> 0;
  bytes.push((high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff);
  bytes.push((low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff);

  const roundLogs = [];
  const scheduleLogs = [];

  for (let chunkStart = 0; chunkStart < bytes.length; chunkStart += 64) {
    const chunk = bytes.slice(chunkStart, chunkStart + 64);
    const w = new Array(64).fill(0);
    for (let t = 0; t < 16; t += 1) {
      const i = t * 4;
      w[t] =
        (chunk[i] << 24) |
        (chunk[i + 1] << 16) |
        (chunk[i + 2] << 8) |
        chunk[i + 3];
    }
    for (let t = 16; t < 64; t += 1) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = add32(w[t - 16], s0, w[t - 7], s1);
    }

    if (chunkStart === 0) {
      for (let i = 0; i < 20; i += 1) {
        scheduleLogs.push(`W[${i}] = 0x${toHex32(w[i])}`);
      }
    }

    let [a, b, c, d, e, f, g, h] = H;

    for (let t = 0; t < 64; t += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = add32(h, S1, ch, K[t], w[t]);
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = add32(S0, maj);

      h = g;
      g = f;
      f = e;
      e = add32(d, temp1);
      d = c;
      c = b;
      b = a;
      a = add32(temp1, temp2);

      if (chunkStart === 0 && (t < 6 || t >= 58)) {
        roundLogs.push(
          `t=${t}: a=${toHex32(a)} b=${toHex32(b)} c=${toHex32(c)} d=${toHex32(d)} e=${toHex32(e)} f=${toHex32(f)} g=${toHex32(g)} h=${toHex32(h)}`
        );
      }
    }

    H = [
      add32(H[0], a),
      add32(H[1], b),
      add32(H[2], c),
      add32(H[3], d),
      add32(H[4], e),
      add32(H[5], f),
      add32(H[6], g),
      add32(H[7], h),
    ];
  }

  const hashHex = H.map((v) => toHex32(v)).join("");
  return {
    inputBytes,
    paddedBytesLength: bytes.length,
    chunks: bytes.length / 64,
    bitLen,
    scheduleLogs,
    roundLogs,
    hashHex,
  };
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
  if (shaPrepOutput) shaPrepOutput.textContent = "Ожидание запуска...";
  if (shaScheduleOutput) shaScheduleOutput.textContent = "Ожидание запуска...";
  if (shaRoundsOutput) shaRoundsOutput.textContent = "Ожидание запуска...";
  if (shaFinalOutput) shaFinalOutput.textContent = "Ожидание запуска...";
  if (aesOutput) aesOutput.textContent = "Ожидание запуска...";
  if (rsaEncryptOutput) rsaEncryptOutput.textContent = "Ожидание запуска...";
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

if (analyzeShaBtn) {
  analyzeShaBtn.addEventListener("click", async () => {
    try {
      const text = advancedInput.value;
      const details = sha256Detailed(text);
      const nativeDigest = await sha256(text);
      const nativeHex = toHex(nativeDigest);
      const same = details.hashHex === nativeHex;

      shaPrepOutput.textContent =
        `message = "${text}"\n` +
        `байт (UTF-8): ${details.inputBytes.length}\n` +
        `битовая длина: ${details.bitLen}\n` +
        `после padding: ${details.paddedBytesLength} байт\n` +
        `блоков по 512 бит: ${details.chunks}\n\n` +
        `Первые байты (hex):\n${formatBytesHex(details.inputBytes).slice(0, 800)}`;
      shaScheduleOutput.textContent = details.scheduleLogs.join("\n");
      shaRoundsOutput.textContent =
        "Показаны первые 6 и последние 6 раундов первой 512-битной порции:\n\n" +
        details.roundLogs.join("\n");
      shaFinalOutput.textContent =
        `Реализация (ручная):\n${details.hashHex}\n\n` +
        `WebCrypto (браузер):\n${nativeHex}\n\n` +
        `Совпадение: ${same ? "да" : "нет"}`;
    } catch (error) {
      shaFinalOutput.textContent = `Ошибка SHA-анализа: ${error.message}`;
    }
  });
}

if (runAesBtn) {
  runAesBtn.addEventListener("click", async () => {
    try {
      const text = advancedInput.value;
      const data = textToArrayBuffer(text);
      const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, data);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encrypted);
      const decoded = new TextDecoder().decode(decrypted);

      aesOutput.textContent =
        `Алгоритм: AES-GCM (256 бит)\n` +
        `IV (hex): ${toHex(iv)}\n` +
        `Открытый текст: ${text}\n` +
        `Шифртекст+тег (Base64): ${toBase64(encrypted)}\n` +
        `После дешифрования: ${decoded}\n` +
        `Совпадение: ${decoded === text ? "да" : "нет"}`;
    } catch (error) {
      aesOutput.textContent = `Ошибка AES-GCM: ${error.message}`;
    }
  });
}

if (runRsaEncryptBtn) {
  runRsaEncryptBtn.addEventListener("click", async () => {
    try {
      const text = advancedInput.value;
      if (!rsaEncryptPair) {
        rsaEncryptOutput.textContent = "Генерируем RSA-OAEP ключи для шифрования...";
        rsaEncryptPair = await crypto.subtle.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          },
          true,
          ["encrypt", "decrypt"]
        );
      }

      const data = textToArrayBuffer(text);
      const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaEncryptPair.publicKey,
        data
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        rsaEncryptPair.privateKey,
        encrypted
      );
      const decoded = new TextDecoder().decode(decrypted);

      rsaEncryptOutput.textContent =
        `Алгоритм: RSA-OAEP (SHA-256)\n` +
        `Открытый текст: ${text}\n` +
        `Шифртекст (Base64): ${toBase64(encrypted)}\n` +
        `После дешифрования: ${decoded}\n` +
        `Совпадение: ${decoded === text ? "да" : "нет"}\n\n` +
        `Примечание: RSA обычно шифрует короткие данные (часто ключ AES), а не большие файлы.`;
    } catch (error) {
      rsaEncryptOutput.textContent = `Ошибка RSA-OAEP: ${error.message}`;
    }
  });
}

resetDemo();
