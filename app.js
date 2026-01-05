(() => {
  const MAX_BYTES = 2048;
  const ITERATIONS = 150000;
  const SALT_LEN = 32;
  const IV_LEN = 12;

  const plaintextEl = document.getElementById("plaintext");
  const passwordEl = document.getElementById("password");
  const encryptedEl = document.getElementById("encrypted");
  const messageEl = document.getElementById("message");
  const decryptBtn = document.getElementById("decryptBtn");
  const clearBtn = document.getElementById("clearBtn");
  const qrEl = document.getElementById("qr");
  const copyQrBtn = document.getElementById("copyQrBtn");
  const downloadQrBtn = document.getElementById("downloadQrBtn");
  const encryptBtn = document.getElementById("encryptBtn");
  const togglePasswordBtn = document.getElementById("togglePassword");
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let qr;

  encryptBtn.addEventListener("click", async () => {
    setMessage("");
    encryptBtn.disabled = true;
    try {
      await handleEncrypt();
    } catch (err) {
      console.error(err);
      setMessage("Encryption failed. Check console for details.", true);
    } finally {
      encryptBtn.disabled = false;
    }
  });

  decryptBtn.addEventListener("click", async () => {
    setMessage("");
    decryptBtn.disabled = true;
    try {
      await handleDecrypt();
    } catch (err) {
      console.error(err);
      setMessage("Decryption failed. Check password and data.", true);
    } finally {
      decryptBtn.disabled = false;
    }
  });

  togglePasswordBtn.addEventListener("click", () => {
    const isHidden = passwordEl.type === "password";
    passwordEl.type = isHidden ? "text" : "password";
    const eyeIcon = document.getElementById("eyeIcon");
    if (eyeIcon) eyeIcon.textContent = isHidden ? "🙈" : "👁️";
    togglePasswordBtn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
  });

  clearBtn.addEventListener("click", () => {
    plaintextEl.value = "";
    passwordEl.value = "";
    encryptedEl.value = "";
    passwordEl.type = "password";
    const eyeIcon = document.getElementById("eyeIcon");
    if (eyeIcon) eyeIcon.textContent = "👁️";
    togglePasswordBtn.setAttribute("aria-label", "Show password");
    decryptBtn.classList.add("hidden");
    qrEl.innerHTML = '<span style="color: var(--muted); font-size: 14px;">QR code</span>';
    messageEl.textContent = "";
    messageEl.className = "";
  });

  copyQrBtn.addEventListener("click", async () => {
    const canvas = qrEl.querySelector("canvas");
    if (!canvas) {
      setMessage("No QR available to copy.", true);
      return;
    }
    copyQrBtn.disabled = true;
    try {
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
      if (!blob) throw new Error("Failed to render QR");
      if (!navigator.clipboard || !navigator.clipboard.write) throw new Error("Clipboard API not available");
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      setMessage("QR image copied to clipboard.");
    } catch (err) {
      console.error(err);
      setMessage("Could not copy QR. Check browser permissions.", true);
    } finally {
      copyQrBtn.disabled = false;
    }
  });

  downloadQrBtn.addEventListener("click", async () => {
    const canvas = qrEl.querySelector("canvas");
    if (!canvas) {
      setMessage("No QR available to download.", true);
      return;
    }
    downloadQrBtn.disabled = true;
    try {
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
      if (!blob) throw new Error("Failed to render QR");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "webenc-qr.png";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setMessage("QR downloaded.");
    } catch (err) {
      console.error(err);
      setMessage("Could not download QR.", true);
    } finally {
      downloadQrBtn.disabled = false;
    }
  });

  function setMessage(text, isError = false) {
    messageEl.textContent = text;
    messageEl.className = isError ? "error" : "";
  }

  function bufferToBase64(buf) {
    let binary = "";
    const bytes = new Uint8Array(buf);
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function bufferToBase64Url(buf) {
    return bufferToBase64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToUint8(str) {
    let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function concatUint8(...arrays) {
    const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    arrays.forEach((arr) => {
      out.set(arr, offset);
      offset += arr.length;
    });
    return out;
  }

  async function deriveKey(password, salt, usages = ["encrypt", "decrypt"]) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      usages
    );
  }

  async function handleEncrypt() {
    const plaintext = plaintextEl.value;
    const password = passwordEl.value;
    if (!plaintext) {
      setMessage("Add some text to encrypt.", true);
      return;
    }
    if (!password) {
      setMessage("Password is required.", true);
      return;
    }

    const data = encoder.encode(plaintext);
    if (data.length > MAX_BYTES) {
      setMessage(`Input is ${data.length} bytes. Limit is ${MAX_BYTES} bytes.`, true);
      return;
    }

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(password, salt);
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

    const payload = concatUint8(salt, iv, new Uint8Array(cipherBuf));
    const base64url = bufferToBase64Url(payload.buffer);
    encryptedEl.value = base64url;
    const shareUrl = `${location.origin}${location.pathname}#d=${base64url}`;
    renderQr(shareUrl);
    showDecryptButton();
  }

  async function handleDecrypt() {
    const cipherText = encryptedEl.value.trim();
    const password = passwordEl.value;
    if (!cipherText) {
      setMessage("No encrypted data provided.", true);
      return;
    }
    if (!password) {
      setMessage("Password is required.", true);
      return;
    }
    let payload;
    try {
      payload = base64UrlToUint8(cipherText);
    } catch (err) {
      setMessage("Encrypted data is not valid base64url.", true);
      throw err;
    }
    if (payload.length <= SALT_LEN + IV_LEN) {
      setMessage("Encrypted data is too short.", true);
      return;
    }
    const salt = payload.slice(0, SALT_LEN);
    const iv = payload.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const data = payload.slice(SALT_LEN + IV_LEN);
    const key = await deriveKey(password, salt);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    plaintextEl.value = decoder.decode(plainBuf);
    setMessage(`Decrypted ${data.length} bytes.`, false);
  }

  function renderQr(text) {
    qrEl.innerHTML = "";
    const paddingAllowance = 32;
    const size = Math.max((qrEl.clientWidth || 260) - paddingAllowance, 180);
    if (!window.QRCode || !QRCode.CorrectLevel) {
      setMessage("QR library failed to load. Check your network.", true);
      return;
    }
    qr = new QRCode(qrEl, {
      text,
      width: size,
      height: size,
      correctLevel: QRCode.CorrectLevel.L,
      colorDark: "#000000",
      colorLight: "#ffffff",
    });
  }

  function showDecryptButton() {
    decryptBtn.classList.remove("hidden");
  }

  function prefillFromFragment() {
    const hash = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
    if (!hash) return;
    const raw = hash.startsWith("d=") ? hash.slice(2) : hash;
    const value = decodeURIComponent(raw || "");
    if (!value) return;
    encryptedEl.value = value;
    showDecryptButton();
    setMessage("Loaded encrypted blob from URL. Enter password to decrypt.");
  }

  prefillFromFragment();

})();
