# WebEnc

WebEnc is a static, client-side tool for encrypting short secrets and encoding them as QR codes, with built-in decryption using the same password.

## What it does
- Derives an AES-256-GCM key from your password via PBKDF2-HMAC-SHA256 (150k iterations).
- Encrypts up to ~2 KB of plaintext, outputs a base64url blob, and generates a QR containing a URL fragment (`#d=<blob>`).
- Decrypts locally with your password; no server calls, no data persistence.

## Why the fragment?
- The encrypted payload lives in the URL fragment (hash), which is not sent to servers during HTTP requests. Everything stays in the browser; nothing is stored or transmitted beyond your device.

## Typical use case
- Securely store 2FA recovery/restore codes: paste the codes, encrypt with a known password, print the QR, and keep it in a safe place. To recover, scan the QR, open the page, enter the password, and decrypt locally.

## How to use
1) Open `index.html` in your browser (or visit the hosted version at http://dropfile.me).
2) Enter your secret (<= 2 KB) and password.
3) Click “Encrypt & share” to get the base64url blob plus a QR code.
4) Save/print the QR (or copy/download the image).
5) To decrypt, open the page with the `#d=` fragment or paste the blob, enter the password, and click “Decrypt”.

All encryption/decryption happens entirely on the client side. Keep your password safe—without it, the encrypted blob cannot be recovered.
