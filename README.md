# BlindCrypt

BlindCrypt is a static web app for client-side file encryption and decryption. Your passphrase and plaintext stay in your browser.

## Features

- Encrypt a file with a passphrase and download a `.blindcrypt` file
- Decrypt a `.blindcrypt` file with the passphrase and download the original
- Passphrase generator with adjustable security levels
- Versioned file format for future compatibility

## Security model

- Encryption and decryption occur locally via WebCrypto
- Server only hosts static files
- If the endpoint is compromised (malware, hostile browser extensions), no web app can protect the data

## Algorithms

- Cipher: AES-256-GCM (authenticated encryption)
- KDF: PBKDF2 with SHA-256
- Randomness: `crypto.getRandomValues`

This starter uses PBKDF2 to remain dependency-free for GitHub Pages. For stronger GPU-resistant derivation, replace PBKDF2 with Argon2id via WASM.

## Passphrase word list

BlindCrypt uses the 2048 word BIP39 English word list (bundled in `assets/wordlist.js`).

## File format

```
[4 bytes big-endian header length][header JSON UTF-8][ciphertext bytes]
```

The header contains version, KDF parameters, salt, IV, and original filename/type.

## Run locally

Use a local web server (recommended):

```bash
python -m http.server 8080
```

Then visit `http://localhost:8080`.

## Host on GitHub Pages

1. Push this repo to GitHub
2. Settings -> Pages
3. Source: Deploy from a branch
4. Branch: `main` and folder `/root`
5. Save

## License

MIT
