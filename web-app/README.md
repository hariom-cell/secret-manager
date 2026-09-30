# Secret Manager — Web App

A browser-based interface for the Secret Manager vault. Uses the same Rust cryptographic core compiled to WASM.

## Build & Run

```bash
# 1. Install wasm-pack (one-time)
cargo install wasm-pack

# 2. Build the WASM module
cd crates/vault-wasm
wasm-pack build --target web --out-dir ../../web-app/pkg

# 3. Serve the web app
cd web-app
npx serve . -p 3000
# → Open http://localhost:3000
```

## What You Get

| Feature | Status |
|---------|--------|
| Create / Unlock vault | ✅ |
| Add / View / Delete secrets | ✅ |
| Password generator | ✅ |
| TOTP code generation | ✅ |
| Auto-lock timer | ✅ |
| Vault export | ✅ |
| Password change | ✅ |
| Encrypted localStorage | ✅ |

## Security

- All crypto runs in WASM — same Rust code as the desktop CLI
- Vault encrypted with XChaCha20-Poly1305
- Key derivation via Argon2id
- Master password never stored
- Vault auto-locks after configurable inactivity
- Vault file is an opaque encrypted blob — sync it via any cloud storage

## Browser Extension (Chrome/Firefox)

To package as a browser extension:

1. Build WASM: `wasm-pack build --target web`
2. Create `manifest.json` in web-app/:

```json
{
  "manifest_version": 3,
  "name": "Secret Manager",
  "version": "0.1.0",
  "permissions": ["storage"],
  "action": { "default_popup": "index.html" }
}
```

3. Load `web-app/` as an unpacked extension in `chrome://extensions`

## PWA (Mobile Install)

Add a `manifest.json` with `"display": "standalone"` and a service worker for offline caching. Install from Chrome on Android or Safari on iOS.
