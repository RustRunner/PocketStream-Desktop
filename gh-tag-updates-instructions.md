# PocketStream Desktop — Signed Release & Auto-Updater Setup

## First-Time Setup

### 1. Generate a signed keypair

```powershell
npx tauri signer generate -w src-tauri/.tauri-signing-key --password "your-passphrase-here"
```

Copy the **public key** from the output and update it in `src-tauri/tauri.conf.json` under `plugins.updater.pubkey`.

### 2. Store secrets in GitHub

```powershell
gh secret set TAURI_SIGNING_PRIVATE_KEY < src-tauri/.tauri-signing-key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD
```

The second command prompts for input — paste your passphrase and press Enter.

### 3. Commit, tag, and push

```powershell
git add -A
git commit -m "v0.1.4: Add auto-updater, CI pipeline, graceful error handling, credential redaction"
git tag v0.1.4
git push origin main --tags
```

### 4. Publish the release

Go to GitHub → Releases → review the draft → Publish.

Existing installs will detect the update on next launch.

---

## Subsequent Releases

For future versions, bump the version in these files:

- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`
- `package.json`
- `index.html` (about panel)

Then:

```powershell
git add -A
git commit -m "v0.X.Y: description of changes"
git tag v0.X.Y
git push origin main --tags
```

Review and publish the draft release on GitHub. The updater endpoint (`latest.json`) is updated automatically when the release is published.

---

## Local Signed Build (optional)

To build a signed installer locally without CI:

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content src-tauri/.tauri-signing-key -Raw
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "your-passphrase-here"
npx tauri build
```

Output: `src-tauri/target/release/bundle/nsis/`

---

## Key Files

| File | Purpose |
|------|---------|
| `src-tauri/.tauri-signing-key` | Private signing key (gitignored, never commit) |
| `src-tauri/.tauri-signing-key.pub` | Public key (embedded in tauri.conf.json) |
| `.github/workflows/release.yml` | CI release workflow (triggers on `v*` tags) |
| `.github/workflows/ci.yml` | CI checks (triggers on push/PR to main) |
| `src-tauri/tauri.conf.json` | Contains updater pubkey and endpoint |
