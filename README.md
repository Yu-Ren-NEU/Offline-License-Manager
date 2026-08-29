# Offline License Manager

A zero-server license toolkit for desktop, mobile, Mini Program, and other offline-first apps. It issues compact licenses signed with Ed25519 and verifies them locally with public keys embedded in the app.

## What is included

- Core license envelope and strict payload validation
- Ed25519 key generation, signing, and verification
- Password-encrypted private-key storage using Argon2id and AES-256-GCM
- SDK client with `valid`, `plan`, and `hasFeature()`
- CLI for key generation, issuing, and verification
- Local-only graphical manager for setup, unlock, issue history, backup, and restore
- Multiple public keys selected by `kid` for safe key rotation

There is no server, account system, telemetry, remote revocation, version entity, semver range, or payload encryption.

## Local Manager UI

Install once:

```bash
npm install -g @ben0918/offline-license-manager
```

Start a manager bound only to this Mac:

```bash
offline-license manager \
  --app app_lemon_note \
  --major 1 \
  --kid lemon-2026-01 \
  --expected-public-key i-Sop6wjh-4WkfONZw-ycYvti4LmdluuRLSaFj7gHUY \
  --import-key "$HOME/Library/Application Support/Lemon Point Note License Manager/private-key.pem"
```

The browser opens automatically at a tokenized `127.0.0.1` URL. On first launch, paste the existing PKCS#8 Ed25519 private-key PEM or generate a key for a new app, then choose a password of at least 12 characters. The UI never writes the plaintext key to disk and keeps the decrypted key only in process memory until locked or closed.

Manager data defaults to:

```text
~/Library/Application Support/Offline License Manager/<appId>/
```

The UI creates every license record before reporting issuance success. It can produce a complete manual `.olmbackup`, copy that encrypted backup to iCloud Drive, and restore a selected backup on a new machine.

## Install and test

```bash
npm install
npm test
```

## CLI quick start

```bash
npm run build

node dist/src/cli.js keygen \
  --kid 2026-01 \
  --private .local/lemon.olmkey \
  --public .local/lemon.public.json \
  --password 'replace-with-a-long-password'

node dist/src/cli.js issue \
  --key .local/lemon.olmkey \
  --password 'replace-with-a-long-password' \
  --app app_lemon_note \
  --major 1 \
  --records .local/licenses.json \
  --plan pro \
  --features excel-export,unlimited-roster
```

The password option is convenient for local testing but can appear in shell history. A local manager UI should collect it through a password field; production CLI integration should provide a secret-input wrapper.

## SDK

```ts
import { createLicenseClient } from '@ben0918/offline-license-manager'

const license = createLicenseClient({
  appId: 'app_lemon_note',
  majorVersion: 1,
  publicKeys: {
    '2026-01': `-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n`
  }
})

const result = license.verify(userSuppliedCode)
if (result.valid && result.plan === 'pro') enablePro()
if (result.valid && result.hasFeature('excel-export')) enableExport()
```

The SDK checks the signature, `kid`, `appId`, exact `majorVersion`, and optional expiry. Business code decides what plans and features mean.

For WeChat Mini Programs, vendor `miniprogram/index.js` and provide a TweetNaCl-compatible implementation plus raw public keys from the generated public-key record. This adapter has no Node.js dependency.

## Backup and recovery

Create a complete encrypted backup containing the encrypted signing key, public-key record, and all issued-license records:

```bash
offline-license backup-export --app app_lemon_note \
  --key .local/lemon.olmkey \
  --public .local/lemon.public.json \
  --records .local/licenses.json \
  --output /Volumes/OfflineBackup/lemon.olmbackup \
  --password 'a-separate-backup-password'

offline-license backup-icloud --app app_lemon_note \
  --backup /Volumes/OfflineBackup/lemon.olmbackup

offline-license backup-restore \
  --app app_lemon_note \
  --backup /path/to/lemon.olmbackup \
  --destination .local \
  --password 'a-separate-backup-password'
```

The whole `.olmbackup` is protected by Argon2id and AES-256-GCM. Keep at least one iCloud copy and one manual offline copy on separate storage; iCloud must never be the only backup. Restore is fully local and requires no server.

## Design contract

See [License_Manager_Plan.md](License_Manager_Plan.md). The current SDK uses Node's crypto API. Apps without Node compatibility can implement the same `OLM1` wire format with any conforming Ed25519 library.

## Security

Never commit `.olmkey` files, plaintext private keys, real licenses, passwords, or customer records. The public key is intentionally safe to embed in an app. Offline licensing cannot revoke a license in real time and cannot stop a determined attacker from patching an app binary.

## License

MIT
