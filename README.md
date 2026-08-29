# Offline License Manager

A zero-server license toolkit for desktop, mobile, Mini Program, and other offline-first apps. It issues compact licenses signed with Ed25519 and verifies them locally with public keys embedded in the app.

## What is included

- Core license envelope and strict payload validation
- Ed25519 key generation, signing, and verification
- Password-encrypted private-key storage using Argon2id and AES-256-GCM
- SDK client with `valid`, `plan`, and `hasFeature()`
- CLI for key generation, issuing, and verification
- Multiple public keys selected by `kid` for safe key rotation

There is no server, account system, telemetry, remote revocation, version entity, semver range, or payload encryption.

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
  --plan pro \
  --features excel-export,unlimited-roster
```

The password option is convenient for local testing but can appear in shell history. A local manager UI should collect it through a password field; production CLI integration should provide a secret-input wrapper.

## SDK

```ts
import { createLicenseClient } from '@yu-ren/offline-license-manager'

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

## Design contract

See [License_Manager_Plan.md](License_Manager_Plan.md). The current SDK uses Node's crypto API. Apps without Node compatibility can implement the same `OLM1` wire format with any conforming Ed25519 library.

## Security

Never commit `.olmkey` files, plaintext private keys, real licenses, passwords, or customer records. The public key is intentionally safe to embed in an app. Offline licensing cannot revoke a license in real time and cannot stop a determined attacker from patching an app binary.

## License

MIT
