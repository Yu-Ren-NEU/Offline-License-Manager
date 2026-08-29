# License Manager v1 — Final Implementation Plan

## 1. Status and intent

This document is the implementation contract for v1. License Manager is a reusable, fully offline signing platform. It creates trustworthy license credentials; each business app remains responsible for deciding what its plans, features, and releases do.

The v1 system has zero server components, zero required network calls, and no hosted database. A future server may be added as an optional v2 extension, but it must not be required by or silently enter the v1 design.

## 2. Goals

- Issue licenses locally for multiple independent apps.
- Verify licenses entirely inside a business app.
- Authorize one exact product major generation using a simple integer.
- Support a simple plan-only mode and an optional fine-grained feature mode.
- Keep signing private keys only in the owner's local manager.
- Support multiple verification keys through `kid`, allowing safe key rotation.
- Publish core, cryptography, SDK, and CLI as a standalone public repository.
- Permit an optional local-only manager UI without changing the protocol.

## 3. Non-goals

v1 does not provide:

- a server, cloud database, account system, hosted admin panel, or telemetry;
- remote activation, online payment reconciliation, or device attestation;
- real-time revocation or a global list of used licenses;
- a `Version` entity, semantic-version ranges, upgrade policies, or release catalogs;
- automatic interpretation of plan names or feature names;
- payload confidentiality or DRM against a determined reverse engineer.

## 4. Responsibility boundary

### License Platform

The platform owns:

- the payload schema and license wire format;
- Ed25519 key generation, signing, and verification;
- encrypted local storage of private keys;
- strict validation of signature, `kid`, `appId`, `majorVersion`, and expiry;
- ergonomic SDK results and CLI workflows.

### Business App

Each integrating app owns:

- its stable `appId`;
- its current major-version integer;
- the meaning of `plan` and each feature identifier;
- UI and behavior for valid, invalid, mismatched, and expired licenses;
- storage of the user's license code;
- its commercial upgrade and compatibility policy.

The platform must not contain a product version catalog or infer feature behavior.

## 5. Architecture

```text
Local manager machine                         End-user business app

core + crypto + CLI/UI                        core + SDK
        |                                         |
encrypted private key                             embedded public key set
        |                                         |
sign payload -> license code  --------copy------> verify locally
```

Required v1 modules:

- `core`: types, strict schema validation, base64url encoding, envelope parsing.
- `crypto`: Ed25519 operations and encrypted private-key files.
- `sdk`: app-bound verification and entitlement helpers.
- `cli`: key generation, license issuing, and diagnostic verification.

The local manager UI is multi-App: its home screen creates, lists, and restores Apps; each App then has its own signing, records, and backup workspace. It calls the shared modules, binds only to loopback, makes no outbound requests, and stores no plaintext private key. A random per-process session token protects its local JSON API.

## 6. App and key model

Every app has one stable `appId`, for example `app_lemon_note`. It has at least one Ed25519 signing key pair:

- the private key exists only in the local manager and signs licenses;
- the public key is embedded in the business app and verifies licenses;
- `kid` identifies the signing key used for a license.

An app may trust several public keys simultaneously. `kid` is generated automatically by the Manager and is not an ordinary App-creation input:

```ts
const publicKeys = {
  '2026-01': oldPublicKey,
  '2027-01': newPublicKey
}
```

Key rotation is a two-stage publish workflow. The Manager first creates a pending key and exports the combined old/new public-key set. The business App must include and release that set before the Manager allows the operator to confirm the new active signing key. Rotation never overwrites the old key: old public and encrypted private keys remain in the keyring and backups so old licenses continue to verify. A key must never be reused across unrelated apps unless the owner deliberately accepts the larger blast radius.

## 7. Payload

The canonical v1 payload is:

```ts
type LicensePayload = {
  licenseId: string
  appId: string
  majorVersion: number
  plan?: string
  features?: string[]
  issuedAt: number
  expiresAt?: number
  kid: string
}
```

Rules:

- `licenseId` is a unique opaque identifier, normally a UUID.
- `appId` is a stable, non-empty product identifier.
- `majorVersion` is a positive safe integer and matches one exact app major.
- `plan` is an optional non-empty opaque string such as `pro`.
- `features` is an optional de-duplicated set of opaque feature identifiers.
- `issuedAt` and `expiresAt` are integer Unix timestamps in seconds.
- `expiresAt` is absent for a perpetual license.
- `kid` is a non-empty identifier resolved against the app's trusted public-key set.
- Unknown fields are rejected in v1 so accidental schema drift fails visibly.

There is deliberately no `versionRange`, `versionPolicy`, `minVersion`, `maxVersion`, `semver`, `Version` entity, or `maxMajorVersion`.

### Authorization modes

Simple plan mode:

```json
{
  "licenseId": "bfa01fa8-7a6a-4bc2-9508-87f08923e82c",
  "appId": "app_lemon_note",
  "majorVersion": 1,
  "plan": "pro",
  "issuedAt": 1788019200,
  "kid": "2026-01"
}
```

Fine-grained feature mode adds, or uses instead of `plan`:

```json
"features": ["excel-export", "unlimited-roster"]
```

The platform does not expand `pro` into features and does not require features for plan licenses.

## 8. Wire format and signing

The license code is:

```text
OLM1.<base64url(UTF-8 canonical JSON)>.<base64url(Ed25519 signature)>
```

The Ed25519 signature covers the ASCII bytes of the encoded payload segment exactly. Base64url is unpadded. Canonical serialization uses a fixed field order and sorted feature identifiers.

The payload is signed but not encrypted. It contains entitlements, not secrets. Encryption would not hide data from the verifying app and would add key-management risk without improving license authenticity.

## 9. SDK contract

Initialization binds a client to an app and one current major version:

```ts
const client = createLicenseClient({
  appId: 'app_lemon_note',
  majorVersion: 1,
  publicKeys: {
    '2026-01': publicKey
  }
})
```

`verify(code)` performs, in order:

1. envelope, base64url, JSON, and payload-schema validation;
2. public-key lookup by `kid`;
3. Ed25519 signature verification;
4. exact `appId` equality;
5. exact `majorVersion` equality;
6. expiry check, where `now >= expiresAt` is expired.

Valid results expose:

```ts
{
  valid: true,
  payload,
  plan,
  hasFeature(featureId): boolean
}
```

Invalid results expose `valid: false`, a stable reason code, a display-safe message, and `hasFeature()` returning false. Expected reason codes are `malformed`, `invalid_payload`, `unknown_key`, `invalid_signature`, `app_mismatch`, `major_version_mismatch`, and `expired`.

The SDK never decides that `plan === 'pro'` unlocks a particular feature. Business code makes that decision:

```ts
const result = client.verify(savedCode)
if (result.valid && result.plan === 'pro') enableProFeatures()
if (result.valid && result.hasFeature('excel-export')) enableExcelExport()
```

## 10. Backup & Recovery

Backup and recovery are mandatory v1 capabilities. A manager is not production-ready until its key, public-key configuration, and complete issuance ledger can be recovered on another machine without a server.

### 10.1 Local private-key protection

Private keys are PKCS#8 Ed25519 keys encrypted at rest with:

- Argon2id password derivation;
- a random 128-bit or larger salt per key file;
- a 256-bit derived key;
- AES-256-GCM;
- a random 96-bit IV per encryption;
- the GCM authentication tag stored with the ciphertext.

The v1 implementation uses Argon2id with 64 MiB memory, three iterations, and parallelism one. Parameters are stored in the envelope so they can be strengthened later. Key files use owner-only permissions where the operating system supports them.

Passwords and plaintext keys must never be written to logs, records, repositories, backups, or crash reports. Decryption failure must not overwrite existing data. The local manager persists only the encrypted `.olmkey` envelope and decrypts it in memory for signing.

### 10.2 Persistent issuance ledger

Every successful issue operation must be recorded before it is reported as complete. The append-only logical record contains the complete signed payload, final license code, UTC issuance time, and optional customer/note metadata. Records use `licenseId` as their unique key and are written atomically with owner-only permissions.

The ledger is operational data, not part of license verification. Losing it does not invalidate customer licenses, but it destroys the owner's audit and re-delivery history; it is therefore a required backup component.

### 10.3 Complete encrypted backup format

A `.olmbackup` is a single portable, authenticated envelope containing:

- the already-encrypted local private-key record;
- the public-key record and `kid`;
- the complete issued-license ledger;
- `appId`, format version, creation time, and consistency metadata.

The whole backup payload is independently encrypted with AES-256-GCM using a 256-bit key derived from the backup password with Argon2id. Each backup gets a new random salt and IV. KDF parameters, salt, IV, and authentication tag are stored in the outer envelope. This second encryption layer protects customer metadata and license codes as well as the encrypted signing key.

Creating a backup must first verify that the encrypted private-key record and public-key record have the same `kid`. A backup is not successful until the complete file has been atomically written and can be decrypted and validated.

### 10.4 Two independent backup channels

v1 supports both:

1. **iCloud Drive copy:** copy a completed `.olmbackup` into `iCloud Drive/Offline License Manager/<appId>/Backups/` with a timestamped filename.
2. **Manual offline export:** save the same `.olmbackup` to a user-selected external drive, encrypted archive, or other offline medium.

iCloud is a convenience channel, not the backup system and never the only copy. The recommended minimum is one current iCloud copy plus one current offline copy on separate storage. Backup passwords must be held separately, ideally in a password manager and an offline recovery record.

No sync provider receives plaintext keys, plaintext records, or the backup password. Backup and restore make no network request; copying into the local iCloud Drive folder is an ordinary filesystem operation whose later synchronization is performed by macOS.

### 10.5 Full restore on a new machine

The new-machine recovery flow is:

1. Install a supported Node runtime and this CLI from a trusted release or verified source checkout.
2. Obtain one `.olmbackup` from either the manual offline copy or the locally synchronized iCloud Drive folder.
3. Run `backup-restore` with the expected `appId`, destination manager-data directory, and backup password.
4. Derive the backup key with the stored Argon2id parameters and authenticate/decrypt with AES-256-GCM.
5. Validate format version, `appId`, `kid`, encrypted-key format, public-key record, and ledger structure before writing anything.
6. Write `signing-key.olmkey`, `public-key.json`, and `licenses.json` atomically with restrictive permissions.
7. Unlock the restored `.olmkey` using its local-key password and confirm its derived public key matches the restored public-key record.
8. Issue a disposable test license and verify it with the restored public key before resuming real issuance.
9. Immediately create fresh iCloud and manual offline backups from the restored machine.

Wrong passwords, damaged authentication tags, mismatched apps/keys, incomplete files, or invalid records must abort without partially replacing an existing installation. Restore targets should be empty; overwriting an active manager requires an explicit UI confirmation and a safety backup.

## 11. CLI

The CLI provides:

- `keygen`: create an Ed25519 pair, encrypt the private key, and export a public-key record containing `kid`;
- `issue`: decrypt a selected local key and sign a validated payload;
- `verify`: verify a code for an explicit `appId` and major version using one or more public-key records.
- `backup-export`: create a complete encrypted `.olmbackup` for manual offline storage;
- `backup-icloud`: copy an encrypted backup to the app's iCloud Drive backup directory;
- `backup-restore`: authenticate, validate, and restore a complete backup on a new machine.

The CLI must fail with a non-zero exit status on verification or input failure. Production wrappers should collect passwords through hidden input or an OS secret store; passing a password as an argument is only a minimal integration interface and may expose it in shell history.

## 12. Local records and optional UI

Customer, payment, and issuance records are local manager metadata and are not part of the signed protocol. They must be persisted in a local file or database keyed by `licenseId`. A UI must clearly separate business records from signed payload fields.

The UI provides App creation, key generation or existing-key import, in-memory unlock/lock, license issue, history, automatic encrypted snapshots, independent offline export, iCloud copy, and complete new-machine restore. App creation and every successful issuance trigger an automatic encrypted snapshot while the unlock password remains only in process memory. iCloud Drive is the default copy destination when present; otherwise macOS folder selection establishes a user-chosen destination. It must not implement its own cryptography or payload serializer; it calls the shared modules.

## 13. Revocation and offline limitations

An issued perpetual offline license behaves like a signed paper ticket. With no server, an already shipped app cannot learn that the owner later marked that license revoked. v1 therefore cannot provide real-time revocation.

Mitigations available within v1 are limited to short expiries, shipping a new app build with changed policy, and ceasing to trust a compromised key for future builds. Removing an old public key also invalidates every license signed by it and is not a selective revocation mechanism.

A future optional v2 server may provide revocation lists, activation limits, synchronization, and payment integration. Those capabilities require explicit online behavior and must remain an additive layer; v1 offline verification continues to work independently.

## 14. Security requirements

- Never embed or commit a private key.
- Never accept a payload before verifying its signature.
- Resolve `kid` only from a locally configured allowlist; never fetch a key from the license.
- Compare `appId` and `majorVersion` exactly.
- Treat plan and feature identifiers as untrusted strings until signature verification succeeds.
- Put practical limits on code and payload size in app integrations.
- Preserve old trusted public keys during planned rotation.
- Do not claim offline licensing prevents binary patching, source modification, clock rollback, or license copying where the app provides no device binding.

Device binding is intentionally absent from the common v1 payload. A product needing it may define a future separately reviewed extension; it must not overload `licenseId` or `appId`.

## 15. Tests and acceptance criteria

Automated tests must cover:

- issue and verify for plan-only, feature-only, combined, perpetual, and expiring licenses;
- tampered payload and signature;
- malformed envelope, JSON, base64url, and schema;
- wrong app and wrong major version;
- unknown and rotated `kid` values;
- exact expiry boundary;
- private-key encrypt/decrypt round trip, wrong password, and damaged ciphertext;
- atomic issued-license record persistence and duplicate rejection;
- complete backup creation and restore, including every issued record;
- wrong backup password, damaged backup, mismatched `appId`, and inconsistent `kid` rejection;
- iCloud copy and manual offline export using the same encrypted backup format;
- stable canonical serialization and duplicate feature handling.

v1 is complete when:

- the package builds from a clean checkout;
- all tests pass on the supported Node version;
- CLI key generation, issue, and verify complete end to end;
- a clean-machine restore can sign a test license that the original public key verifies;
- documented iCloud and manual offline backup copies can both restore the same state;
- repository history contains no private key, real license, customer record, or password;
- README examples match the exported API;
- a second app can use the package without Lemon Note-specific source changes.

## 16. Lemon Note reference integration

Lemon Note should integrate as:

```ts
createLicenseClient({
  appId: 'app_lemon_note',
  majorVersion: CURRENT_MAJOR_VERSION,
  publicKeys
})
```

The pre-release Lemon Note integration was reset to this contract: its product-specific `maxMajorVersion`, installation request code, permanent flag, and shared version catalog were removed. It accepts only `OLM1` licenses and uses `plan === 'pro'` or explicit feature identifiers for business behavior.

Released products with an older protocol must make their own explicit migration decision; the generic library never silently reinterprets legacy payloads.
