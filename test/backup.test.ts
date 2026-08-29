import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { appendIssuedLicenseRecord, copyBackupToICloud, createBackup, decryptPrivateKey, generateSigningKeyPair, encryptPrivateKey, issueLicense, rawPublicKey, restoreBackup } from '../src/index.js'

test('persists records and performs a complete new-machine restore', async () => {
  const root = await mkdtemp(join(tmpdir(), 'olm-backup-')), original = join(root, 'original'), restored = join(root, 'restored')
  const { mkdir } = await import('node:fs/promises'); await mkdir(original)
  const pair = generateSigningKeyPair(), localPassword = 'local-private-password', backupPassword = 'separate-backup-password'
  const encrypted = await encryptPrivateKey(pair.privateKeyPem, localPassword)
  const keyFile = join(original, 'signing-key.olmkey'), publicFile = join(original, 'public-key.json'), recordsFile = join(original, 'licenses.json'), backupFile = join(root, 'manual.olmbackup')
  await writeFile(keyFile, JSON.stringify({ kid: 'key-1', ...encrypted }))
  await writeFile(publicFile, JSON.stringify({ kid: 'key-1', publicKey: pair.publicKeyPem, publicKeyRaw: rawPublicKey(pair.publicKeyPem) }))
  const issued = issueLicense({ appId: 'app_lemon_note', majorVersion: 1, plan: 'pro', kid: 'key-1' }, pair.privateKeyPem)
  await appendIssuedLicenseRecord(recordsFile, { payload: issued.payload, code: issued.code, issuedAt: new Date().toISOString(), customer: 'Test' })
  await assert.rejects(() => appendIssuedLicenseRecord(recordsFile, { payload: issued.payload, code: issued.code, issuedAt: new Date().toISOString() }), /already exists/)
  const result = await createBackup({ appId: 'app_lemon_note', encryptedKeyFile: keyFile, publicKeyFile: publicFile, recordsFile, outputFile: backupFile, password: backupPassword })
  assert.equal(result.recordCount, 1)
  await assert.rejects(() => restoreBackup({ backupFile, destination: restored, password: 'incorrect-password', expectedAppId: 'app_lemon_note' }), /Incorrect backup password/)
  await assert.rejects(() => restoreBackup({ backupFile, destination: restored, password: backupPassword, expectedAppId: 'other_app' }), /another app/)
  const restoredResult = await restoreBackup({ backupFile, destination: restored, password: backupPassword, expectedAppId: 'app_lemon_note' })
  assert.equal(restoredResult.recordCount, 1)
  assert.equal(JSON.parse(await readFile(join(restored, 'licenses.json'), 'utf8'))[0].code, issued.code)
  const restoredEnvelope = JSON.parse(await readFile(join(restored, 'signing-key.olmkey'), 'utf8'))
  assert.equal(await decryptPrivateKey(restoredEnvelope, localPassword), pair.privateKeyPem)
  const cloud = await copyBackupToICloud({ backupFile, appId: 'app_lemon_note', iCloudRoot: join(root, 'iCloud Drive') })
  const cloudRestore = await restoreBackup({ backupFile: cloud.destination, destination: join(root, 'cloud-restored'), password: backupPassword, expectedAppId: 'app_lemon_note' })
  assert.equal(cloudRestore.recordCount, 1)
})
