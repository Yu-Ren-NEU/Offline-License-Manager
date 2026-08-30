#!/usr/bin/env node
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { createPublicKey } from 'node:crypto'
import { Command } from 'commander'
import { decryptPrivateKey, encryptPrivateKey, generateSigningKeyPair, rawPublicKey } from './crypto.js'
import { issueLicense } from './issuer.js'
import { createLicenseClient } from './sdk.js'
import { appendIssuedLicenseRecord, copyBackupToICloud, createBackup, restoreBackup } from './backup.js'
import { startManager } from './manager.js'

const program = new Command().name('offline-license').description('Zero-server Ed25519 license manager').version('1.5.0')
const json = (value: string) => JSON.parse(value)
const ensureParent = (file: string) => mkdir(dirname(file), { recursive: true })

program.command('keygen')
  .requiredOption('--kid <id>').requiredOption('--private <file>').requiredOption('--public <file>')
  .requiredOption('--password <password>', 'Use a secret input mechanism in production')
  .action(async o => {
    const pair = generateSigningKeyPair()
    const encrypted = await encryptPrivateKey(pair.privateKeyPem, o.password)
    await ensureParent(o.private); await ensureParent(o.public)
    await writeFile(o.private, JSON.stringify({ kid: o.kid, ...encrypted }, null, 2), { mode: 0o600 })
    await chmod(o.private, 0o600)
    await writeFile(o.public, JSON.stringify({ kid: o.kid, publicKey: pair.publicKeyPem, publicKeyRaw: rawPublicKey(pair.publicKeyPem) }, null, 2))
    console.log(`Created key ${o.kid}`)
  })

program.command('key-import')
  .description('Encrypt an existing PKCS#8 Ed25519 private key for the manager')
  .requiredOption('--kid <id>').requiredOption('--input <pem-file>').requiredOption('--private <file>').requiredOption('--public <file>')
  .requiredOption('--password <password>', 'Use a secret input mechanism in production')
  .action(async o => {
    const privateKeyPem = await readFile(o.input, 'utf8')
    const publicKeyPem = createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }).toString()
    await ensureParent(o.private); await ensureParent(o.public)
    await writeFile(o.private, JSON.stringify({ kid: o.kid, ...(await encryptPrivateKey(privateKeyPem, o.password)) }, null, 2), { mode: 0o600 }); await chmod(o.private, 0o600)
    await writeFile(o.public, JSON.stringify({ kid: o.kid, publicKey: publicKeyPem, publicKeyRaw: rawPublicKey(publicKeyPem) }, null, 2))
    console.log(`Imported and encrypted key ${o.kid}`)
  })

program.command('manager')
  .description('Open the local-only graphical License Manager')
  .option('--data <directory>').option('--port <number>', 'Loopback port', '47831')
  .action(async o => {
    const dataDirectory = o.data || join(homedir(), 'Library', 'Application Support', 'Offline License Manager')
    const result = await startManager({ dataDirectory, port: Number(o.port) })
    console.log(`Manager running at ${result.url}`)
  })

program.command('issue')
  .requiredOption('--key <file>').requiredOption('--password <password>')
  .requiredOption('--app <appId>').requiredOption('--major <number>')
  .requiredOption('--records <file>', 'Persistent issued-license record file')
  .option('--plan <plan>').option('--features <items>', 'Comma-separated features')
  .option('--expires-at <unix>').option('--license-id <id>')
  .option('--device <deviceId>', 'Bind the license to one device')
  .option('--customer <name>').option('--note <text>')
  .action(async o => {
    const envelope = json(await readFile(o.key, 'utf8'))
    const privateKey = await decryptPrivateKey(envelope, o.password)
    const result = issueLicense({
      licenseId: o.licenseId, appId: o.app, majorVersion: Number(o.major), kid: envelope.kid,
      ...(o.device ? { deviceId: o.device } : {}),
      ...(o.plan ? { plan: o.plan } : {}),
      ...(o.features ? { features: o.features.split(',').map((x: string) => x.trim()).filter(Boolean) } : {}),
      ...(o.expiresAt ? { expiresAt: Number(o.expiresAt) } : {})
    }, privateKey)
    await appendIssuedLicenseRecord(o.records, { payload: result.payload, code: result.code, issuedAt: new Date().toISOString(), ...(o.customer ? { customer: o.customer } : {}), ...(o.note ? { note: o.note } : {}) })
    console.log(result.code)
  })

program.command('backup-export')
  .description('Create a complete encrypted offline backup file')
  .requiredOption('--app <appId>').requiredOption('--key <encrypted-key-file>').requiredOption('--public <public-key-file>')
  .requiredOption('--records <records-file>').requiredOption('--output <file>').requiredOption('--password <password>')
  .action(async o => console.log(JSON.stringify(await createBackup({ appId: o.app, encryptedKeyFile: o.key, publicKeyFile: o.public, recordsFile: o.records, outputFile: o.output, password: o.password }), null, 2)))

program.command('backup-icloud')
  .description('Copy an already encrypted backup file to iCloud Drive')
  .requiredOption('--app <appId>').requiredOption('--backup <file>').option('--icloud-root <directory>')
  .action(async o => console.log(JSON.stringify(await copyBackupToICloud({ appId: o.app, backupFile: o.backup, iCloudRoot: o.icloudRoot }), null, 2)))

program.command('backup-restore')
  .description('Restore a complete backup on a new machine')
  .requiredOption('--backup <file>').requiredOption('--destination <directory>').requiredOption('--password <password>')
  .option('--app <appId>', 'Reject a backup for another app')
  .action(async o => console.log(JSON.stringify(await restoreBackup({ backupFile: o.backup, destination: o.destination, password: o.password, expectedAppId: o.app }), null, 2)))

program.command('verify')
  .requiredOption('--license <code>').requiredOption('--app <appId>').requiredOption('--major <number>')
  .requiredOption('--public <file...>', 'One or more public key JSON files')
  .option('--device <deviceId>', 'Current device ID for a bound license')
  .action(async o => {
    const publicKeys: Record<string, string> = {}
    for (const file of o.public) { const key = json(await readFile(file, 'utf8')); publicKeys[key.kid] = key.publicKey }
    const result = createLicenseClient({ appId: o.app, majorVersion: Number(o.major), publicKeys, ...(o.device ? { deviceId: o.device } : {}) }).verify(o.license)
    console.log(JSON.stringify(result, (_key, value) => typeof value === 'function' ? undefined : value, 2))
    if (!result.valid) process.exitCode = 1
  })

program.parseAsync().catch(error => { console.error(error.message); process.exitCode = 1 })
