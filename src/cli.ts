#!/usr/bin/env node
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { Command } from 'commander'
import { decryptPrivateKey, encryptPrivateKey, generateSigningKeyPair } from './crypto.js'
import { issueLicense } from './issuer.js'
import { createLicenseClient } from './sdk.js'

const program = new Command().name('offline-license').description('Zero-server Ed25519 license manager').version('1.0.0')
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
    await writeFile(o.public, JSON.stringify({ kid: o.kid, publicKey: pair.publicKeyPem }, null, 2))
    console.log(`Created key ${o.kid}`)
  })

program.command('issue')
  .requiredOption('--key <file>').requiredOption('--password <password>')
  .requiredOption('--app <appId>').requiredOption('--major <number>')
  .option('--plan <plan>').option('--features <items>', 'Comma-separated features')
  .option('--expires-at <unix>').option('--license-id <id>')
  .action(async o => {
    const envelope = json(await readFile(o.key, 'utf8'))
    const privateKey = await decryptPrivateKey(envelope, o.password)
    const result = issueLicense({
      licenseId: o.licenseId, appId: o.app, majorVersion: Number(o.major), kid: envelope.kid,
      ...(o.plan ? { plan: o.plan } : {}),
      ...(o.features ? { features: o.features.split(',').map((x: string) => x.trim()).filter(Boolean) } : {}),
      ...(o.expiresAt ? { expiresAt: Number(o.expiresAt) } : {})
    }, privateKey)
    console.log(result.code)
  })

program.command('verify')
  .requiredOption('--license <code>').requiredOption('--app <appId>').requiredOption('--major <number>')
  .requiredOption('--public <file...>', 'One or more public key JSON files')
  .action(async o => {
    const publicKeys: Record<string, string> = {}
    for (const file of o.public) { const key = json(await readFile(file, 'utf8')); publicKeys[key.kid] = key.publicKey }
    const result = createLicenseClient({ appId: o.app, majorVersion: Number(o.major), publicKeys }).verify(o.license)
    console.log(JSON.stringify(result, (_key, value) => typeof value === 'function' ? undefined : value, 2))
    if (!result.valid) process.exitCode = 1
  })

program.parseAsync().catch(error => { console.error(error.message); process.exitCode = 1 })
