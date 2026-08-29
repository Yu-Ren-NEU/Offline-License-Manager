import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { encryptPrivateKey, generateSigningKeyPair, rawPublicKey, restoreFromICloud, syncToICloud } from '../src/index.js'

test('syncs only encrypted manager data and restores it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'olm-icloud-'))
  const local = join(root, 'local'), cloud = join(root, 'cloud'), restored = join(root, 'restored')
  const { mkdir } = await import('node:fs/promises'); await mkdir(local)
  const pair = generateSigningKeyPair(), encrypted = await encryptPrivateKey(pair.privateKeyPem, 'a-long-test-password')
  const keyFile = join(local, 'key.olmkey'), publicFile = join(local, 'public.json'), recordsFile = join(local, 'licenses.json')
  await writeFile(keyFile, JSON.stringify({ kid: 'key-1', ...encrypted }))
  await writeFile(publicFile, JSON.stringify({ kid: 'key-1', publicKey: pair.publicKeyPem, publicKeyRaw: rawPublicKey(pair.publicKeyPem) }))
  await writeFile(recordsFile, '[]')
  await syncToICloud({ appId: 'app_lemon_note', encryptedKeyFile: keyFile, publicKeyFile: publicFile, recordsFile, iCloudRoot: cloud })
  await restoreFromICloud({ appId: 'app_lemon_note', destination: restored, iCloudRoot: cloud })
  assert.equal(JSON.parse(await readFile(join(restored, 'signing-key.olmkey'), 'utf8')).cipher.name, 'aes-256-gcm')
  assert.equal(await readFile(join(restored, 'licenses.json'), 'utf8'), '[]')
})
