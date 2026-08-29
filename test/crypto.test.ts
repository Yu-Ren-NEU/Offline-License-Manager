import assert from 'node:assert/strict'
import test from 'node:test'
import { decryptPrivateKey, encryptPrivateKey, generateSigningKeyPair } from '../src/index.js'

test('encrypts and decrypts a private key', async () => {
  const pair = generateSigningKeyPair()
  const encrypted = await encryptPrivateKey(pair.privateKeyPem, 'a-long-test-password')
  assert.equal(await decryptPrivateKey(encrypted, 'a-long-test-password'), pair.privateKeyPem)
  await assert.rejects(() => decryptPrivateKey(encrypted, 'wrong-password'), /Incorrect password/)
})
