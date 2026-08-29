import assert from 'node:assert/strict'
import test from 'node:test'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { generateSigningKeyPair, issueLicense, rawPublicKey, verifyBytes } from '../src/index.js'

const require = createRequire(import.meta.url)
const mini = require(join(process.cwd(), 'miniprogram/index.js'))

test('Mini Program adapter verifies the shared OLM1 format', () => {
  const previousWx = (globalThis as any).wx
  ;(globalThis as any).wx = { base64ToArrayBuffer(value: string) { const b = Buffer.from(value, 'base64'); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) } }
  const pair = generateSigningKeyPair()
  const nacl = { sign: { detached: { verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array) {
    const prefix = Buffer.from('302a300506032b6570032100', 'hex')
    const pem = `-----BEGIN PUBLIC KEY-----\n${Buffer.concat([prefix, Buffer.from(publicKey)]).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----\n`
    return verifyBytes(data, signature, pem)
  } } } }
  const { code } = issueLicense({ appId: 'app_lemon_note', majorVersion: 1, plan: 'pro', features: ['excel-export'], kid: 'key-1' }, pair.privateKeyPem)
  const result = mini.createMiniProgramLicenseClient({ appId: 'app_lemon_note', majorVersion: 1, publicKeys: { 'key-1': rawPublicKey(pair.publicKeyPem) }, nacl }).verify(code)
  assert.equal(result.valid, true); assert.equal(result.plan, 'pro'); assert.equal(result.hasFeature('excel-export'), true)
  ;(globalThis as any).wx = previousWx
})
