import assert from 'node:assert/strict'
import test from 'node:test'
import { createLicenseClient, generateSigningKeyPair, issueLicense } from '../src/index.js'

const key = generateSigningKeyPair()
const keys = { '2026-01': key.publicKeyPem }
const reason = (result: ReturnType<ReturnType<typeof createLicenseClient>['verify']>) => {
  assert.equal(result.valid, false)
  return result.reason
}

test('issues and verifies plan and feature licenses', () => {
  const { code } = issueLicense({ appId: 'app_lemon_note', majorVersion: 2, plan: 'pro', features: ['export', 'sync'], issuedAt: 100, expiresAt: 300, kid: '2026-01' }, key.privateKeyPem)
  const result = createLicenseClient({ appId: 'app_lemon_note', majorVersion: 2, publicKeys: keys, now: () => 200 }).verify(code)
  assert.equal(result.valid, true)
  assert.equal(result.plan, 'pro')
  assert.equal(result.hasFeature('export'), true)
  assert.equal(result.hasFeature('missing'), false)
})

test('rejects tampering, wrong app, wrong major, expiry, and unknown kid', () => {
  const { code } = issueLicense({ appId: 'app_lemon_note', majorVersion: 2, issuedAt: 100, expiresAt: 300, kid: '2026-01' }, key.privateKeyPem)
  assert.equal(reason(createLicenseClient({ appId: 'other', majorVersion: 2, publicKeys: keys }).verify(code)), 'app_mismatch')
  assert.equal(reason(createLicenseClient({ appId: 'app_lemon_note', majorVersion: 1, publicKeys: keys }).verify(code)), 'major_version_mismatch')
  assert.equal(reason(createLicenseClient({ appId: 'app_lemon_note', majorVersion: 2, publicKeys: keys, now: () => 300 }).verify(code)), 'expired')
  assert.equal(reason(createLicenseClient({ appId: 'app_lemon_note', majorVersion: 2, publicKeys: {} }).verify(code)), 'unknown_key')
  const parts = code.split('.'); parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`
  assert.equal(reason(createLicenseClient({ appId: 'app_lemon_note', majorVersion: 2, publicKeys: keys }).verify(parts.join('.'))), 'invalid_signature')
})
