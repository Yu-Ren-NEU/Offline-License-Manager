import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { startManager } from '../src/index.js'

test('local manager configures, unlocks, issues, records, and backs up', async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), 'olm-manager-'))
  const manager = await startManager({ dataDirectory, port: 0, openBrowser: false })
  try {
    const url = new URL(manager.url), token = url.searchParams.get('token')!, origin = url.origin
    const api = async (path: string, value?: unknown) => {
      const response = await fetch(`${origin}/api/${path}`, { method: value === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', 'X-Manager-Token': token }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) })
      const body = await response.json() as any
      assert.equal(response.ok, true, body.error)
      return body
    }
    assert.equal((await api('apps')).apps.length, 0)
    const setup = await api('create-app', { appId: 'test_app', name: 'Test App', majorVersion: 1, kid: 'test-key', password: 'manager-test-password', privateKeyPem: '', backupDirectory: join(dataDirectory, 'external-backups') })
    assert.equal(setup.app.unlocked, true)
    assert.match(setup.app.kid, /^key-\d{8}-[a-f0-9]{6}$/)
    const issued = await api('issue', { appId: 'test_app', customer: 'Customer', plan: 'pro', features: 'export,sync' })
    assert.match(issued.issued.code, /^OLM1\./)
    assert.equal(issued.app.records.length, 1)
    const oldKid = issued.issued.payload.kid
    const rotated = await api('rotate-key', { appId: 'test_app' })
    const pending = rotated.app.keys.find((key: any) => key.status === 'pending')
    assert.ok(pending); assert.notEqual(pending.kid, oldKid); assert.equal(Object.keys(rotated.app.publicKeys).length, 2)
    const activated = await api('activate-key', { appId: 'test_app', kid: pending.kid })
    assert.equal(activated.app.kid, pending.kid); assert.equal(activated.app.keys.find((key: any) => key.kid === oldKid).status, 'retired')
    const afterRotation = await api('issue', { appId: 'test_app', customer: 'After rotation', plan: 'free' })
    assert.equal(afterRotation.issued.payload.kid, pending.kid)
    const backup = await api('export-backup', { appId: 'test_app', password: 'backup-test-password', directory: join(dataDirectory, 'manual-backups') })
    assert.equal(backup.result.recordCount, 2)
    assert.equal((await api('lock', { appId: 'test_app' })).unlocked, false)
    assert.equal((await api('unlock', { appId: 'test_app', password: 'manager-test-password' })).unlocked, true)
  } finally { await new Promise<void>(resolve => manager.server.close(() => resolve())) }
})

test('new machine restores a complete App from one encrypted backup', async () => {
  const source = await mkdtemp(join(tmpdir(), 'olm-source-')), destination = await mkdtemp(join(tmpdir(), 'olm-destination-')), external = join(source, 'offline-copy')
  const first = await startManager({ dataDirectory: source, port: 0, openBrowser: false })
  let backupFile = ''
  try {
    const url = new URL(first.url), token = url.searchParams.get('token')!, origin = url.origin
    const call = async (path: string, body: unknown) => { const response = await fetch(`${origin}/api/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Manager-Token': token }, body: JSON.stringify(body) }); const value = await response.json() as any; assert.equal(response.ok, true, value.error); return value }
    await call('create-app', { appId: 'restored_app', name: 'Restored App', majorVersion: 2, kid: 'key-2', password: 'manager-test-password', backupDirectory: external })
    await call('issue', { appId: 'restored_app', customer: 'One', plan: 'free' })
    const exported = await call('export-backup', { appId: 'restored_app', directory: external })
    backupFile = exported.copied.destination
  } finally { await new Promise<void>(resolve => first.server.close(() => resolve())) }
  const second = await startManager({ dataDirectory: destination, port: 0, openBrowser: false })
  try {
    const url = new URL(second.url), token = url.searchParams.get('token')!, origin = url.origin
    const response = await fetch(`${origin}/api/restore-new`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Manager-Token': token }, body: JSON.stringify({ backupFile, password: 'manager-test-password' }) })
    const value = await response.json() as any
    assert.equal(response.ok, true, value.error)
    assert.equal(value.app.name, 'Restored App'); assert.equal(value.app.majorVersion, 2); assert.equal(value.app.records.length, 1)
  } finally { await new Promise<void>(resolve => second.server.close(() => resolve())) }
})
