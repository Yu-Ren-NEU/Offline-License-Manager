import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { startManager } from '../src/index.js'

test('local manager configures, unlocks, issues, records, and backs up', async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), 'olm-manager-'))
  const manager = await startManager({ appId: 'test_app', majorVersion: 1, kid: 'test-key', dataDirectory, port: 0, openBrowser: false })
  try {
    const url = new URL(manager.url), token = url.searchParams.get('token')!, origin = url.origin
    const api = async (path: string, value?: unknown) => {
      const response = await fetch(`${origin}/api/${path}`, { method: value === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', 'X-Manager-Token': token }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) })
      const body = await response.json() as any
      assert.equal(response.ok, true, body.error)
      return body
    }
    assert.equal((await api('state')).configured, false)
    const setup = await api('setup', { password: 'manager-test-password', privateKeyPem: '' })
    assert.equal(setup.unlocked, true)
    const issued = await api('issue', { customer: 'Customer', plan: 'pro', features: 'export,sync' })
    assert.match(issued.issued.code, /^OLM1\./)
    assert.equal(issued.state.records.length, 1)
    const backup = await api('backup', { password: 'backup-test-password', iCloud: false })
    assert.equal(backup.result.recordCount, 1)
    assert.equal((await api('lock', {})).unlocked, false)
    assert.equal((await api('unlock', { password: 'manager-test-password' })).unlocked, true)
  } finally { await new Promise<void>(resolve => manager.server.close(() => resolve())) }
})
