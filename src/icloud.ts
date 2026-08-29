import { access, copyFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { homedir } from 'node:os'

const defaultRoot = () => join(homedir(), 'Library', 'Mobile Documents', 'com~apple~CloudDocs', 'Offline License Manager')
const safeAppId = (value: string) => {
  if (!/^[A-Za-z0-9._-]+$/.test(value)) throw new Error('appId may contain only letters, numbers, dot, underscore, and hyphen')
  return value
}
const exists = async (file: string) => access(file).then(() => true, () => false)
const atomicCopy = async (source: string, destination: string) => {
  const temporary = `${destination}.tmp-${process.pid}`
  await copyFile(source, temporary)
  await rename(temporary, destination)
}

export async function syncToICloud(options: { appId: string; encryptedKeyFile: string; publicKeyFile: string; recordsFile?: string; iCloudRoot?: string }) {
  const directory = join(options.iCloudRoot ?? defaultRoot(), safeAppId(options.appId))
  await mkdir(directory, { recursive: true })
  const key = JSON.parse(await readFile(options.encryptedKeyFile, 'utf8'))
  if (key.version !== 1 || key.kdf?.name !== 'argon2id' || key.cipher?.name !== 'aes-256-gcm') throw new Error('Only encrypted .olmkey files may be synced')
  const publicRecord = JSON.parse(await readFile(options.publicKeyFile, 'utf8'))
  if (!key.kid || key.kid !== publicRecord.kid) throw new Error('Private and public key records do not match')
  await atomicCopy(options.encryptedKeyFile, join(directory, 'signing-key.olmkey'))
  await atomicCopy(options.publicKeyFile, join(directory, 'public-key.json'))
  const hasRecords = !!options.recordsFile && await exists(options.recordsFile)
  if (hasRecords) await atomicCopy(options.recordsFile!, join(directory, 'licenses.json'))
  const manifest = { version: 1, appId: options.appId, kid: key.kid, syncedAt: new Date().toISOString(), files: ['signing-key.olmkey', 'public-key.json', ...(hasRecords ? ['licenses.json'] : [])] }
  await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2))
  return { directory, manifest }
}

export async function restoreFromICloud(options: { appId: string; destination: string; iCloudRoot?: string }) {
  const source = join(options.iCloudRoot ?? defaultRoot(), safeAppId(options.appId))
  const manifest = JSON.parse(await readFile(join(source, 'manifest.json'), 'utf8'))
  if (manifest.version !== 1 || manifest.appId !== options.appId || !Array.isArray(manifest.files)) throw new Error('Invalid iCloud backup manifest')
  await mkdir(options.destination, { recursive: true })
  for (const file of manifest.files) {
    if (!['signing-key.olmkey', 'public-key.json', 'licenses.json'].includes(file) || basename(file) !== file) throw new Error('Invalid backup file entry')
    if (await exists(join(source, file))) await atomicCopy(join(source, file), join(options.destination, file))
  }
  return { source, destination: options.destination, manifest }
}
