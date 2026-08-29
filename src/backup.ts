import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { chmod, copyFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import argon2 from 'argon2'
import type { LicensePayload } from './types.js'

export type IssuedLicenseRecord = { payload: LicensePayload; code: string; issuedAt: string; customer?: string; note?: string }
export type BackupEnvelope = {
  version: 1
  kdf: { name: 'argon2id'; salt: string; memoryCost: number; timeCost: number; parallelism: number }
  cipher: { name: 'aes-256-gcm'; iv: string; tag: string }
  ciphertext: string
}
type BackupContent = { version: 1; appId: string; kid: string; createdAt: string; encryptedPrivateKey: unknown; publicKey: unknown; records: IssuedLicenseRecord[]; managerConfig?: unknown; managerKeyring?: unknown }

const params = { memoryCost: 65536, timeCost: 3, parallelism: 1 }
const atomicWrite = async (file: string, data: string, mode = 0o600) => {
  await mkdir(dirname(file), { recursive: true })
  const temporary = `${file}.tmp-${process.pid}`
  await writeFile(temporary, data, { mode })
  await rename(temporary, file)
  await chmod(file, mode)
}

export async function readIssuedLicenseRecords(file: string): Promise<IssuedLicenseRecord[]> {
  try { const value = JSON.parse(await readFile(file, 'utf8')); if (!Array.isArray(value)) throw new Error(); return value }
  catch (error: any) { if (error?.code === 'ENOENT') return []; throw new Error('License records file is invalid') }
}

export async function appendIssuedLicenseRecord(file: string, record: IssuedLicenseRecord): Promise<void> {
  const records = await readIssuedLicenseRecords(file)
  if (records.some(item => item.payload?.licenseId === record.payload.licenseId)) throw new Error('licenseId already exists in records')
  records.unshift(record)
  await atomicWrite(file, JSON.stringify(records, null, 2))
}

export async function createBackup(options: { appId: string; encryptedKeyFile: string; publicKeyFile: string; recordsFile: string; outputFile: string; password: string; configFile?: string; keyringFile?: string }) {
  if (options.password.length < 12) throw new Error('Backup password must contain at least 12 characters')
  const encryptedPrivateKey = JSON.parse(await readFile(options.encryptedKeyFile, 'utf8'))
  const publicKey = JSON.parse(await readFile(options.publicKeyFile, 'utf8'))
  if (!encryptedPrivateKey.kid || encryptedPrivateKey.kid !== publicKey.kid) throw new Error('Private and public key records do not match')
  if (encryptedPrivateKey.kdf?.name !== 'argon2id' || encryptedPrivateKey.cipher?.name !== 'aes-256-gcm') throw new Error('Local private key is not encrypted with the supported format')
  const managerConfig = options.configFile ? JSON.parse(await readFile(options.configFile, 'utf8')) : undefined
  const managerKeyring = options.keyringFile ? JSON.parse(await readFile(options.keyringFile, 'utf8')) : undefined
  const content: BackupContent = { version: 1, appId: options.appId, kid: publicKey.kid, createdAt: new Date().toISOString(), encryptedPrivateKey, publicKey, records: await readIssuedLicenseRecords(options.recordsFile), ...(managerConfig === undefined ? {} : { managerConfig }), ...(managerKeyring === undefined ? {} : { managerKeyring }) }
  const salt = randomBytes(16), iv = randomBytes(12)
  const key = await argon2.hash(options.password, { type: argon2.argon2id, salt, hashLength: 32, raw: true, ...params })
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(content), 'utf8'), cipher.final()])
  const envelope: BackupEnvelope = { version: 1, kdf: { name: 'argon2id', salt: salt.toString('base64'), ...params }, cipher: { name: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') }, ciphertext: ciphertext.toString('base64') }
  await atomicWrite(options.outputFile, JSON.stringify(envelope, null, 2))
  return { outputFile: options.outputFile, appId: options.appId, kid: publicKey.kid, recordCount: content.records.length, createdAt: content.createdAt }
}

export async function restoreBackup(options: { backupFile: string; destination: string; password: string; expectedAppId?: string }) {
  const envelope = JSON.parse(await readFile(options.backupFile, 'utf8')) as BackupEnvelope
  if (envelope.version !== 1 || envelope.kdf?.name !== 'argon2id' || envelope.cipher?.name !== 'aes-256-gcm') throw new Error('Unsupported backup format')
  const key = await argon2.hash(options.password, { type: argon2.argon2id, salt: Buffer.from(envelope.kdf.salt, 'base64'), hashLength: 32, raw: true, memoryCost: envelope.kdf.memoryCost, timeCost: envelope.kdf.timeCost, parallelism: envelope.kdf.parallelism })
  let content: BackupContent
  try { const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.cipher.iv, 'base64')); decipher.setAuthTag(Buffer.from(envelope.cipher.tag, 'base64')); content = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8')) }
  catch { throw new Error('Incorrect backup password or damaged backup') }
  if (content.version !== 1 || !content.appId || !content.kid || !Array.isArray(content.records)) throw new Error('Backup content is invalid')
  if (options.expectedAppId && content.appId !== options.expectedAppId) throw new Error('Backup belongs to another app')
  const encryptedKey: any = content.encryptedPrivateKey, publicKey: any = content.publicKey
  if (encryptedKey?.kid !== content.kid || publicKey?.kid !== content.kid || encryptedKey?.kdf?.name !== 'argon2id' || encryptedKey?.cipher?.name !== 'aes-256-gcm') throw new Error('Backup key records are inconsistent')
  const config: any = content.managerConfig
  if (config && (config.appId !== content.appId || config.kid !== content.kid)) throw new Error('Backup manager configuration is inconsistent')
  const keyring: any = content.managerKeyring
  if (keyring && (!keyring.keys || !keyring.keys[content.kid])) throw new Error('Backup manager keyring is inconsistent')
  await mkdir(options.destination, { recursive: true })
  await atomicWrite(join(options.destination, 'signing-key.olmkey'), JSON.stringify(encryptedKey, null, 2))
  await atomicWrite(join(options.destination, 'public-key.json'), JSON.stringify(publicKey, null, 2), 0o644)
  await atomicWrite(join(options.destination, 'licenses.json'), JSON.stringify(content.records, null, 2))
  if (config) await atomicWrite(join(options.destination, 'app.json'), JSON.stringify(config, null, 2), 0o644)
  if (keyring) await atomicWrite(join(options.destination, 'keyring.json'), JSON.stringify(keyring, null, 2))
  return { appId: content.appId, kid: content.kid, recordCount: content.records.length, destination: options.destination }
}

export async function copyBackupToICloud(options: { backupFile: string; appId: string; iCloudRoot?: string }) {
  if (!/^[A-Za-z0-9._-]+$/.test(options.appId)) throw new Error('Invalid appId')
  const root = options.iCloudRoot ?? join(process.env.HOME || '', 'Library', 'Mobile Documents', 'com~apple~CloudDocs', 'Offline License Manager')
  const directory = join(root, options.appId, 'Backups'); await mkdir(directory, { recursive: true })
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const destination = join(directory, `${options.appId}-${stamp}.olmbackup`)
  await copyFile(options.backupFile, destination)
  return { destination }
}

export async function copyBackupToDirectory(options: { backupFile: string; appId: string; directory: string }) {
  if (!/^[A-Za-z0-9._-]+$/.test(options.appId) || !options.directory) throw new Error('Valid appId and directory are required')
  await mkdir(options.directory, { recursive: true })
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const destination = join(options.directory, `${options.appId}-${stamp}.olmbackup`)
  await copyFile(options.backupFile, destination)
  return { destination }
}
