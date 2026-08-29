import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto'
import argon2 from 'argon2'

export type EncryptedPrivateKey = {
  version: 1
  kdf: { name: 'argon2id'; salt: string; memoryCost: number; timeCost: number; parallelism: number }
  cipher: { name: 'aes-256-gcm'; iv: string; tag: string }
  ciphertext: string
}

export function generateSigningKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
  }
}

export function signBytes(data: Uint8Array, privateKeyPem: string): Buffer {
  return sign(null, data, createPrivateKey(privateKeyPem))
}

export function verifyBytes(data: Uint8Array, signature: Uint8Array, publicKeyPem: string): boolean {
  return verify(null, data, createPublicKey(publicKeyPem), signature)
}

export async function encryptPrivateKey(privateKeyPem: string, password: string): Promise<EncryptedPrivateKey> {
  if (password.length < 12) throw new Error('Password must contain at least 12 characters')
  createPrivateKey(privateKeyPem)
  const salt = randomBytes(16)
  const params = { memoryCost: 65536, timeCost: 3, parallelism: 1 }
  const key = await argon2.hash(password, { type: argon2.argon2id, salt, hashLength: 32, raw: true, ...params })
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(privateKeyPem, 'utf8'), cipher.final()])
  return {
    version: 1,
    kdf: { name: 'argon2id', salt: salt.toString('base64'), ...params },
    cipher: { name: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') },
    ciphertext: ciphertext.toString('base64')
  }
}

export async function decryptPrivateKey(envelope: EncryptedPrivateKey, password: string): Promise<string> {
  if (envelope.version !== 1 || envelope.kdf?.name !== 'argon2id' || envelope.cipher?.name !== 'aes-256-gcm') throw new Error('Unsupported key file')
  const key = await argon2.hash(password, {
    type: argon2.argon2id,
    salt: Buffer.from(envelope.kdf.salt, 'base64'),
    hashLength: 32,
    raw: true,
    memoryCost: envelope.kdf.memoryCost,
    timeCost: envelope.kdf.timeCost,
    parallelism: envelope.kdf.parallelism
  })
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.cipher.iv, 'base64'))
    decipher.setAuthTag(Buffer.from(envelope.cipher.tag, 'base64'))
    const pem = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8')
    createPrivateKey(pem)
    return pem
  } catch { throw new Error('Incorrect password or damaged key file') }
}
