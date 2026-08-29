import type { LicensePayload } from './types.js'

export const LICENSE_PREFIX = 'OLM1'

export function encodeBase64Url(value: Uint8Array | string): string {
  return Buffer.from(value).toString('base64url')
}

export function decodeBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid base64url')
  return Buffer.from(value, 'base64url')
}

export function validatePayload(value: unknown): LicensePayload {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Payload must be an object')
  const p = value as Record<string, unknown>
  const keys = new Set(['licenseId', 'appId', 'majorVersion', 'plan', 'features', 'issuedAt', 'expiresAt', 'kid'])
  if (Object.keys(p).some(key => !keys.has(key))) throw new Error('Payload contains unknown fields')
  for (const key of ['licenseId', 'appId', 'kid'] as const) {
    if (typeof p[key] !== 'string' || !(p[key] as string).trim()) throw new Error(`${key} is required`)
  }
  if (!Number.isSafeInteger(p.majorVersion) || (p.majorVersion as number) < 1) throw new Error('majorVersion must be a positive integer')
  if (!Number.isSafeInteger(p.issuedAt) || (p.issuedAt as number) < 0) throw new Error('issuedAt must be a Unix timestamp')
  if (p.expiresAt !== undefined && (!Number.isSafeInteger(p.expiresAt) || (p.expiresAt as number) < 0)) throw new Error('expiresAt must be a Unix timestamp')
  if (p.plan !== undefined && (typeof p.plan !== 'string' || !p.plan)) throw new Error('plan must be a non-empty string')
  if (p.features !== undefined && (!Array.isArray(p.features) || p.features.some(x => typeof x !== 'string' || !x))) throw new Error('features must be strings')
  return {
    licenseId: p.licenseId as string,
    appId: p.appId as string,
    majorVersion: p.majorVersion as number,
    ...(p.plan === undefined ? {} : { plan: p.plan as string }),
    ...(p.features === undefined ? {} : { features: [...new Set(p.features as string[])].sort() }),
    issuedAt: p.issuedAt as number,
    ...(p.expiresAt === undefined ? {} : { expiresAt: p.expiresAt as number }),
    kid: p.kid as string
  }
}

export function serializePayload(payload: LicensePayload): string {
  const p = validatePayload(payload)
  return JSON.stringify({
    licenseId: p.licenseId,
    appId: p.appId,
    majorVersion: p.majorVersion,
    ...(p.plan === undefined ? {} : { plan: p.plan }),
    ...(p.features === undefined ? {} : { features: p.features }),
    issuedAt: p.issuedAt,
    ...(p.expiresAt === undefined ? {} : { expiresAt: p.expiresAt }),
    kid: p.kid
  })
}

export function parseLicense(code: string): { encodedPayload: string; payload: LicensePayload; signature: Buffer } {
  const parts = code.trim().split('.')
  if (parts.length !== 3 || parts[0] !== LICENSE_PREFIX) throw new Error('Invalid license envelope')
  const payload = validatePayload(JSON.parse(decodeBase64Url(parts[1]).toString('utf8')))
  const signature = decodeBase64Url(parts[2])
  if (signature.length !== 64) throw new Error('Invalid Ed25519 signature length')
  return { encodedPayload: parts[1], payload, signature }
}
