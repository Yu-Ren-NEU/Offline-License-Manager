import { randomUUID } from 'node:crypto'
import { encodeBase64Url, LICENSE_PREFIX, serializePayload, validatePayload } from './core.js'
import { signBytes } from './crypto.js'
import type { IssueLicenseInput, LicensePayload } from './types.js'

export function issueLicense(input: IssueLicenseInput, privateKeyPem: string): { code: string; payload: LicensePayload } {
  const payload = validatePayload({ ...input, licenseId: input.licenseId ?? randomUUID(), issuedAt: input.issuedAt ?? Math.floor(Date.now() / 1000) })
  const encodedPayload = encodeBase64Url(serializePayload(payload))
  const signature = signBytes(Buffer.from(encodedPayload, 'ascii'), privateKeyPem)
  return { code: `${LICENSE_PREFIX}.${encodedPayload}.${encodeBase64Url(signature)}`, payload }
}
