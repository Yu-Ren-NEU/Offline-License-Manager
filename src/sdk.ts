import { parseLicense } from './core.js'
import { verifyBytes } from './crypto.js'
import type { LicenseResult, PublicKeySet, VerifyReason } from './types.js'

export type LicenseClientOptions = { appId: string; majorVersion: number; deviceId?: string; publicKeys: PublicKeySet; now?: () => number }

export function createLicenseClient(options: LicenseClientOptions) {
  if (!options.appId || !Number.isSafeInteger(options.majorVersion) || options.majorVersion < 1) throw new Error('Valid appId and majorVersion are required')
  const invalid = (reason: VerifyReason, message: string, payload?: any): LicenseResult => ({ valid: false, reason, message, ...(payload ? { payload } : {}), hasFeature: () => false })
  return {
    verify(code: string): LicenseResult {
      let parsed
      try { parsed = parseLicense(code) } catch { return invalid('malformed', 'License cannot be parsed') }
      const { payload, encodedPayload, signature } = parsed
      const publicKey = options.publicKeys[payload.kid]
      if (!publicKey) return invalid('unknown_key', `Unknown signing key: ${payload.kid}`, payload)
      if (!verifyBytes(Buffer.from(encodedPayload, 'ascii'), signature, publicKey)) return invalid('invalid_signature', 'License signature is invalid', payload)
      if (payload.appId !== options.appId) return invalid('app_mismatch', 'License belongs to another app', payload)
      if (payload.majorVersion !== options.majorVersion) return invalid('major_version_mismatch', 'License does not cover this major version', payload)
      if (payload.deviceId !== options.deviceId) return invalid('device_mismatch', 'License device binding does not match this app', payload)
      const now = options.now?.() ?? Math.floor(Date.now() / 1000)
      if (payload.expiresAt !== undefined && now >= payload.expiresAt) return invalid('expired', 'License has expired', payload)
      return { valid: true, payload, plan: payload.plan, hasFeature: feature => payload.features?.includes(feature) ?? false }
    }
  }
}
