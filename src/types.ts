export type LicensePayload = {
  licenseId: string
  appId: string
  majorVersion: number
  plan?: string
  features?: string[]
  issuedAt: number
  expiresAt?: number
  kid: string
}

export type IssueLicenseInput = Omit<LicensePayload, 'licenseId' | 'issuedAt'> & {
  licenseId?: string
  issuedAt?: number
}

export type PublicKeySet = Record<string, string>

export type VerifyReason =
  | 'malformed'
  | 'invalid_payload'
  | 'unknown_key'
  | 'invalid_signature'
  | 'app_mismatch'
  | 'major_version_mismatch'
  | 'expired'

export type LicenseResult =
  | {
      valid: true
      payload: LicensePayload
      plan?: string
      hasFeature(feature: string): boolean
    }
  | {
      valid: false
      reason: VerifyReason
      message: string
      payload?: LicensePayload
      plan?: undefined
      hasFeature(feature: string): false
    }
