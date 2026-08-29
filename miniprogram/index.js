function createMiniProgramLicenseClient(options) {
  if (!options || !options.appId || !Number.isSafeInteger(options.majorVersion) || options.majorVersion < 1) throw new Error('Valid appId and majorVersion are required')
  const nacl = options.nacl
  if (!nacl || !nacl.sign || !nacl.sign.detached) throw new Error('A TweetNaCl-compatible implementation is required')

  function base64UrlToBytes(value) {
    if (!/^[A-Za-z0-9_-]+$/.test(value || '')) throw new Error('Invalid base64url')
    let text = value.replace(/-/g, '+').replace(/_/g, '/')
    while (text.length % 4) text += '='
    return new Uint8Array(wx.base64ToArrayBuffer(text))
  }
  function utf8Bytes(text) {
    const encoded = unescape(encodeURIComponent(String(text)))
    const result = new Uint8Array(encoded.length)
    for (let i = 0; i < encoded.length; i++) result[i] = encoded.charCodeAt(i)
    return result
  }
  function utf8Text(bytes) {
    let text = ''
    for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i])
    return decodeURIComponent(escape(text))
  }
  function invalid(reason, message, payload) {
    return { valid: false, reason, message, payload: payload || null, plan: undefined, hasFeature: function () { return false } }
  }
  function validPayload(p) {
    if (!p || typeof p !== 'object' || Array.isArray(p)) return false
    const allowed = { licenseId: 1, appId: 1, majorVersion: 1, plan: 1, features: 1, deviceId: 1, issuedAt: 1, expiresAt: 1, kid: 1 }
    if (Object.keys(p).some(function (key) { return !allowed[key] })) return false
    return typeof p.licenseId === 'string' && !!p.licenseId && typeof p.appId === 'string' && !!p.appId &&
      Number.isSafeInteger(p.majorVersion) && p.majorVersion > 0 && Number.isSafeInteger(p.issuedAt) && p.issuedAt >= 0 &&
      typeof p.kid === 'string' && !!p.kid && (p.deviceId === undefined || (typeof p.deviceId === 'string' && !!p.deviceId)) && (p.plan === undefined || (typeof p.plan === 'string' && !!p.plan)) &&
      (p.features === undefined || (Array.isArray(p.features) && p.features.every(function (x) { return typeof x === 'string' && !!x }))) &&
      (p.expiresAt === undefined || (Number.isSafeInteger(p.expiresAt) && p.expiresAt >= 0))
  }
  function verify(code) {
    let parts, payload, signature
    try {
      parts = String(code || '').trim().split('.')
      if (parts.length !== 3 || parts[0] !== 'OLM1') return invalid('malformed', '激活码格式不正确')
      payload = JSON.parse(utf8Text(base64UrlToBytes(parts[1])))
      if (!validPayload(payload)) return invalid('invalid_payload', '激活码内容不正确')
      signature = base64UrlToBytes(parts[2])
      if (signature.length !== 64) return invalid('malformed', '激活码签名格式不正确')
    } catch (_) { return invalid('malformed', '激活码无法解析') }
    const publicKey = options.publicKeys[payload.kid]
    if (!publicKey) return invalid('unknown_key', '激活码使用了未知签名密钥', payload)
    if (!nacl.sign.detached.verify(utf8Bytes(parts[1]), signature, base64UrlToBytes(publicKey))) return invalid('invalid_signature', '激活码签名无效', payload)
    if (payload.appId !== options.appId) return invalid('app_mismatch', '激活码不属于当前应用', payload)
    if (payload.majorVersion !== options.majorVersion) return invalid('major_version_mismatch', '激活码不适用于当前大版本', payload)
    if (payload.deviceId !== options.deviceId) return invalid('device_mismatch', '激活码的设备绑定与当前应用不一致', payload)
    const now = options.now ? options.now() : Math.floor(Date.now() / 1000)
    if (payload.expiresAt !== undefined && now >= payload.expiresAt) return invalid('expired', '激活码已过期', payload)
    return { valid: true, payload: payload, plan: payload.plan, hasFeature: function (feature) { return Array.isArray(payload.features) && payload.features.indexOf(feature) >= 0 } }
  }
  return { verify: verify }
}

module.exports = { createMiniProgramLicenseClient: createMiniProgramLicenseClient }
