import http from 'node:http'
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { appendIssuedLicenseRecord, copyBackupToICloud, createBackup, readIssuedLicenseRecords, restoreBackup } from './backup.js'
import { decryptPrivateKey, encryptPrivateKey, generateSigningKeyPair, rawPublicKey } from './crypto.js'
import { issueLicense } from './issuer.js'

export type ManagerOptions = { appId: string; majorVersion: number; kid: string; dataDirectory: string; port?: number; expectedPublicKeyRaw?: string; importPrivateKeyFile?: string; openBrowser?: boolean }

export async function startManager(options: ManagerOptions) {
  if (!/^[A-Za-z0-9._-]+$/.test(options.appId) || !options.kid || !Number.isSafeInteger(options.majorVersion) || options.majorVersion < 1) throw new Error('Valid appId, kid, and majorVersion are required')
  await mkdir(options.dataDirectory, { recursive: true })
  const keyFile = join(options.dataDirectory, 'signing-key.olmkey'), publicFile = join(options.dataDirectory, 'public-key.json'), recordsFile = join(options.dataDirectory, 'licenses.json'), exportDirectory = join(options.dataDirectory, 'Backups')
  const token = randomBytes(24).toString('base64url')
  let unlockedPrivateKey: string | null = null
  const exists = async (file: string) => readFile(file).then(() => true, () => false)
  const writeSecure = async (file: string, value: unknown, mode = 0o600) => { await writeFile(file, JSON.stringify(value, null, 2), { mode }); await chmod(file, mode) }
  const body = (req: http.IncomingMessage) => new Promise<any>((resolve, reject) => { let value = ''; req.on('data', chunk => { value += chunk; if (value.length > 2_000_000) reject(new Error('Request too large')) }); req.on('end', () => { try { resolve(value ? JSON.parse(value) : {}) } catch { reject(new Error('Invalid JSON')) } }); req.on('error', reject) })
  const send = (res: http.ServerResponse, status: number, value: unknown, type = 'application/json; charset=utf-8') => { res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'none'; connect-src 'self'" }); res.end(type.startsWith('application/json') ? JSON.stringify(value) : String(value)) }
  const state = async () => ({ appId: options.appId, majorVersion: options.majorVersion, kid: options.kid, configured: await exists(keyFile), importAvailable: !!options.importPrivateKeyFile && await exists(options.importPrivateKeyFile), unlocked: !!unlockedPrivateKey, records: await readIssuedLicenseRecords(recordsFile), dataDirectory: options.dataDirectory })

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', `http://${req.headers.host}`)
      if (req.method === 'GET' && url.pathname === '/') return send(res, 200, MANAGER_HTML, 'text/html; charset=utf-8')
      if (req.headers['x-manager-token'] !== token) return send(res, 403, { error: 'Invalid local session token' })
      if (req.method === 'GET' && url.pathname === '/api/state') return send(res, 200, await state())
      if (req.method === 'POST' && url.pathname === '/api/setup') {
        if (await exists(keyFile)) throw new Error('Manager is already configured')
        const input = await body(req), password = String(input.password || '')
        const importedPem = input.privateKeyPem ? String(input.privateKeyPem) : options.importPrivateKeyFile && await exists(options.importPrivateKeyFile) ? await readFile(options.importPrivateKeyFile, 'utf8') : ''
        const pair = importedPem ? { privateKeyPem: importedPem, publicKeyPem: '' } : generateSigningKeyPair()
        const publicKeyPem = pair.publicKeyPem || (await import('node:crypto')).createPublicKey(pair.privateKeyPem).export({ type: 'spki', format: 'pem' }).toString()
        const publicKeyRaw = rawPublicKey(publicKeyPem)
        if (options.expectedPublicKeyRaw && publicKeyRaw !== options.expectedPublicKeyRaw) throw new Error('Imported private key does not match the public key embedded in the app')
        await writeSecure(keyFile, { kid: options.kid, ...(await encryptPrivateKey(pair.privateKeyPem, password)) })
        await writeSecure(publicFile, { kid: options.kid, publicKey: publicKeyPem, publicKeyRaw }, 0o644)
        await writeSecure(recordsFile, [])
        unlockedPrivateKey = pair.privateKeyPem
        return send(res, 200, await state())
      }
      if (req.method === 'POST' && url.pathname === '/api/unlock') { const input = await body(req); const envelope = JSON.parse(await readFile(keyFile, 'utf8')); unlockedPrivateKey = await decryptPrivateKey(envelope, String(input.password || '')); return send(res, 200, await state()) }
      if (req.method === 'POST' && url.pathname === '/api/lock') { unlockedPrivateKey = null; return send(res, 200, await state()) }
      if (req.method === 'POST' && url.pathname === '/api/issue') {
        if (!unlockedPrivateKey) throw new Error('Unlock the signing key first')
        const input = await body(req), features = String(input.features || '').split(',').map(x => x.trim()).filter(Boolean)
        const issued = issueLicense({ appId: options.appId, majorVersion: options.majorVersion, kid: options.kid, ...(input.plan ? { plan: String(input.plan) } : {}), ...(features.length ? { features } : {}), ...(input.expiresAt ? { expiresAt: Number(input.expiresAt) } : {}) }, unlockedPrivateKey)
        await appendIssuedLicenseRecord(recordsFile, { payload: issued.payload, code: issued.code, issuedAt: new Date().toISOString(), ...(input.customer ? { customer: String(input.customer) } : {}), ...(input.note ? { note: String(input.note) } : {}) })
        return send(res, 200, { issued, state: await state() })
      }
      if (req.method === 'POST' && url.pathname === '/api/backup') {
        const input = await body(req); await mkdir(exportDirectory, { recursive: true }); const stamp = new Date().toISOString().replace(/[:.]/g, '-'), outputFile = join(exportDirectory, `${options.appId}-${stamp}.olmbackup`)
        const result = await createBackup({ appId: options.appId, encryptedKeyFile: keyFile, publicKeyFile: publicFile, recordsFile, outputFile, password: String(input.password || '') })
        const cloud = input.iCloud ? await copyBackupToICloud({ backupFile: outputFile, appId: options.appId }) : null
        return send(res, 200, { result, cloud })
      }
      if (req.method === 'POST' && url.pathname === '/api/restore') { const input = await body(req); unlockedPrivateKey = null; const restored = await restoreBackup({ backupFile: String(input.backupFile || ''), destination: options.dataDirectory, password: String(input.password || ''), expectedAppId: options.appId }); return send(res, 200, { restored, state: await state() }) }
      send(res, 404, { error: 'Not found' })
    } catch (error: any) { send(res, 400, { error: error?.message || 'Request failed' }) }
  })
  const port = options.port ?? 47831
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve) })
  const address = server.address()
  const actualPort = typeof address === 'object' && address ? address.port : port
  const url = `http://127.0.0.1:${actualPort}/?token=${token}`
  if (options.openBrowser !== false) execFile('open', [url])
  return { server, url }
}

const MANAGER_HTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline License Manager</title><style>
:root{--ink:#17211a;--green:#294e35;--paper:#f3f5ef;--line:#dfe6dc;--muted:#708074}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}.shell{width:min(1120px,calc(100% - 32px));margin:34px auto}.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.title{font-size:28px;font-weight:800}.sub,.meta{color:var(--muted);font-size:13px}.badge{padding:8px 12px;border-radius:18px;background:#fff}.grid{display:grid;grid-template-columns:400px 1fr;gap:22px}.card{background:#fff;border-radius:20px;padding:24px;box-shadow:0 12px 34px #243b2b12}h2{margin:0 0 18px;font-size:19px}label{display:block;margin:14px 0 7px;font-weight:650}input,textarea{width:100%;border:1px solid var(--line);border-radius:12px;background:#f8faf6;padding:11px 13px;font:inherit}textarea{min-height:94px;resize:vertical;font-family:ui-monospace,monospace}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}button{border:0;border-radius:12px;padding:12px 15px;background:#eaf0e8;color:var(--green);font:inherit;font-weight:750;cursor:pointer}.primary{width:100%;margin-top:18px;background:var(--green);color:#fff}.tools{display:flex;gap:8px;flex-wrap:wrap}.hidden{display:none}.record{padding:14px 0;border-bottom:1px solid var(--line)}.record:last-child{border:0}.code{margin-top:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font:12px ui-monospace,monospace;color:var(--muted)}.result{margin-top:16px}.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--ink);color:#fff;padding:10px 17px;border-radius:20px;opacity:0;transition:.2s}.toast.show{opacity:1}@media(max-width:800px){.grid{grid-template-columns:1fr}.head{align-items:flex-start;flex-direction:column;gap:12px}}
</style></head><body><main class="shell"><header class="head"><div><div class="title">Offline License Manager</div><div class="sub" id="identity"></div></div><div class="badge" id="status"></div></header><section id="setup" class="card hidden"><h2>首次设置</h2><div class="sub" id="setupHint">生成新密钥，或粘贴现有 PKCS#8 Ed25519 私钥。私钥会立即加密，明文不会写入磁盘。</div><label>现有私钥 PEM（可选）</label><textarea id="privateKeyPem"></textarea><div class="row"><div><label>加密密码</label><input id="setupPassword" type="password"></div><div><label>确认密码</label><input id="setupConfirm" type="password"></div></div><button class="primary" id="setupButton">安全初始化</button></section><section id="unlock" class="card hidden"><h2>解锁签名密钥</h2><label>本地私钥密码</label><input id="unlockPassword" type="password"><button class="primary" id="unlockButton">解锁</button></section><section id="manager" class="grid hidden"><div><div class="card"><h2>签发 License</h2><div class="row"><div><label>客户</label><input id="customer"></div><div><label>Plan</label><input id="plan" value="pro"></div></div><label>Features（逗号分隔，可选）</label><input id="features" placeholder="excel-export,cloud-sync"><label>过期 Unix 时间戳（可选）</label><input id="expiresAt" type="number"><label>备注</label><input id="note"><button class="primary" id="issueButton">生成 License</button><div class="result hidden" id="result"><label>License Code</label><textarea id="licenseCode" readonly></textarea><button id="copyButton">复制</button></div></div><div class="card" style="margin-top:22px"><h2>备份与恢复</h2><label>备份密码</label><input id="backupPassword" type="password"><div class="tools" style="margin-top:12px"><button id="manualBackup">创建手动备份</button><button id="icloudBackup">同时备份到 iCloud</button></div><label>恢复文件完整路径</label><input id="restorePath" placeholder="/Volumes/Backup/app.olmbackup"><button id="restoreButton" style="margin-top:12px">恢复到本机</button></div></div><div class="card"><div class="head" style="margin:0 0 10px"><h2>签发记录</h2><button id="lockButton">锁定</button></div><div id="records"></div></div></section></main><div class="toast" id="toast"></div><script>
const token=new URLSearchParams(location.search).get('token'),$=id=>document.getElementById(id);let state;const toast=t=>{const e=$('toast');e.textContent=t;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),2200)};async function api(path,body){const r=await fetch('/api/'+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Manager-Token':token},body:body?JSON.stringify(body):undefined});const d=await r.json();if(!r.ok)throw new Error(d.error);return d}function render(){ $('identity').textContent=state.appId+' · Major '+state.majorVersion+' · '+state.kid;$('status').textContent=!state.configured?'未设置':state.unlocked?'已解锁':'已锁定';$('setupHint').textContent=state.importAvailable?'已检测到现有签名私钥。设置密码后会将它加密导入，确保继续匹配当前 App。':'生成新密钥，或粘贴现有 PKCS#8 Ed25519 私钥。私钥会立即加密，明文不会写入磁盘。';$('setup').classList.toggle('hidden',state.configured);$('unlock').classList.toggle('hidden',!state.configured||state.unlocked);$('manager').classList.toggle('hidden',!state.unlocked);$('records').innerHTML=state.records.length?state.records.map(r=>'<div class="record"><b>'+esc(r.customer||'未填写客户')+'</b> · '+esc(r.payload.plan||'feature')+'<div class="meta">'+new Date(r.issuedAt).toLocaleString()+' · '+esc(r.payload.licenseId)+'</div><div class="code">'+esc(r.code)+'</div></div>').join(''):'<div class="sub">还没有签发记录</div>'}function esc(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function load(){state=await api('state');render()}$('setupButton').onclick=async()=>{if($('setupPassword').value!==$('setupConfirm').value)return toast('两次密码不一致');try{state=await api('setup',{privateKeyPem:$('privateKeyPem').value,password:$('setupPassword').value});render();toast('初始化成功')}catch(e){toast(e.message)}};$('unlockButton').onclick=async()=>{try{state=await api('unlock',{password:$('unlockPassword').value});render();toast('已解锁')}catch(e){toast(e.message)}};$('lockButton').onclick=async()=>{state=await api('lock',{});render()};$('issueButton').onclick=async()=>{try{const d=await api('issue',{customer:$('customer').value,plan:$('plan').value,features:$('features').value,expiresAt:$('expiresAt').value,note:$('note').value});state=d.state;$('licenseCode').value=d.issued.code;$('result').classList.remove('hidden');render();toast('License 已生成并记录')}catch(e){toast(e.message)}};$('copyButton').onclick=()=>navigator.clipboard.writeText($('licenseCode').value).then(()=>toast('已复制'));async function backup(iCloud){try{const d=await api('backup',{password:$('backupPassword').value,iCloud});toast(iCloud?'本地与 iCloud 备份完成':'手动备份已创建：'+d.result.outputFile)}catch(e){toast(e.message)}}$('manualBackup').onclick=()=>backup(false);$('icloudBackup').onclick=()=>backup(true);$('restoreButton').onclick=async()=>{if(!confirm('恢复将替换当前本机 Manager 数据，确定继续吗？'))return;try{const d=await api('restore',{backupFile:$('restorePath').value,password:$('backupPassword').value});state=d.state;render();toast('恢复成功，请重新解锁')}catch(e){toast(e.message)}};load().catch(e=>toast(e.message))
</script></body></html>`
