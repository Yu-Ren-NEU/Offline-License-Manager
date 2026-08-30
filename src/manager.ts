import http from "node:http";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  appendIssuedLicenseRecord,
  copyBackupToDirectory,
  createBackup,
  readIssuedLicenseRecords,
  restoreBackup,
} from "./backup.js";
import {
  decryptPrivateKey,
  encryptPrivateKey,
  generateSigningKeyPair,
  rawPublicKey,
} from "./crypto.js";
import { issueLicense } from "./issuer.js";

export type ManagerOptions = {
  dataDirectory: string;
  port?: number;
  openBrowser?: boolean;
};
type AppKeyInfo = {
  kid: string;
  publicKeyRaw: string;
  createdAt: string;
  status: "active" | "retired" | "pending";
};
type AppConfig = {
  appId: string;
  name: string;
  majorVersion: number;
  kid: string;
  publicKeyRaw: string;
  keys: AppKeyInfo[];
  deviceBinding: boolean;
  backupDirectory?: string;
};
type Keyring = {
  version: 1;
  keys: Record<
    string,
    {
      encryptedPrivateKey: unknown;
      publicKey: { kid: string; publicKey: string; publicKeyRaw: string };
    }
  >;
};

export async function startManager(options: ManagerOptions) {
  const appsDirectory = join(options.dataDirectory, "apps"),
    iCloudBase = join(
      homedir(),
      "Library",
      "Mobile Documents",
      "com~apple~CloudDocs",
      "Offline License Manager",
    );
  await mkdir(appsDirectory, { recursive: true });
  const token = randomBytes(24).toString("base64url"),
    sessions = new Map<string, { privateKey: string; password: string }>();
  const exists = async (file: string) =>
    access(file).then(
      () => true,
      () => false,
    );
  const appDirectory = (appId: string) => {
    if (!/^[A-Za-z0-9._-]+$/.test(appId))
      throw new Error("appId 只能包含字母、数字、点、下划线和连字符");
    return join(appsDirectory, appId);
  };
  const paths = (appId: string) => {
    const root = appDirectory(appId);
    return {
      root,
      config: join(root, "app.json"),
      key: join(root, "signing-key.olmkey"),
      publicKey: join(root, "public-key.json"),
      keyring: join(root, "keyring.json"),
      records: join(root, "licenses.json"),
      snapshots: join(root, "Backups"),
    };
  };
  const secureWrite = async (file: string, value: unknown, mode = 0o600) => {
    await writeFile(file, JSON.stringify(value, null, 2), { mode });
    await chmod(file, mode);
  };
  const readConfig = async (appId: string) => {
    const config = JSON.parse(
      await readFile(paths(appId).config, "utf8"),
    ) as AppConfig;
    if (typeof config.deviceBinding !== "boolean") config.deviceBinding = false;
    if (!Array.isArray(config.keys))
      config.keys = [
        {
          kid: config.kid,
          publicKeyRaw: config.publicKeyRaw,
          createdAt: new Date(0).toISOString(),
          status: "active",
        },
      ];
    return config;
  };
  const readKeyring = async (appId: string) => {
    const p = paths(appId);
    if (await exists(p.keyring))
      return JSON.parse(await readFile(p.keyring, "utf8")) as Keyring;
    const encryptedPrivateKey = JSON.parse(await readFile(p.key, "utf8")),
      publicKey = JSON.parse(await readFile(p.publicKey, "utf8")),
      keyring: Keyring = {
        version: 1,
        keys: { [publicKey.kid]: { encryptedPrivateKey, publicKey } },
      };
    await secureWrite(p.keyring, keyring);
    return keyring;
  };
  const generateKid = () => {
    const d = new Date(),
      part = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
    return `key-${part}-${randomBytes(3).toString("hex")}`;
  };
  const listApps = async () => {
    const { readdir } = await import("node:fs/promises"),
      entries = await readdir(appsDirectory, { withFileTypes: true });
    const apps: any[] = [];
    for (const entry of entries)
      if (entry.isDirectory() && (await exists(paths(entry.name).config))) {
        const config = await readConfig(entry.name),
          records = await readIssuedLicenseRecords(paths(entry.name).records);
        apps.push({
          ...config,
          recordCount: records.length,
          unlocked: sessions.has(config.appId),
        });
      }
    return apps.sort((a, b) => a.name.localeCompare(b.name));
  };
  const defaultBackupDirectory = async (appId: string) =>
    (await exists(
      join(homedir(), "Library", "Mobile Documents", "com~apple~CloudDocs"),
    ))
      ? join(iCloudBase, appId, "Backups")
      : "";
  const appState = async (appId: string) => {
    const config = await readConfig(appId),
      configuredDirectory =
        config.backupDirectory && (await exists(config.backupDirectory))
          ? config.backupDirectory
          : "";
    return {
      ...config,
      publicKeys: Object.fromEntries(
        config.keys.map((key) => [key.kid, key.publicKeyRaw]),
      ),
      unlocked: sessions.has(appId),
      records: await readIssuedLicenseRecords(paths(appId).records),
      defaultBackupDirectory:
        configuredDirectory || (await defaultBackupDirectory(appId)),
      iCloudAvailable: !!(await defaultBackupDirectory(appId)),
    };
  };
  const body = (req: http.IncomingMessage) =>
    new Promise<any>((resolve, reject) => {
      let value = "";
      req.on("data", (chunk) => {
        value += chunk;
        if (value.length > 2_000_000) reject(new Error("请求过大"));
      });
      req.on("end", () => {
        try {
          resolve(value ? JSON.parse(value) : {});
        } catch {
          reject(new Error("JSON 无法解析"));
        }
      });
      req.on("error", reject);
    });
  const send = (
    res: http.ServerResponse,
    status: number,
    value: unknown,
    type = "application/json; charset=utf-8",
  ) => {
    res.writeHead(status, {
      "Content-Type": type,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'none'; connect-src 'self'",
    });
    res.end(
      type.startsWith("application/json")
        ? JSON.stringify(value)
        : String(value),
    );
  };
  const chooseDirectory = () =>
    new Promise<string>((resolve, reject) =>
      execFile(
        "osascript",
        [
          "-e",
          'POSIX path of (choose folder with prompt "选择 License Manager 备份文件夹")',
        ],
        (error, stdout) =>
          error ? reject(new Error("未选择文件夹")) : resolve(stdout.trim()),
      ),
    );
  const readDeviceRequest = (code: string, config: AppConfig) => {
    try {
      const parts = code.trim().split(".");
      if (parts.length !== 2 || parts[0] !== "OLMR1") throw new Error();
      const request = JSON.parse(
        Buffer.from(parts[1], "base64url").toString("utf8"),
      );
      if (
        request.appId !== config.appId ||
        request.majorVersion !== config.majorVersion ||
        typeof request.deviceId !== "string" ||
        !request.deviceId
      )
        throw new Error();
      return request.deviceId as string;
    } catch {
      throw new Error("设备请求码无效，或不属于当前 App 和大版本");
    }
  };
  const snapshot = async (
    appId: string,
    password: string,
    destination?: string,
    automatic = true,
  ) => {
    const p = paths(appId),
      config = await readConfig(appId);
    await readKeyring(appId);
    await mkdir(p.snapshots, { recursive: true });
    const file = join(p.snapshots, `${appId}-latest.olmbackup`);
    const result = await createBackup({
      appId,
      encryptedKeyFile: p.key,
      publicKeyFile: p.publicKey,
      recordsFile: p.records,
      outputFile: file,
      password,
      configFile: p.config,
      keyringFile: p.keyring,
    });
    const target =
      destination ||
      config.backupDirectory ||
      (await defaultBackupDirectory(appId));
    const copied = target
      ? await copyBackupToDirectory({
          backupFile: file,
          appId,
          directory: target,
          ...(automatic ? { retainLatest: 10 } : {}),
        })
      : null;
    return { result, copied, needsDirectory: !target };
  };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", `http://${req.headers.host}`);
      if (req.method === "GET" && url.pathname === "/")
        return send(res, 200, HTML, "text/html; charset=utf-8");
      if (req.headers["x-manager-token"] !== token)
        return send(res, 403, { error: "本地会话令牌无效" });
      if (req.method === "GET" && url.pathname === "/api/apps")
        return send(res, 200, {
          apps: await listApps(),
          iCloudAvailable: await exists(
            join(
              homedir(),
              "Library",
              "Mobile Documents",
              "com~apple~CloudDocs",
            ),
          ),
        });
      if (req.method === "POST" && url.pathname === "/api/create-app") {
        const input = await body(req),
          appId = String(input.appId || "").trim(),
          name = String(input.name || "").trim() || appId,
          majorVersion = Number(input.majorVersion),
          kid = generateKid(),
          password = String(input.password || "");
        if (!appId || !Number.isSafeInteger(majorVersion) || majorVersion < 1)
          throw new Error("请填写有效的 App ID 和 Major Version");
        const p = paths(appId);
        if (await exists(p.config)) throw new Error("App ID 已存在");
        await mkdir(p.root, { recursive: true });
        const pair = generateSigningKeyPair();
        const publicKeyRaw = rawPublicKey(pair.publicKeyPem),
          encryptedPrivateKey = {
            kid,
            ...(await encryptPrivateKey(pair.privateKeyPem, password)),
          },
          publicRecord = { kid, publicKey: pair.publicKeyPem, publicKeyRaw },
          config: AppConfig = {
            appId,
            name,
            majorVersion,
            kid,
            publicKeyRaw,
            deviceBinding: input.deviceBinding === true,
            keys: [
              {
                kid,
                publicKeyRaw,
                createdAt: new Date().toISOString(),
                status: "active",
              },
            ],
            ...(input.backupDirectory
              ? { backupDirectory: String(input.backupDirectory) }
              : {}),
          },
          keyring: Keyring = {
            version: 1,
            keys: { [kid]: { encryptedPrivateKey, publicKey: publicRecord } },
          };
        await secureWrite(p.key, encryptedPrivateKey);
        await secureWrite(p.publicKey, publicRecord, 0o644);
        await secureWrite(p.keyring, keyring);
        await secureWrite(p.records, []);
        await secureWrite(p.config, config, 0o644);
        sessions.set(appId, { privateKey: pair.privateKeyPem, password });
        const backup = await snapshot(appId, password);
        return send(res, 200, { app: await appState(appId), backup });
      }
      if (req.method === "GET" && url.pathname === "/api/app")
        return send(
          res,
          200,
          await appState(String(url.searchParams.get("appId") || "")),
        );
      if (req.method === "POST" && url.pathname === "/api/unlock") {
        const input = await body(req),
          appId = String(input.appId || ""),
          password = String(input.password || ""),
          envelope = JSON.parse(await readFile(paths(appId).key, "utf8"));
        sessions.set(appId, {
          privateKey: await decryptPrivateKey(envelope, password),
          password,
        });
        return send(res, 200, await appState(appId));
      }
      if (req.method === "POST" && url.pathname === "/api/lock") {
        const input = await body(req);
        sessions.delete(String(input.appId || ""));
        return send(res, 200, await appState(String(input.appId || "")));
      }
      if (req.method === "POST" && url.pathname === "/api/rotate-key") {
        const input = await body(req),
          appId = String(input.appId || ""),
          session = sessions.get(appId);
        if (!session) throw new Error("请先解锁私钥");
        const config = await readConfig(appId);
        if (config.keys.some((key) => key.status === "pending"))
          throw new Error("已有待发布密钥，请先完成切换");
        const kid = generateKid(),
          pair = generateSigningKeyPair(),
          publicKeyRaw = rawPublicKey(pair.publicKeyPem),
          encryptedPrivateKey = {
            kid,
            ...(await encryptPrivateKey(pair.privateKeyPem, session.password)),
          },
          publicRecord = { kid, publicKey: pair.publicKeyPem, publicKeyRaw },
          keyring = await readKeyring(appId);
        keyring.keys[kid] = { encryptedPrivateKey, publicKey: publicRecord };
        config.keys.push({
          kid,
          publicKeyRaw,
          createdAt: new Date().toISOString(),
          status: "pending",
        });
        await secureWrite(paths(appId).keyring, keyring);
        await secureWrite(paths(appId).config, config, 0o644);
        const backup = await snapshot(appId, session.password);
        return send(res, 200, { app: await appState(appId), backup });
      }
      if (req.method === "POST" && url.pathname === "/api/activate-key") {
        const input = await body(req),
          appId = String(input.appId || ""),
          kid = String(input.kid || ""),
          session = sessions.get(appId);
        if (!session) throw new Error("请先解锁私钥");
        const config = await readConfig(appId),
          pending = config.keys.find(
            (key) => key.kid === kid && key.status === "pending",
          );
        if (!pending) throw new Error("找不到待发布密钥");
        const keyring = await readKeyring(appId),
          record = keyring.keys[kid];
        if (!record) throw new Error("密钥环数据不完整");
        const privateKey = await decryptPrivateKey(
          record.encryptedPrivateKey as any,
          session.password,
        );
        config.keys.forEach((key) => {
          if (key.status === "active") key.status = "retired";
        });
        pending.status = "active";
        config.kid = kid;
        config.publicKeyRaw = pending.publicKeyRaw;
        await secureWrite(paths(appId).key, record.encryptedPrivateKey);
        await secureWrite(paths(appId).publicKey, record.publicKey, 0o644);
        await secureWrite(paths(appId).config, config, 0o644);
        sessions.set(appId, { privateKey, password: session.password });
        const backup = await snapshot(appId, session.password);
        return send(res, 200, { app: await appState(appId), backup });
      }
      if (req.method === "POST" && url.pathname === "/api/issue") {
        const input = await body(req),
          appId = String(input.appId || ""),
          session = sessions.get(appId);
        if (!session) throw new Error("请先解锁私钥");
        const config = await readConfig(appId),
          features = String(input.features || "")
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
          deviceId = config.deviceBinding
            ? readDeviceRequest(String(input.deviceRequest || ""), config)
            : undefined;
        const issued = issueLicense(
          {
            appId,
            majorVersion: config.majorVersion,
          ...(deviceId ? { deviceId } : {}),
            kid: config.kid,
            ...(input.plan ? { plan: String(input.plan) } : {}),
            ...(features.length ? { features } : {}),
            ...(input.expiresAt ? { expiresAt: Number(input.expiresAt) } : {}),
          },
          session.privateKey,
        );
        await appendIssuedLicenseRecord(paths(appId).records, {
          payload: issued.payload,
          code: issued.code,
          issuedAt: new Date().toISOString(),
          ...(input.customer ? { customer: String(input.customer) } : {}),
          ...(input.note ? { note: String(input.note) } : {}),
        });
        const backup = await snapshot(appId, session.password);
        return send(res, 200, { issued, app: await appState(appId), backup });
      }
      if (req.method === "POST" && url.pathname === "/api/choose-directory")
        return send(res, 200, { directory: await chooseDirectory() });
      if (
        req.method === "POST" &&
        url.pathname === "/api/set-backup-directory"
      ) {
        const input = await body(req),
          config = await readConfig(input.appId);
        config.backupDirectory = String(input.directory || "");
        await secureWrite(paths(input.appId).config, config, 0o644);
        return send(res, 200, await appState(input.appId));
      }
      if (req.method === "POST" && url.pathname === "/api/export-backup") {
        const input = await body(req),
          session = sessions.get(input.appId);
        if (!session) throw new Error("请先解锁私钥");
        return send(
          res,
          200,
          await snapshot(
            input.appId,
            String(input.password || session.password),
            String(input.directory || ""),
            input.automatic === true,
          ),
        );
      }
      if (req.method === "POST" && url.pathname === "/api/restore") {
        const input = await body(req),
          appId = String(input.appId || "");
        sessions.delete(appId);
        const restored = await restoreBackup({
          backupFile: String(input.backupFile || ""),
          destination: paths(appId).root,
          password: String(input.password || ""),
          expectedAppId: appId,
        });
        return send(res, 200, { restored, app: await appState(appId) });
      }
      if (req.method === "POST" && url.pathname === "/api/restore-new") {
        const input = await body(req),
          temporary = await mkdtemp(join(options.dataDirectory, "restore-"));
        try {
          const restored = await restoreBackup({
            backupFile: String(input.backupFile || ""),
            destination: temporary,
            password: String(input.password || ""),
          });
          const target = paths(restored.appId).root;
          if (await exists(target))
            throw new Error("该 App 已存在，请进入 App 页面执行恢复");
          if (!(await exists(join(temporary, "app.json"))))
            throw new Error("旧备份缺少 App 配置，请先创建同一 App 再恢复");
          await rename(temporary, target);
          return send(res, 200, {
            restored,
            app: await appState(restored.appId),
          });
        } catch (error) {
          await rm(temporary, { recursive: true, force: true });
          throw error;
        }
      }
      send(res, 404, { error: "未找到接口" });
    } catch (error: any) {
      send(res, 400, { error: error?.message || "操作失败" });
    }
  });
  const port = options.port ?? 47831;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const address = server.address(),
    actualPort = typeof address === "object" && address ? address.port : port,
    url = `http://127.0.0.1:${actualPort}/?token=${token}`;
  if (options.openBrowser !== false) execFile("open", [url]);
  return { server, url };
}

const HTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline License Manager</title><style>
:root{--ink:#17211a;--green:#294e35;--paper:#f3f5ef;--line:#dfe6dc;--muted:#708074;--yellow:#f3ca52}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}.shell{width:min(1120px,calc(100% - 32px));margin:34px auto}.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.title{font-size:28px;font-weight:800}.sub,.meta{color:var(--muted);font-size:13px;line-height:1.55}.grid{display:grid;grid-template-columns:400px 1fr;gap:22px}.card{background:#fff;border-radius:20px;padding:24px;box-shadow:0 12px 34px #243b2b12}h2{margin:0 0 18px;font-size:19px}label{display:block;margin:14px 0 7px;font-weight:650}input,textarea{width:100%;border:1px solid var(--line);border-radius:12px;background:#f8faf6;padding:11px 13px;font:inherit}textarea{min-height:84px;resize:vertical;font-family:ui-monospace,monospace}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}button{border:0;border-radius:12px;padding:11px 15px;background:#eaf0e8;color:var(--green);font:inherit;font-weight:750;cursor:pointer}.primary{background:var(--green);color:#fff}.wide{width:100%;margin-top:18px}.hidden{display:none!important}.app-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}.app{cursor:pointer}.app:hover{outline:2px solid #adc4b2}.app-name{font-size:18px;font-weight:800;margin-bottom:7px}.record{padding:15px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:14px}.record:last-child{border:0}.record-main{min-width:0}.tools{display:flex;gap:8px;flex-wrap:wrap}.back{margin-bottom:16px}.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--ink);color:#fff;padding:10px 17px;border-radius:20px;opacity:0;transition:.2s;max-width:80%}.toast.show{opacity:1}@media(max-width:800px){.grid{grid-template-columns:1fr}.head{align-items:flex-start;flex-direction:column;gap:12px}}
.record-filter-bar{display:grid;grid-template-columns:180px 1fr;gap:10px;margin-bottom:8px}.plan-filter{position:relative}.plan-filter>button{width:100%;text-align:left;background:#f8faf6;border:1px solid var(--line)}.plan-filter-menu{position:absolute;z-index:10;top:calc(100% + 6px);left:0;min-width:220px;max-height:240px;overflow:auto;padding:8px 12px;background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 28px #243b2b20}.plan-filter-menu label{display:flex;align-items:center;gap:8px;margin:0;padding:8px 2px;font-weight:500}.plan-filter-menu input{width:auto}.record-filter-count{margin:8px 0 2px}@media(max-width:650px){.record-filter-bar{grid-template-columns:1fr}}
</style></head><body><main class="shell"><header class="head"><div><div class="title">Offline License Manager</div><div class="sub">纯本地签发 · 私钥加密保存 · 自动加密备份</div></div><div class="tools"><button id="restoreOpen">从备份恢复</button><button id="createOpen" class="primary">创建 App</button></div></header>
<section id="home"><div id="empty" class="card hidden"><h2>还没有 App</h2><div class="sub">先创建一个 App，系统会生成 Ed25519 密钥并用你的密码加密私钥。</div></div><div class="app-list" id="apps"></div></section>
<section id="create" class="card hidden"><button class="back" id="createBack">返回</button><h2>创建 App</h2><div class="row"><div><label>App 名称</label><input id="newName" placeholder="Lemon Note"></div><div><label>App ID</label><input id="newAppId" placeholder="app_lemon_note"></div></div><label>Major Version</label><input id="newMajor" type="number" value="1"><label><input id="newDeviceBinding" type="checkbox" style="width:auto;margin-right:8px">License 绑定到设备</label><div class="sub">开启后，每个激活码只能用于签发时指定的设备，创建后不可更改。</div><div class="row"><div><label>私钥加密密码</label><input id="newPassword" type="password"></div><div><label>确认密码</label><input id="newConfirm" type="password"></div></div><label>自动备份目录</label><div class="row"><input id="newBackupDir" placeholder="检测到 iCloud 时自动填入"><button id="chooseNewDir">选择文件夹</button></div><button class="primary wide" id="createButton">生成密钥并创建</button></section>
<section id="restoreNew" class="card hidden"><button class="back" id="restoreNewBack">返回</button><h2>在新机器恢复 App</h2><div class="sub">选择完整的 .olmbackup 文件，恢复 App 配置、加密私钥、公钥和全部签发记录。</div><label>备份文件完整路径</label><input id="restoreNewPath"><label>备份密码</label><input id="restoreNewPassword" type="password"><button class="primary wide" id="restoreNewButton">恢复到本机默认目录</button></section>
<section id="detail" class="hidden"><button class="back" id="detailBack">← 所有 App</button><div class="head"><div><h2 id="appTitle"></h2><div class="sub" id="appMeta"></div></div><div class="tools"><button id="lockButton">锁定</button></div></div><section id="unlock" class="card hidden"><h2>解锁私钥</h2><label>私钥密码</label><input id="unlockPassword" type="password"><button class="primary wide" id="unlockButton">解锁并管理</button></section><section id="workspace" class="grid hidden"><div><div class="card"><h2>签发 License</h2><div id="deviceRequestField" class="hidden"><label>设备请求码</label><textarea id="deviceRequest" placeholder="粘贴用户设备上显示的 OLMR1 请求码"></textarea></div><div class="row"><div><label>客户</label><input id="customer"></div><div><label>Plan</label><input id="plan" value="free"></div></div><label>Features（可选，逗号分隔）</label><input id="features"><label>过期 Unix 时间戳（可选）</label><input id="expiresAt" type="number"><label>备注</label><input id="note"><button class="primary wide" id="issueButton">生成 License</button></div><div class="card" style="margin-top:22px"><h2>密钥管理</h2><div class="sub">新 kid 自动生成。先把待发布公钥加入 App 并发布，再切换签发密钥。</div><div id="keys"></div><div class="tools" style="margin-top:12px"><button id="copyPublicKeys">复制公钥集合</button><button id="rotateKey">生成待发布密钥</button><button id="activatePending" class="hidden">确认切换待发布密钥</button></div></div><div class="card" style="margin-top:22px"><h2>备份与恢复</h2><div class="sub">创建 App 和每次签发后，都会用私钥密码自动生成完整加密备份；自动备份只保留最新 10 份。iCloud 可用时默认同步，否则请选择目录。</div><label>自动备份目录</label><div class="row"><input id="backupDir"><button id="chooseBackupDir">选择文件夹</button></div><button id="saveBackupDir" class="wide">保存目录并立即备份</button><label>导出到其他位置</label><button id="exportOther" class="wide">选择文件夹并导出加密备份</button><label>从备份恢复（完整路径）</label><input id="restorePath" placeholder="/Volumes/Backup/app.olmbackup"><button id="restoreButton" class="wide">恢复到本机</button></div></div><div class="card"><h2>签发记录</h2><div id="records"></div></div></section></section></main><div class="toast" id="toast"></div><script>
const token=new URLSearchParams(location.search).get('token'),$=id=>document.getElementById(id);let apps=[],app=null;const toast=t=>{const e=$('toast');e.textContent=t;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),2600)};async function api(path,body){const r=await fetch('/api/'+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Manager-Token':token},body:body?JSON.stringify(body):undefined});const d=await r.json();if(!r.ok)throw new Error(d.error);return d}const esc=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function show(id){['home','create','restoreNew','detail'].forEach(x=>$(x).classList.toggle('hidden',x!==id))}async function loadApps(){const d=await api('apps');apps=d.apps;$('apps').innerHTML=apps.map(a=>'<article class="card app" data-id="'+esc(a.appId)+'"><div class="app-name">'+esc(a.name)+'</div><div class="meta">'+esc(a.appId)+' · Major '+a.majorVersion+' · '+a.recordCount+' 条记录</div></article>').join('');$('empty').classList.toggle('hidden',apps.length>0);document.querySelectorAll('.app').forEach(e=>e.onclick=()=>openApp(e.dataset.id));if(d.iCloudAvailable&&!$('newBackupDir').value)$('newBackupDir').placeholder='将自动使用 iCloud Drive'}async function openApp(id){app=await api('app?appId='+encodeURIComponent(id));renderApp();show('detail')}function renderApp(){$('appTitle').textContent=app.name;$('appMeta').textContent=app.appId+' · Major '+app.majorVersion+' · '+(app.deviceBinding?'设备绑定':'不限设备')+' · '+app.kid;$('unlock').classList.toggle('hidden',app.unlocked);$('workspace').classList.toggle('hidden',!app.unlocked);$('lockButton').classList.toggle('hidden',!app.unlocked);$('backupDir').value=app.defaultBackupDirectory||'';$('deviceRequestField').classList.toggle('hidden',!app.deviceBinding);$('keys').innerHTML=app.keys.map(k=>'<div class="record"><div><b>'+esc(k.kid)+'</b><div class="meta">'+esc(k.status)+' · '+new Date(k.createdAt).toLocaleDateString()+'</div></div></div>').join('');$('activatePending').classList.toggle('hidden',!app.keys.some(k=>k.status==='pending'));$('records').innerHTML=app.records.length?app.records.map(r=>'<div class="record"><div class="record-main"><b>'+esc(r.customer||'未填写客户')+'</b> · '+esc(r.payload.plan||'feature')+'<div class="meta">'+new Date(r.issuedAt).toLocaleString()+' · '+esc(r.payload.licenseId)+'</div></div><button class="copy-license" data-code="'+esc(r.code)+'">复制 License</button></div>').join(''):'<div class="sub">还没有签发记录</div>';document.querySelectorAll('.copy-license').forEach(b=>b.onclick=()=>navigator.clipboard.writeText(b.dataset.code).then(()=>toast('License 已复制')))}$('createOpen').onclick=()=>show('create');$('restoreOpen').onclick=()=>show('restoreNew');$('createBack').onclick=()=>show('home');$('restoreNewBack').onclick=()=>show('home');$('detailBack').onclick=async()=>{await loadApps();show('home')};$('restoreNewButton').onclick=async()=>{try{const d=await api('restore-new',{backupFile:$('restoreNewPath').value,password:$('restoreNewPassword').value});app=d.app;renderApp();show('detail');toast('App 已恢复，请用私钥密码解锁')}catch(e){toast(e.message)}};async function choose(){return(await api('choose-directory',{})).directory}$('chooseNewDir').onclick=async()=>{try{$('newBackupDir').value=await choose()}catch(e){toast(e.message)}};$('createButton').onclick=async()=>{if($('newPassword').value!==$('newConfirm').value)return toast('两次密码不一致');try{const d=await api('create-app',{name:$('newName').value,appId:$('newAppId').value,majorVersion:Number($('newMajor').value),password:$('newPassword').value,deviceBinding:$('newDeviceBinding').checked,backupDirectory:$('newBackupDir').value});app=d.app;renderApp();show('detail');toast(d.backup.needsDirectory?'App 已创建，请选择自动备份目录':'App 已创建并完成加密备份')}catch(e){toast(e.message)}};$('unlockButton').onclick=async()=>{try{app=await api('unlock',{appId:app.appId,password:$('unlockPassword').value});renderApp();toast('已解锁')}catch(e){toast(e.message)}};$('lockButton').onclick=async()=>{app=await api('lock',{appId:app.appId});renderApp()};$('issueButton').onclick=async()=>{try{const d=await api('issue',{appId:app.appId,deviceRequest:$('deviceRequest').value,customer:$('customer').value,plan:$('plan').value,features:$('features').value,expiresAt:$('expiresAt').value,note:$('note').value});app=d.app;renderApp();await navigator.clipboard.writeText(d.issued.code);toast(d.backup.needsDirectory?'已签发并复制；请设置自动备份目录':'已签发、复制并自动备份')}catch(e){toast(e.message)}};$('chooseBackupDir').onclick=async()=>{try{$('backupDir').value=await choose()}catch(e){toast(e.message)}};$('saveBackupDir').onclick=async()=>{try{app=await api('set-backup-directory',{appId:app.appId,directory:$('backupDir').value});await api('export-backup',{appId:app.appId,directory:$('backupDir').value,automatic:true});renderApp();toast('目录已保存，备份完成')}catch(e){toast(e.message)}};$('exportOther').onclick=async()=>{try{const directory=await choose();await api('export-backup',{appId:app.appId,directory});toast('加密备份已导出')}catch(e){toast(e.message)}};$('restoreButton').onclick=async()=>{if(!confirm('恢复会替换当前 App 的本地管理数据，确定继续吗？'))return;try{const d=await api('restore',{appId:app.appId,backupFile:$('restorePath').value,password:$('unlockPassword').value});app=d.app;renderApp();toast('恢复成功，请用私钥密码重新解锁')}catch(e){toast(e.message)}};$('copyPublicKeys').onclick=()=>navigator.clipboard.writeText(JSON.stringify(app.publicKeys,null,2)).then(()=>toast('公钥集合已复制'));$('rotateKey').onclick=async()=>{if(!confirm('生成新密钥后，需要先更新并发布 App，确定继续吗？'))return;try{const d=await api('rotate-key',{appId:app.appId});app=d.app;renderApp();toast('待发布密钥已生成，请复制公钥集合并更新 App')}catch(e){toast(e.message)}};$('activatePending').onclick=async()=>{const pending=app.keys.find(k=>k.status==='pending');if(!pending||!confirm('确认 App 已包含新公钥并发布？切换后新 License 将使用新密钥。'))return;try{const d=await api('activate-key',{appId:app.appId,kid:pending.kid});app=d.app;renderApp();toast('新签发密钥已启用')}catch(e){toast(e.message)}};loadApps().then(()=>show('home')).catch(e=>toast(e.message))
</script><script>
(()=>{
  const baseRenderApp=renderApp
  let filterAppId='',selectedPlans=new Set()
  function decodeDeviceId(value){
    if(!app.deviceBinding)return ''
    try{
      const parts=String(value||'').trim().split('.')
      if(!((parts[0]==='OLM1'&&parts.length===3)||(parts[0]==='OLMR1'&&parts.length===2)))return ''
      let encoded=parts[1].replace(/-/g,'+').replace(/_/g,'/');while(encoded.length%4)encoded+='='
      const binary=atob(encoded),bytes=Uint8Array.from(binary,c=>c.charCodeAt(0)),payload=JSON.parse(new TextDecoder().decode(bytes))
      return typeof payload.deviceId==='string'?payload.deviceId:''
    }catch(_){return ''}
  }
  function applyRecordFilters(){
    if(!app)return
    const input=$('recordSearch'),rawQuery=String(input?.value||'').trim(),query=rawQuery.toLowerCase(),decodedDeviceId=decodeDeviceId(rawQuery)
    let visible=0
    Array.from($('records').children).forEach((element,index)=>{
      const record=app.records[index]
      if(!record){element.classList.toggle('hidden',!!query||selectedPlans.size>0);return}
      const plan=String(record.payload?.plan||''),planMatches=!selectedPlans.size||selectedPlans.has(plan)
      const searchable=[record.customer,(record.payload?.features||[]).join(' '),record.note,record.payload?.deviceId].filter(Boolean).join(' ').toLowerCase()
      const textMatches=!query||(decodedDeviceId?record.payload?.deviceId===decodedDeviceId:searchable.includes(query))
      const show=planMatches&&textMatches;element.classList.toggle('hidden',!show);if(show)visible++
    })
    $('recordFilterCount').textContent='显示 '+visible+' / '+app.records.length+' 条记录'
    $('recordNoResults').classList.toggle('hidden',visible>0||app.records.length===0)
  }
  function setupRecordFilters(){
    const records=$('records'),card=records.parentElement
    if(filterAppId!==app.appId){filterAppId=app.appId;selectedPlans=new Set()}
    let controls=$('recordFilters')
    if(!controls){
      controls=document.createElement('div');controls.id='recordFilters';controls.innerHTML='<div class="record-filter-bar"><div class="plan-filter"><button id="planFilterButton">Plan：全部 ▾</button><div id="planFilterMenu" class="plan-filter-menu hidden"></div></div><input id="recordSearch" placeholder="搜索姓名、Features、备注或粘贴激活码"></div><div id="recordFilterCount" class="meta record-filter-count"></div><div id="recordNoResults" class="sub hidden">没有符合条件的签发记录</div>'
      card.insertBefore(controls,records)
      $('planFilterButton').onclick=event=>{event.stopPropagation();$('planFilterMenu').classList.toggle('hidden')}
      $('planFilterMenu').onclick=event=>event.stopPropagation()
      $('recordSearch').oninput=applyRecordFilters
      document.addEventListener('click',()=>$('planFilterMenu')?.classList.add('hidden'))
    }
    const plans=[...new Set(app.records.map(record=>record.payload?.plan).filter(Boolean))].sort()
    selectedPlans=new Set([...selectedPlans].filter(plan=>plans.includes(plan)))
    $('planFilterMenu').innerHTML=plans.length?plans.map(plan=>'<label><input type="checkbox" value="'+esc(plan)+'" '+(selectedPlans.has(plan)?'checked':'')+'>'+esc(plan)+'</label>').join(''):'<div class="sub" style="padding:8px 2px">暂无 Plan</div>'
    $('planFilterMenu').querySelectorAll('input').forEach(box=>box.onchange=()=>{box.checked?selectedPlans.add(box.value):selectedPlans.delete(box.value);$('planFilterButton').textContent=selectedPlans.size?'Plan：'+[...selectedPlans].join('、')+' ▾':'Plan：全部 ▾';applyRecordFilters()})
    $('planFilterButton').textContent=selectedPlans.size?'Plan：'+[...selectedPlans].join('、')+' ▾':'Plan：全部 ▾'
    $('recordSearch').placeholder=app.deviceBinding?'搜索姓名、Features、备注，或粘贴激活码/设备请求码':'搜索姓名、Features 或备注'
    applyRecordFilters()
  }
  renderApp=function(){baseRenderApp();setupRecordFilters()}
})()
</script></body></html>`;
