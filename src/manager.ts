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
  plans: string[];
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
      throw new Error("appId may contain only letters, numbers, dots, underscores, and hyphens");
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
    if (!Array.isArray(config.plans)) config.plans = [];
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
        if (value.length > 2_000_000) reject(new Error("Request is too large"));
      });
      req.on("end", () => {
        try {
          resolve(value ? JSON.parse(value) : {});
        } catch {
          reject(new Error("JSON could not be parsed"));
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
          'POSIX path of (choose folder with prompt "Choose a License Manager backup folder")',
        ],
        (error, stdout) =>
          error ? reject(new Error("No folder selected")) : resolve(stdout.trim()),
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
      throw new Error("The device request is invalid or belongs to another app or major version");
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
        return send(res, 403, { error: "Invalid local session token" });
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
          throw new Error("Enter a valid App ID and Major Version");
        const p = paths(appId);
        if (await exists(p.config)) throw new Error("App ID already exists");
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
            plans: [],
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
      if (req.method === "POST" && url.pathname === "/api/create-plan") {
        const input = await body(req), appId = String(input.appId || ""), session = sessions.get(appId)
        if (!session) throw new Error("Unlock the private key first")
        const name = String(input.name || "").trim()
        if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) throw new Error("Plan names may contain only letters, numbers, dots, underscores, and hyphens")
        const config = await readConfig(appId)
        if (config.plans.some(plan => plan.toLowerCase() === name.toLowerCase())) throw new Error("Plan already exists")
        config.plans.push(name)
        await secureWrite(paths(appId).config, config, 0o644)
        const backup = await snapshot(appId, session.password)
        return send(res, 200, { app: await appState(appId), backup })
      }
      if (req.method === "POST" && url.pathname === "/api/rotate-key") {
        const input = await body(req),
          appId = String(input.appId || ""),
          session = sessions.get(appId);
        if (!session) throw new Error("Unlock the private key first");
        const config = await readConfig(appId);
        if (config.keys.some((key) => key.status === "pending"))
          throw new Error("A pending key already exists; finish the current rotation first");
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
        if (!session) throw new Error("Unlock the private key first");
        const config = await readConfig(appId),
          pending = config.keys.find(
            (key) => key.kid === kid && key.status === "pending",
          );
        if (!pending) throw new Error("Pending key not found");
        const keyring = await readKeyring(appId),
          record = keyring.keys[kid];
        if (!record) throw new Error("Keyring data is incomplete");
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
        if (!session) throw new Error("Unlock the private key first");
        const config = await readConfig(appId),
          features = String(input.features || "")
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
          deviceId = config.deviceBinding
            ? readDeviceRequest(String(input.deviceRequest || ""), config)
            : undefined;
        const plan = String(input.plan || "")
        if (!plan || !config.plans.includes(plan)) throw new Error("Choose an existing Plan before issuing")
        const issued = issueLicense(
          {
            appId,
            majorVersion: config.majorVersion,
          ...(deviceId ? { deviceId } : {}),
            kid: config.kid,
            plan,
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
        if (!session) throw new Error("Unlock the private key first");
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
            throw new Error("This App already exists; restore it from the App page");
          if (!(await exists(join(temporary, "app.json"))))
            throw new Error("This legacy backup has no App configuration; create the same App before restoring it");
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
      send(res, 404, { error: "Endpoint not found" });
    } catch (error: any) {
      send(res, 400, { error: error?.message || "Operation failed" });
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
:root{--ink:#17211a;--green:#294e35;--paper:#f3f5ef;--line:#dfe6dc;--muted:#708074;--yellow:#f3ca52}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}.shell{width:min(1120px,calc(100% - 32px));margin:34px auto}.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.title{font-size:28px;font-weight:800}.sub,.meta{color:var(--muted);font-size:13px;line-height:1.55}.grid{display:grid;grid-template-columns:400px 1fr;gap:22px}.card{background:#fff;border-radius:20px;padding:24px;box-shadow:0 12px 34px #243b2b12}h2{margin:0 0 18px;font-size:19px}label{display:block;margin:14px 0 7px;font-weight:650}input,textarea,select{width:100%;border:1px solid var(--line);border-radius:12px;background:#f8faf6;padding:11px 13px;font:inherit}textarea{min-height:84px;resize:vertical;font-family:ui-monospace,monospace}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}button{border:0;border-radius:12px;padding:11px 15px;background:#eaf0e8;color:var(--green);font:inherit;font-weight:750;cursor:pointer}.primary{background:var(--green);color:#fff}.wide{width:100%;margin-top:18px}.hidden{display:none!important}.app-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}.app{cursor:pointer}.app:hover{outline:2px solid #adc4b2}.app-name{font-size:18px;font-weight:800;margin-bottom:7px}.record{padding:15px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:14px}.record:last-child{border:0}.record-main{min-width:0}.tools{display:flex;gap:8px;flex-wrap:wrap}.back{margin-bottom:16px}.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--ink);color:#fff;padding:10px 17px;border-radius:20px;opacity:0;transition:.2s;max-width:80%}.toast.show{opacity:1}@media(max-width:800px){.grid{grid-template-columns:1fr}.head{align-items:flex-start;flex-direction:column;gap:12px}}
.record-filter-bar{display:grid;grid-template-columns:180px 1fr;gap:10px;margin-bottom:8px}.plan-filter{position:relative}.plan-filter>button{width:100%;display:flex;align-items:center;justify-content:space-between;gap:12px;text-align:left;background:#f8faf6;border:1px solid var(--line)}.plan-filter-menu{position:absolute;z-index:10;top:calc(100% + 6px);left:0;min-width:220px;max-height:240px;overflow:auto;padding:8px 12px;background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 28px #243b2b20}.plan-filter-menu label{display:flex;align-items:center;gap:8px;margin:0;padding:8px 2px;font-weight:500}.plan-filter-menu input{width:auto}.record-filter-count{margin:8px 0 2px}@media(max-width:650px){.record-filter-bar{grid-template-columns:1fr}}
</style></head><body><main class="shell"><header class="head"><div><div class="title">Offline License Manager</div><div class="sub">Local issuance · Encrypted private keys · Automatic encrypted backups</div></div><div class="tools"><button id="restoreOpen">Restore from Backup</button><button id="createOpen" class="primary">Create App</button></div></header>
<section id="home"><div id="empty" class="card hidden"><h2>No Apps yet</h2><div class="sub">Create an App to generate an Ed25519 key pair. Your password encrypts the private key.</div></div><div class="app-list" id="apps"></div></section>
<section id="create" class="card hidden"><button class="back" id="createBack">Back</button><h2>Create App</h2><div class="row"><div><label>App Name</label><input id="newName" placeholder="Lemon Note"></div><div><label>App ID</label><input id="newAppId" placeholder="app_lemon_note"></div></div><label>Major Version</label><input id="newMajor" type="number" value="1"><label><input id="newDeviceBinding" type="checkbox" style="width:auto;margin-right:8px">Bind licenses to devices</label><div class="sub">When enabled, each license works only on the device specified at issuance. This setting cannot be changed later.</div><div class="row"><div><label>Private Key Password</label><input id="newPassword" type="password"></div><div><label>Confirm Password</label><input id="newConfirm" type="password"></div></div><label>Automatic Backup Folder</label><div class="row"><input id="newBackupDir" placeholder="Uses iCloud Drive automatically when available"><button id="chooseNewDir">Choose Folder</button></div><button class="primary wide" id="createButton">Generate Key and Create</button></section>
<section id="restoreNew" class="card hidden"><button class="back" id="restoreNewBack">Back</button><h2>Restore App on a New Machine</h2><div class="sub">Select a complete .olmbackup file to restore the App configuration, encrypted private keys, public keys, and all issued-license records.</div><label>Full Backup File Path</label><input id="restoreNewPath"><label>Backup Password</label><input id="restoreNewPassword" type="password"><button class="primary wide" id="restoreNewButton">Restore to Default Local Folder</button></section>
<section id="detail" class="hidden"><button class="back" id="detailBack">← All Apps</button><div class="head"><div><h2 id="appTitle"></h2><div class="sub" id="appMeta"></div></div><div class="tools"><button id="lockButton">Lock</button></div></div><section id="unlock" class="card hidden"><h2>Unlock Private Key</h2><label>Private Key Password</label><input id="unlockPassword" type="password"><button class="primary wide" id="unlockButton">Unlock and Manage</button></section><section id="workspace" class="grid hidden"><div><div class="card"><h2>Issue License</h2><div id="deviceRequestField" class="hidden"><label>Device Request</label><textarea id="deviceRequest" placeholder="Paste the OLMR1 request shown on the user device"></textarea></div><div class="row"><div><label>Customer</label><input id="customer"></div><div><label>Plan</label><div class="plan-filter"><input id="plan" type="hidden"><button id="planSelectButton"><span id="planSelectValue">Choose a Plan</span><span>▾</span></button><div id="planSelectMenu" class="plan-filter-menu hidden"></div></div></div></div><label>Features (optional, comma-separated)</label><input id="features"><label>Expiration Unix Timestamp (optional)</label><input id="expiresAt" type="number"><label>Note</label><textarea id="note"></textarea><button class="primary wide" id="issueButton">Generate License</button></div><div class="card" style="margin-top:22px"><h2>Key Management</h2><div class="sub">New key IDs are generated automatically. Add and release the pending public key in your App before switching the signing key.</div><div id="keys"></div><div class="tools" style="margin-top:12px"><button id="copyPublicKeys">Copy Public Key Set</button><button id="rotateKey">Generate Pending Key</button><button id="activatePending" class="hidden">Activate Pending Key</button></div></div><div class="card" style="margin-top:22px"><h2>Backup & Recovery</h2><div class="sub">A complete encrypted backup is created after App creation and every issuance. Automatic backups keep the latest 10 snapshots. iCloud Drive is used by default when available.</div><label>Automatic Backup Folder</label><div class="row"><input id="backupDir"><button id="chooseBackupDir">Choose Folder</button></div><button id="saveBackupDir" class="wide">Save Folder and Back Up Now</button><label>Export to Another Location</label><button id="exportOther" class="wide">Choose Folder and Export Encrypted Backup</button><label>Restore from Backup (full path)</label><input id="restorePath" placeholder="/Volumes/Backup/app.olmbackup"><button id="restoreButton" class="wide">Restore Locally</button></div></div><div class="card"><h2>Issued Licenses</h2><div id="records"></div></div></section></section></main><div class="toast" id="toast"></div><script>
const token=new URLSearchParams(location.search).get('token'),$=id=>document.getElementById(id);let apps=[],app=null;const toast=t=>{const e=$('toast');e.textContent=t;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),2600)};async function api(path,body){const r=await fetch('/api/'+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Manager-Token':token},body:body?JSON.stringify(body):undefined});const d=await r.json();if(!r.ok)throw new Error(d.error);return d}const esc=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function show(id){['home','create','restoreNew','detail'].forEach(x=>$(x).classList.toggle('hidden',x!==id))}async function loadApps(){const d=await api('apps');apps=d.apps;$('apps').innerHTML=apps.map(a=>'<article class="card app" data-id="'+esc(a.appId)+'"><div class="app-name">'+esc(a.name)+'</div><div class="meta">'+esc(a.appId)+' · Major '+a.majorVersion+' · '+a.recordCount+' records</div></article>').join('');$('empty').classList.toggle('hidden',apps.length>0);document.querySelectorAll('.app').forEach(e=>e.onclick=()=>openApp(e.dataset.id));if(d.iCloudAvailable&&!$('newBackupDir').value)$('newBackupDir').placeholder='iCloud Drive will be used automatically'}async function openApp(id){app=await api('app?appId='+encodeURIComponent(id));renderApp();show('detail')}function renderApp(){$('appTitle').textContent=app.name;$('appMeta').textContent=app.appId+' · Major '+app.majorVersion+' · '+(app.deviceBinding?'Device-bound':'Portable')+' · '+app.kid;$('unlock').classList.toggle('hidden',app.unlocked);$('workspace').classList.toggle('hidden',!app.unlocked);$('lockButton').classList.toggle('hidden',!app.unlocked);$('backupDir').value=app.defaultBackupDirectory||'';$('deviceRequestField').classList.toggle('hidden',!app.deviceBinding);$('keys').innerHTML=app.keys.map(k=>'<div class="record"><div><b>'+esc(k.kid)+'</b><div class="meta">'+esc(k.status)+' · '+new Date(k.createdAt).toLocaleDateString()+'</div></div></div>').join('');$('activatePending').classList.toggle('hidden',!app.keys.some(k=>k.status==='pending'));$('records').innerHTML=app.records.length?app.records.map(r=>'<div class="record"><div class="record-main"><b>'+esc(r.customer||'Unnamed customer')+'</b> · '+esc(r.payload.plan||'feature')+'<div class="meta">'+new Date(r.issuedAt).toLocaleString()+' · '+esc(r.payload.licenseId)+'</div></div><button class="copy-license" data-code="'+esc(r.code)+'">Copy License</button></div>').join(''):'<div class="sub">No issued licenses yet</div>';document.querySelectorAll('.copy-license').forEach(b=>b.onclick=()=>navigator.clipboard.writeText(b.dataset.code).then(()=>toast('License copied')))}$('createOpen').onclick=()=>show('create');$('restoreOpen').onclick=()=>show('restoreNew');$('createBack').onclick=()=>show('home');$('restoreNewBack').onclick=()=>show('home');$('detailBack').onclick=async()=>{await loadApps();show('home')};$('restoreNewButton').onclick=async()=>{try{const d=await api('restore-new',{backupFile:$('restoreNewPath').value,password:$('restoreNewPassword').value});app=d.app;renderApp();show('detail');toast('App restored. Unlock it with the private key password.')}catch(e){toast(e.message)}};async function choose(){return(await api('choose-directory',{})).directory}$('chooseNewDir').onclick=async()=>{try{$('newBackupDir').value=await choose()}catch(e){toast(e.message)}};$('createButton').onclick=async()=>{if($('newPassword').value!==$('newConfirm').value)return toast('Passwords do not match');try{const d=await api('create-app',{name:$('newName').value,appId:$('newAppId').value,majorVersion:Number($('newMajor').value),password:$('newPassword').value,deviceBinding:$('newDeviceBinding').checked,backupDirectory:$('newBackupDir').value});app=d.app;renderApp();show('detail');toast(d.backup.needsDirectory?'App created. Choose an automatic backup folder.':'App created and encrypted backup completed.')}catch(e){toast(e.message)}};$('unlockButton').onclick=async()=>{try{app=await api('unlock',{appId:app.appId,password:$('unlockPassword').value});renderApp();toast('Unlocked')}catch(e){toast(e.message)}};$('lockButton').onclick=async()=>{app=await api('lock',{appId:app.appId});renderApp()};$('issueButton').onclick=async()=>{try{const d=await api('issue',{appId:app.appId,deviceRequest:$('deviceRequest').value,customer:$('customer').value,plan:$('plan').value,features:$('features').value,expiresAt:$('expiresAt').value,note:$('note').value});app=d.app;renderApp();await navigator.clipboard.writeText(d.issued.code);toast(d.backup.needsDirectory?'License issued and copied. Set an automatic backup folder.':'License issued, copied, and backed up.')}catch(e){toast(e.message)}};$('chooseBackupDir').onclick=async()=>{try{$('backupDir').value=await choose()}catch(e){toast(e.message)}};$('saveBackupDir').onclick=async()=>{try{app=await api('set-backup-directory',{appId:app.appId,directory:$('backupDir').value});await api('export-backup',{appId:app.appId,directory:$('backupDir').value,automatic:true});renderApp();toast('Folder saved and backup completed.')}catch(e){toast(e.message)}};$('exportOther').onclick=async()=>{try{const directory=await choose();await api('export-backup',{appId:app.appId,directory});toast('Encrypted backup exported.')}catch(e){toast(e.message)}};$('restoreButton').onclick=async()=>{if(!confirm('Restoring will replace this App’s local manager data. Continue?'))return;try{const d=await api('restore',{appId:app.appId,backupFile:$('restorePath').value,password:$('unlockPassword').value});app=d.app;renderApp();toast('Restore completed. Unlock again with the private key password.')}catch(e){toast(e.message)}};$('copyPublicKeys').onclick=()=>navigator.clipboard.writeText(JSON.stringify(app.publicKeys,null,2)).then(()=>toast('Public key set copied.'));$('rotateKey').onclick=async()=>{if(!confirm('After generating a new key, you must update and release the App before activating it. Continue?'))return;try{const d=await api('rotate-key',{appId:app.appId});app=d.app;renderApp();toast('Pending key generated. Copy the public key set and update the App.')}catch(e){toast(e.message)}};$('activatePending').onclick=async()=>{const pending=app.keys.find(k=>k.status==='pending');if(!pending||!confirm('Has the App been released with the new public key? New licenses will use the new key after activation.'))return;try{const d=await api('activate-key',{appId:app.appId,kid:pending.kid});app=d.app;renderApp();toast('New signing key activated.')}catch(e){toast(e.message)}};loadApps().then(()=>show('home')).catch(e=>toast(e.message))
</script><script>
(()=>{
  const baseRenderApp=renderApp
  const baseOpenApp=openApp
  let filterAppId='',selectedPlans=new Set(),lastAutofillDeviceId=''
  $('unlockPassword').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.isComposing){event.preventDefault();$('unlockButton').click()}})
  openApp=async function(id){await baseOpenApp(id);if(!app.unlocked)requestAnimationFrame(()=>$('unlockPassword').focus())}
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
    $('recordFilterCount').textContent='Showing '+visible+' of '+app.records.length+' records'
    $('recordNoResults').classList.toggle('hidden',visible>0||app.records.length===0)
  }
  function setupRecordFilters(){
    const records=$('records'),card=records.parentElement
    if(filterAppId!==app.appId){filterAppId=app.appId;selectedPlans=new Set()}
    let controls=$('recordFilters')
    if(!controls){
      controls=document.createElement('div');controls.id='recordFilters';controls.innerHTML='<div class="record-filter-bar"><div class="plan-filter"><button id="planFilterButton"><span>Plan:</span><span id="planFilterValue">All ▾</span></button><div id="planFilterMenu" class="plan-filter-menu hidden"></div></div><input id="recordSearch" placeholder="Search customer, features, note, or paste a license"></div><div id="recordFilterCount" class="meta record-filter-count"></div><div id="recordNoResults" class="sub hidden">No issued licenses match these filters</div>'
      card.insertBefore(controls,records)
      $('planFilterButton').onclick=event=>{event.stopPropagation();$('planFilterMenu').classList.toggle('hidden')}
      $('planFilterMenu').onclick=event=>event.stopPropagation()
      $('recordSearch').oninput=applyRecordFilters
      document.addEventListener('click',()=>{$('planFilterMenu')?.classList.add('hidden');$('planSelectMenu')?.classList.add('hidden')})
    }
    const plans=[...new Set(app.records.map(record=>record.payload?.plan).filter(Boolean))].sort()
    selectedPlans=new Set([...selectedPlans].filter(plan=>plans.includes(plan)))
    $('planFilterMenu').innerHTML=plans.length?plans.map(plan=>'<label><input type="checkbox" value="'+esc(plan)+'" '+(selectedPlans.has(plan)?'checked':'')+'>'+esc(plan)+'</label>').join(''):'<div class="sub" style="padding:8px 2px">No plans yet</div>'
    $('planFilterMenu').querySelectorAll('input').forEach(box=>box.onchange=()=>{box.checked?selectedPlans.add(box.value):selectedPlans.delete(box.value);$('planFilterValue').textContent=selectedPlans.size?[...selectedPlans].join(', ')+' ▾':'All ▾';applyRecordFilters()})
    $('planFilterValue').textContent=selectedPlans.size?[...selectedPlans].join(', ')+' ▾':'All ▾'
    $('recordSearch').placeholder=app.deviceBinding?'Search customer, features, note, or paste a license/device request':'Search customer, features, or note'
    applyRecordFilters()
  }
  function selectPlan(name){
    const selected=app.plans.includes(name)?name:''
    $('plan').value=selected;$('planSelectValue').textContent=selected||'Choose a Plan'
    $('planSelectMenu').querySelectorAll('input').forEach(input=>input.checked=input.value===selected)
  }
  function setupPlanCatalog(){
    let manager=$('planManager')
    if(!manager){
      manager=document.createElement('div');manager.id='planManager';manager.className='card';manager.style.marginBottom='22px';manager.innerHTML='<h2>Create Plan</h2><div class="sub">Plans are ordered from oldest to newest. Licenses can use only Plans created here.</div><div id="planCatalog" class="meta" style="margin-top:12px"></div><div class="row" style="grid-template-columns:1fr auto;margin-top:12px"><input id="newPlanName" placeholder="e.g. free or pro"><button id="createPlanButton">Create Plan</button></div>'
      const issueCard=$('issueButton').closest('.card');issueCard.parentElement.insertBefore(manager,issueCard)
      $('createPlanButton').onclick=async()=>{try{const d=await api('create-plan',{appId:app.appId,name:$('newPlanName').value});app=d.app;$('newPlanName').value='';renderApp();toast('Plan created and backed up.')}catch(error){toast(error.message)}}
      $('newPlanName').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.isComposing){event.preventDefault();$('createPlanButton').click()}})
    }
    $('planCatalog').textContent=app.plans.length?app.plans.map((plan,index)=>(index+1)+'. '+plan).join('  →  '):'No Plans yet.'
    if(!$('planSelectButton').dataset.ready){
      $('planSelectButton').dataset.ready='true';$('planSelectButton').onclick=event=>{event.stopPropagation();$('planSelectMenu').classList.toggle('hidden')};$('planSelectMenu').onclick=event=>event.stopPropagation()
    }
    const current=$('plan').value
    $('planSelectMenu').innerHTML=app.plans.length?app.plans.map(plan=>'<label><input type="radio" name="issuePlan" value="'+esc(plan)+'">'+esc(plan)+'</label>').join(''):'<div class="sub" style="padding:8px 2px">No Plans yet.</div>'
    $('planSelectMenu').querySelectorAll('input').forEach(input=>input.onchange=()=>{selectPlan(input.value);$('planSelectMenu').classList.add('hidden')})
    selectPlan(current)
  }
  function setupDeviceAutofill(){
    const field=$('deviceRequest')
    field.oninput=()=>{
      const deviceId=decodeDeviceId(field.value)
      if(!deviceId){lastAutofillDeviceId='';return}
      if(deviceId===lastAutofillDeviceId)return
      lastAutofillDeviceId=deviceId
      const previous=app.records.find(record=>record.payload?.deviceId===deviceId)
      if(!previous)return
      if(previous.customer)$('customer').value=previous.customer
      const subject=previous.customer||'This device',previousPlan=previous.payload?.plan,latestPlan=app.plans[app.plans.length-1]
      if(latestPlan)selectPlan(latestPlan)
      if(previousPlan&&latestPlan&&previousPlan!==latestPlan)toast(subject+' currently has '+previousPlan+'. '+latestPlan+' was selected as the newest Plan.')
      else if(previousPlan)toast(subject+' already has the latest '+previousPlan+' Plan.')
      else toast(subject+' has already received a license.')
    }
  }
  renderApp=function(){baseRenderApp();if(filterAppId!==app.appId)lastAutofillDeviceId='';setupPlanCatalog();setupRecordFilters();setupDeviceAutofill()}
})()
</script></body></html>`;
