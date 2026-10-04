// 证据归档服务（独立进程，零依赖 Node ≥20）：网页 + HTTP 接口。
//   导入带签名的离线证据包 → 规范化哈希/Ed25519 验签/哈希链校验 → 按 packageId 归档
//   → 生成可阅读、可下载（JSON/TXT/HTML）的脱敏核验报告。
//
// 密钥纪律（页面与日志绝不泄露）：
//   - upload secret：仅经 X-Upload-Secret 请求头校验（常量时间比较），
//     任何响应/日志/导出只出现为 ***REDACTED***，且永不回显；
//   - 网关私钥：服务从不持有；注册 API 只收公钥 PEM；
//   - 拒绝信封落盘 0600，读取出口一律 redact。
import { createServer } from 'node:http';
import { readFile, appendFile, mkdir } from 'node:fs/promises';
import { mkdirSync, chmodSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { ArchiveManager } from './archive.js';
import { buildReport, exportRedactedJSON, renderText, renderHTMLFragment } from './report.js';
import {
  GatewayRegistry, loadOrCreateUploadSecret, safeEqual, generateGatewayKeyPair,
} from './crypto.js';
import { redact, safeLog } from './hashing.js';
import { RetentionService, RetentionError } from './retention.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const DATA_DIR = process.env.EVIDENCE_DIR || join(__dirname, '..', 'data', 'evidence');
const PORT = Number(process.env.EVIDENCE_PORT || 8092);
const HOST = process.env.EVIDENCE_HOST || '127.0.0.1';

export class EvidenceLogger {
  // file 为 null 时仅 stdout。写入前统一过 safeLog 白名单 + 密钥字面量打码。
  constructor(file, { secret = '' } = {}) {
    this.file = file;
    this.secret = secret;
    if (file) {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      try { chmodSync(file, 0o600); } catch { /* 文件尚不存在时忽略 */ }
    }
  }

  log(fields) {
    const clean = safeLog({ at: new Date().toISOString(), ...fields }, this.secret ? [this.secret] : []);
    const line = JSON.stringify(clean);
    process.stdout.write(line + '\n');
    if (this.file) appendFile(this.file, line + '\n', { mode: 0o600 }).catch(() => {});
  }
}

export async function createApp(deps = {}) {
  await mkdir(DATA_DIR, { recursive: true });
  const dataDir = deps.dataDir ?? DATA_DIR;
  await mkdir(dataDir, { recursive: true });
  const manager = deps.manager ?? new ArchiveManager(dataDir);
  const registry = deps.registry ?? new GatewayRegistry(join(dataDir, 'gateways.json'));
  const secretInfo = deps.secretInfo ?? loadOrCreateUploadSecret(
    join(dataDir, 'upload-secret.json'), process.env.EVIDENCE_UPLOAD_SECRET);
  const uploadSecret = deps.uploadSecret ?? secretInfo.secret;
  const logger = deps.logger ?? new EvidenceLogger(join(dataDir, 'audit-server.log'), { secret: uploadSecret });
  // 保留期限 / 证据保全 / 到期销毁（全局保留链 + 每包凭据旁车）。构造时自动恢复中断的销毁。
  const retention = deps.retention ?? new RetentionService(dataDir, {
    clock: deps.clock,
    fs: deps.fs,
    onDestroyed: (packageId) => manager.evict(packageId),
  });

  const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.txt': 'text/plain; charset=utf-8',
  };

  function send(res, status, body, headers = {}) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  }

  function requireSecret(req) {
    const got = req.headers['x-upload-secret'];
    // 无 header / 值错误一律 401；响应不回显任何提交内容。
    if (typeof got !== 'string' || !safeEqual(got, uploadSecret)) {
      throw Object.assign(new Error('缺少或无效的 X-Upload-Secret'), { code: 'UNAUTHORIZED', status: 401 });
    }
  }

  function readBody(req) {
    if (req.method === 'GET' || req.method === 'HEAD') return Promise.resolve({});
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (c) => {
        data += c;
        if (data.length > 5_000_000) reject(Object.assign(new Error('证据包过大（上限 5MB）'), { status: 413, code: 'BODY_TOO_LARGE' }));
      });
      req.on('end', () => {
        if (!data.trim()) return resolve({});
        try { resolve(JSON.parse(data)); }
        catch { reject(Object.assign(new Error('非法 JSON'), { status: 400, code: 'BAD_JSON' })); }
      });
      req.on('error', reject);
    });
  }

  async function serveStatic(req, res) {
    let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (path === '/') path = '/index.html';
    const file = normalize(join(PUBLIC_DIR, path));
    if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, { error: 'forbidden' });
    try {
      const buf = await readFile(file);
      res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
      res.end(buf);
    } catch {
      send(res, 404, { error: 'not found' });
    }
  }

  function packageView(packageId) {
    const archive = manager.open(packageId);
    const report = buildReport(archive);
    return report;
  }

  // 销毁读闸：COMMITTING / DESTROYED 的包，任何“证据读取”统一返回已销毁状态（410），
  // 不可能看到部分删除；销毁提交之前仍返回完整旧报告。
  function destroyedGate(packageId) {
    return retention.destroyedView(packageId);
  }

  // 读取证据前过闸：已提交销毁统一 410 + 销毁状态（不含任何原始证据）。
  function requireNotDestroyed(packageId) {
    const d = destroyedGate(packageId);
    if (d) {
      throw Object.assign(new Error(d.note), { code: 'PACKAGE_DESTROYED', status: 410, details: d });
    }
  }

  // 在完整报告上附加保留/保全状态（仅 ACTIVE 包）。
  function withRetention(report) {
    const st = retention.status(report.packageId);
    if (st && st.destroyedState) return null; // 已进入销毁：调用方应走 410
    return {
      ...report,
      retention: st ? {
        retention: st.retention,
        activeHoldCount: st.activeHoldCount,
        holds: st.holds,
        destructionDue: st.destructionDue,
      } : { retention: null, activeHoldCount: 0, holds: [], destructionDue: false },
    };
  }

  // 进程级重启等价物：丢弃所有缓存的归档对象，从磁盘重放重建。
  function restartFromDisk() {
    manager.cache.clear();
    // 保留/保全/销毁状态机也从全局保留链重放（reload 会自动续完中断的销毁）。
    retention.reload();
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    const at = new Date().toISOString();
    try {
      if (req.method === 'GET' && !path.startsWith('/api')) return await serveStatic(req, res);

      const body = await readBody(req);

      // ---------- 网关公钥注册 ----------
      if (path === '/api/gateways' && req.method === 'GET') {
        return send(res, 200, { gateways: registry.list() });
      }
      if (path === '/api/gateways' && req.method === 'POST') {
        requireSecret(req);
        const { gatewayId, keyId, publicKeyPem, note } = body;
        if (!gatewayId || !keyId || !publicKeyPem || typeof publicKeyPem !== 'string') {
          throw Object.assign(new Error('gatewayId/keyId/publicKeyPem 必填'), { code: 'ENVELOPE_MALFORMED', status: 400 });
        }
        if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) {
          throw Object.assign(new Error('只接受 SPKI PEM 公钥，绝不接受私钥'), { code: 'PRIVATE_KEY_REJECTED', status: 400 });
        }
        const g = registry.register({
          gatewayId: String(gatewayId), keyId: String(keyId),
          publicKeyPem: String(publicKeyPem), createdAt: at, note: note ? String(note) : null,
        });
        logger.log({ level: 'info', msg: 'gateway-registered', gatewayId: g.gatewayId, keyId: g.keyId });
        return send(res, 201, { gatewayId: g.gatewayId, keyId: g.keyId, createdAt: g.createdAt });
      }

      // ---------- 包列表 / 状态 ----------
      if (path === '/api/packages' && req.method === 'GET') {
        const ids = manager.list();
        const destroyedIds = new Set();
        const items = ids.map((id) => {
          const r = packageView(id);
          const st = retention.status(id);
          const destroyed = st?.destroyedState ? st : null;
          if (destroyed) destroyedIds.add(id);
          return {
            packageId: id,
            reportDigest: r.reportDigest,
            currentFence: r.currentFence,
            currentProgress: r.currentProgress,
            acceptedRecordCount: r.acceptedRecordCount,
            conflictCount: r.conflictCount,
            fenceCount: r.fenceCount,
            retention: st && !destroyed ? {
              retention: st.retention,
              activeHoldCount: st.activeHoldCount,
              destructionDue: st.destructionDue,
              holdCases: st.holds.filter((h) => h.active).map((h) => h.caseNo),
            } : null,
            destroyedState: destroyed?.destroyedState || null,
            destructionId: destroyed?.destructionId || null,
          };
        });
        // 已物理删除目录但保留链仍有墓碑的包（重启后 manager.list 不再包含它们）。
        for (const st of retention.listAll()) {
          if (!st || !st.destroyedState) continue;
          if (destroyedIds.has(st.packageId)) continue;
          items.push({
            packageId: st.packageId,
            reportDigest: null,
            currentFence: null,
            currentProgress: null,
            acceptedRecordCount: 0,
            conflictCount: 0,
            fenceCount: 0,
            retention: null,
            destroyedState: st.destroyedState,
            destructionId: st.destructionId,
          });
        }
        items.sort((a, b) => (a.packageId < b.packageId ? -1 : a.packageId > b.packageId ? 1 : 0));
        return send(res, 200, { packages: items });
      }

      const importPath = path.match(/^\/api\/packages\/([^/]+)\/import$/);
      if (importPath && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(importPath[1]);
        requireNotDestroyed(packageId);
        const archive = manager.open(packageId);
        try {
          const out = archive.importEnvelope(body, { registry, nowIso: at });
          logger.log({
            level: 'info',
            msg: out.duplicate ? 'evidence-duplicate' : 'evidence-imported',
            packageId, gatewayId: body?.gatewayId,
            duplicate: out.duplicate, result: out.duplicate ? out.disposition : out.result,
            records: out.duplicate ? undefined : out.disposition?.recordsAccepted,
            conflict: out.duplicate ? out.disposition?.recordsConflicted : out.disposition?.recordsConflicted,
            envelopeHash: out.envelopeHash, importId: out.duplicate ? out.importId : out.importId,
          });
          return send(res, out.duplicate ? 200 : (out.result === 'CONFLICTS' ? 200 : 201), out);
        } catch (err) {
          // 已通过信封哈希复算、但后续被拒的信封留底（0600，仅审计，不进入证据链）。
          let storedReject = null;
          if (body && typeof body === 'object' && err.status === 422) {
            try { storedReject = archive.persistRejected(manager.rejectedDir, body, err.code, err.message, at); } catch { /* 忽略留底失败 */ }
          }
          logger.log({
            level: 'warn', msg: 'evidence-rejected', packageId,
            gatewayId: body?.gatewayId, code: err.code, reason: err.message,
            envelopeHash: typeof body?.envelopeHash === 'string' ? body.envelopeHash : undefined,
          });
          return send(res, err.status || 422, {
            error: err.message, code: err.code, details: redact(err.details || {}, [uploadSecret]),
            ...(storedReject ? { rejectedSaved: true } : {}),
          });
        }
      }

      // ---------- 报告与导出 ----------
      const reportMatch = path.match(/^\/api\/packages\/([^/]+)\/report$/);
      if (reportMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(reportMatch[1]);
        requireNotDestroyed(packageId);
        const r = withRetention(packageView(packageId));
        return send(res, 200, exportRedactedJSON(r, [uploadSecret]));
      }
      const exportMatch = path.match(/^\/api\/packages\/([^/]+)\/report\.(json|txt|html)$/);
      if (exportMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(exportMatch[1]);
        requireNotDestroyed(packageId);
        const r = withRetention(packageView(packageId));
        const fmt = exportMatch[2];
        if (fmt === 'json') {
          return send(res, 200, JSON.stringify(exportRedactedJSON(r, [uploadSecret]), null, 2), {
            'Content-Disposition': `attachment; filename="report-${r.packageId}.json"`,
            'Content-Type': 'application/json; charset=utf-8',
          });
        }
        if (fmt === 'txt') {
          return send(res, 200, renderText(exportRedactedJSON(r, [uploadSecret])), {
            'Content-Disposition': `attachment; filename="report-${r.packageId}.txt"`,
            'Content-Type': 'text/plain; charset=utf-8',
          });
        }
        return send(res, 200, renderHTMLFragment(exportRedactedJSON(r, [uploadSecret])), { 'Content-Type': 'text/html; charset=utf-8' });
      }

      const timelineMatch = path.match(/^\/api\/packages\/([^/]+)\/timeline$/);
      if (timelineMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(timelineMatch[1]);
        requireNotDestroyed(packageId);
        const r = packageView(packageId);
        return send(res, 200, redact({ packageId: r.packageId, timeline: r.timeline }, [uploadSecret]));
      }
      const conflictMatch = path.match(/^\/api\/packages\/([^/]+)\/conflicts$/);
      if (conflictMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(conflictMatch[1]);
        requireNotDestroyed(packageId);
        const r = packageView(packageId);
        return send(res, 200, redact({ packageId: r.packageId, conflicts: r.conflicts }, [uploadSecret]));
      }
      const oldFenceMatch = path.match(/^\/api\/packages\/([^/]+)\/fences\/(\d+)$/);
      if (oldFenceMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(oldFenceMatch[1]);
        requireNotDestroyed(packageId);
        // 旧围栏证据仍可查询（按版本），响应标注它不是当前围栏/当前进度。
        const r = packageView(packageId);
        const v = Number(oldFenceMatch[2]);
        const f = r.fences.find((x) => x.version === v);
        if (!f) throw Object.assign(new Error(`围栏版本 v${v} 不存在`), { code: 'FENCE_UNKNOWN', status: 404 });
        const segs = r.timeline.filter((t) => t.fenceVersion === v && t.type === 'SEGMENT_ACCEPTED');
        return send(res, 200, redact({
          packageId: r.packageId,
          fence: f,
          segments: segs,
          isCurrentFence: f.isCurrent,
          note: f.isCurrent ? '当前围栏' : '旧围栏证据：可查询，但不得作为当前进度',
        }, [uploadSecret]));
      }

      // ---------- 哈希链核验 ----------
      if (path === '/api/chain/verify' && req.method === 'GET') {
        const out = {};
        for (const id of manager.list()) out[id] = manager.open(id).verify();
        return send(res, 200, { packages: out, retention: retention.verifyChain() });
      }
      const verifyPkg = path.match(/^\/api\/packages\/([^/]+)\/verify$/);
      if (verifyPkg && req.method === 'GET') {
        const packageId = decodeURIComponent(verifyPkg[1]);
        requireNotDestroyed(packageId);
        return send(res, 200, manager.open(packageId).verify());
      }

      // ---------- 导入裁决审计（脱敏）----------
      const importsMatch = path.match(/^\/api\/packages\/([^/]+)\/imports$/);
      if (importsMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(importsMatch[1]);
        requireNotDestroyed(packageId);
        const r = packageView(packageId);
        return send(res, 200, redact({ packageId: r.packageId, imports: r.imports }, [uploadSecret]));
      }

      // ============================================================
      // 保留期限 / 证据保全 / 到期销毁
      // ============================================================

      // 待销毁列表（保留期限已到、无有效保全）与全部保留状态
      if (path === '/api/retention/due' && req.method === 'GET') {
        return send(res, 200, { at: at, count: retention.listDue().length, packages: retention.listDue() });
      }
      if (path === '/api/retention' && req.method === 'GET') {
        return send(res, 200, { at: at, packages: retention.listAll() });
      }
      // 到期任务：立即扫描并销毁所有已到期且无保全的包
      if (path === '/api/retention/expiry-task' && req.method === 'POST') {
        requireSecret(req);
        const out = retention.runExpiryTask(at);
        logger.log({ level: 'info', msg: 'retention-expiry-task', destroyed: out.destroyed.length, count: out.skipped.length });
        return send(res, 200, out);
      }

      // 单包保留/保全状态
      const retentionStatusMatch = path.match(/^\/api\/packages\/([^/]+)\/retention$/);
      if (retentionStatusMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(retentionStatusMatch[1]);
        const st = retention.status(packageId);
        if (!st) return send(res, 404, { error: '作业包尚无保留策略记录', code: 'PACKAGE_NOT_FOUND' });
        return send(res, 200, st);
      }
      // 运营设置保留期限
      const retentionSetMatch = path.match(/^\/api\/packages\/([^/]+)\/retention$/);
      if (retentionSetMatch && req.method === 'POST') {
        requireSecret(req);
        const out = retention.setRetention({
          packageId: decodeURIComponent(retentionSetMatch[1]),
          requestId: body.requestId,
          retainUntil: body.retainUntil,
          retainForDays: body.retainForDays != null ? Number(body.retainForDays) : undefined,
          retainForSeconds: body.retainForSeconds != null ? Number(body.retainForSeconds) : undefined,
          setBy: body.setBy,
        });
        return send(res, out.idempotent ? 200 : 201, out);
      }
      // 审计发起保全（带原因与案件号）
      const holdPlaceMatch = path.match(/^\/api\/packages\/([^/]+)\/holds$/);
      if (holdPlaceMatch && req.method === 'POST') {
        requireSecret(req);
        const out = retention.placeHold({
          packageId: decodeURIComponent(holdPlaceMatch[1]),
          requestId: body.requestId,
          caseNo: body.caseNo,
          reason: body.reason,
          requestedBy: body.requestedBy,
        });
        return send(res, out.idempotent ? 200 : 201, out);
      }
      // 解除保全
      const holdReleaseMatch = path.match(/^\/api\/packages\/([^/]+)\/holds\/release$/);
      if (holdReleaseMatch && req.method === 'POST') {
        requireSecret(req);
        const out = retention.releaseHold({
          packageId: decodeURIComponent(holdReleaseMatch[1]),
          requestId: body.requestId,
          holdId: body.holdId,
          caseNo: body.caseNo,
          releasedBy: body.releasedBy,
          reason: body.reason,
        });
        return send(res, out.idempotent ? 200 : 200, out);
      }
      // 立即执行销毁
      const destroyMatch = path.match(/^\/api\/packages\/([^/]+)\/destroy$/);
      if (destroyMatch && req.method === 'POST') {
        requireSecret(req);
        const out = retention.destroy({
          packageId: decodeURIComponent(destroyMatch[1]),
          requestId: body.requestId,
          trigger: body.trigger === 'MANUAL' ? 'MANUAL' : (body.trigger || 'MANUAL'),
          destroyedBy: body.destroyedBy,
        });
        logger.log({ level: 'warn', msg: 'package-destroyed', packageId: out.packageId,
          destructionId: out.destructionId, records: out.alreadyDestroyed ? 0 : 1 });
        return send(res, 200, out);
      }
      // 失败后恢复：继续所有卡在 COMMITTING 的销毁到唯一结果
      if (path === '/api/retention/recover' && req.method === 'POST') {
        requireSecret(req);
        const recovered = retention.recoverCommitting();
        return send(res, 200, { recovered, lastRecoveryError: retention.lastRecoveryError });
      }
      // 销毁回执（不含原始证据）与验签
      const receiptMatch = path.match(/^\/api\/packages\/([^/]+)\/destruction-receipt$/);
      if (receiptMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(receiptMatch[1]);
        const signed = retention.signedReceipt(packageId);
        if (!signed) {
          const d = retention.destroyedView(packageId);
          if (d) return send(res, 409, { error: d.note, code: 'DESTRUCTION_IN_PROGRESS', details: d });
          return send(res, 404, { error: '该作业包没有销毁回执', code: 'RECEIPT_NOT_FOUND' });
        }
        return send(res, 200, redact(signed, [uploadSecret]));
      }
      const receiptVerifyMatch = path.match(/^\/api\/packages\/([^/]+)\/destruction-receipt\/verify$/);
      if (receiptVerifyMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(receiptVerifyMatch[1]);
        const v = retention.verifyReceipt(packageId);
        if (!v) return send(res, 404, { error: '该作业包没有销毁回执', code: 'RECEIPT_NOT_FOUND' });
        return send(res, 200, v);
      }

      // ---------- 运营：从磁盘重放重建（等价进程重启）----------
      if (path === '/api/admin/restart' && req.method === 'POST') {
        requireSecret(req);
        restartFromDisk();
        logger.log({ level: 'info', msg: 'replay-restart' });
        return send(res, 200, { restarted: true, packages: manager.list() });
      }

      // ---------- 演示/测试辅助：存储删除故障注入（仅 EVIDENCE_DEMO=1）----------
      // 让后续物理删除对命中的 packageId 失败（模拟存储故障），用于验证 COMMITTING 恢复。
      const faultMatch = path.match(/^\/api\/demo\/fault\/delete$/);
      if (faultMatch && req.method === 'POST') {
        if (process.env.EVIDENCE_DEMO !== '1') {
          throw Object.assign(new Error('演示接口未开启（EVIDENCE_DEMO=1）'), { code: 'DEMO_DISABLED', status: 403 });
        }
        requireSecret(req);
        const mode = String(body.mode || 'off'); // 'fail-package' | 'fail-all' | 'off'
        const matchPackageId = body.packageId ? String(body.packageId) : null;
        retention.setDeleteArtifacts(mode === 'off' ? null : (() => {
          let calls = 0;
          return (_dir, packageId) => {
            calls += 1;
            if (mode === 'fail-all' || packageId === matchPackageId) {
              throw Object.assign(new Error('注入的存储删除失败'), { code: 'STORAGE_DELETE_FAILED', injected: true, calls });
            }
          };
        })());
        return send(res, 200, { fault: mode, packageId: matchPackageId });
      }

      // ---------- 演示辅助：生成网关密钥对（仅在显式开启时；服务端不保存私钥）----------
      if (path === '/api/demo/keypair' && req.method === 'POST') {
        if (process.env.EVIDENCE_DEMO !== '1') {
          throw Object.assign(new Error('演示接口未开启（EVIDENCE_DEMO=1）'), { code: 'DEMO_DISABLED', status: 403 });
        }
        const pair = generateGatewayKeyPair();
        return send(res, 201, pair);
      }

      return send(res, 404, { error: 'unknown route', path });
    } catch (err) {
      // RetentionError 自带 HTTP 状态（400/404/409/410）；其余沿用既有规则。
      const status = err.status || (err instanceof RetentionError ? 400 : (err.code === 'CHAIN_QUARANTINED' ? 503 : 500));
      if (status === 500) {
        logger.log({ level: 'error', msg: 'internal-error', code: err.code, reason: String(err.message).slice(0, 160) });
      }
      const noStore = status === 503 || status === 410 || status === 409;
      send(res, status, {
        error: status === 500 ? 'internal error' : err.message,
        code: err.code || 'INTERNAL',
        details: redact(err.details || {}, [uploadSecret]),
      }, noStore ? { 'Retry-After': status === 503 ? '300' : '0', 'Cache-Control': 'no-store' } : {});
    }
  });

  return {
    server, manager, registry, retention,
    get uploadSecret() { return uploadSecret; },
    restartFromDisk,
    start() {
      return new Promise((resolve) => {
        server.listen(deps.port ?? PORT, HOST, () => resolve(server.address().port));
      });
    },
    stop() {
      return new Promise((r) => server.close(r));
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = await createApp();
  const actualPort = await app.start();
  console.log(`证据归档与冲突核验服务已启动: http://localhost:${actualPort}/`);
  console.log(`证据目录: ${DATA_DIR}`);
  console.log(`导入鉴权: X-Upload-Secret 请求头（读取 sidecar: ${join(DATA_DIR, 'upload-secret.json')}，权限 0600）`);
}
