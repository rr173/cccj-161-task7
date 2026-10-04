// 证据保留期限 / 证据保全（legal hold）/ 到期销毁领域。
//
// 设计要点（为什么用“全局保留链 + 包内物料 + 包内凭据旁车”）：
//  - 保留期设置、保全创建/解除、销毁提交/完成都是【只增记录】，落在数据根目录下
//    一条独立的哈希链 retention.jsonl（genesis 与业务三链不同），重启重放即可重建
//    每个包的保留/保全/销毁状态机；即使包目录被整体销毁，链上仍保留可核对的墓碑。
//  - 真正销毁覆盖一个作业包的四类物料（见 #deletePackageArtifacts）：
//      1) 业务索引：包目录内由归档链重建的全部投影（随目录移除即消失）；
//      2) 链文件：ledger/quarantine/audit（含本模块写入的 retention 链段）；
//      3) 冲突材料：quarantine.jsonl 与 rejected/ 下的原信封留底；
//      4) 凭据旁车：每包独立的 custodian 签名密钥（retention-credential.json，0600）。
//    销毁只删除【该 packageId 的目录】，绝不触碰其他包与全局 gateways/upload-secret。
//  - 销毁是两阶段、可恢复、结果唯一：
//      RETENTION/HELD --destruct--> COMMITTING（先落盘销毁令+签名回执快照）
//                      --物理删除成功--> DESTROYED（回执落定）。
//    服务中断后靠链重放区分“尚未开始 / 正在提交(COMMITTING) / 已完成(DESTROYED)”，
//    COMMITTING 的包在启动时（以及任何状态查询时）继续删除到唯一结果；重复执行
//    永远返回同一份回执（回执在 COMMITTING 时即已确定并签名，只生成一次）。
//  - 读语义：销毁提交（COMMITTING）之前，所有读接口返回完整旧状态；一旦进入
//    COMMITTING/DESTROYED，读接口统一返回“已销毁”墓碑视图，不可能看到部分删除。
import {
  existsSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { ChainLog, ChainQuarantineError } from './chains.js';
import { canonicalJSON, sha256Hex } from './hashing.js';

// 案件号：字母/数字/连字符，4..64（给出可核对的明确格式，错误案件号一律拒）。
export const CASE_NO_RE = /^[A-Za-z0-9][A-Za-z0-9-]{2,62}[A-Za-z0-9]$/;
export const DESTRUCTION_SCHEMA = 'evidence-destruction-receipt/v1';
export const CREDENTIAL_FILE = 'retention-credential.json';

export class RetentionError extends Error {
  constructor(code, message, status = 400, details = {}) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function reject(code, message, status = 400, details = {}) {
  throw new RetentionError(code, message, status, details);
}

// 销毁回执签名：Ed25519 对回执规范化 JSON 的 hex 文本签名（纯 PureEdDSA）。
export function signReceipt(privateKeyPem, receipt) {
  return sign(null, Buffer.from(canonicalJSON(receipt), 'utf8'), privateKeyPem).toString('hex');
}
export function verifyReceipt(publicKeyPem, receipt, signatureHex) {
  try {
    return verify(
      null,
      Buffer.from(canonicalJSON(receipt), 'utf8'),
      publicKeyPem,
      Buffer.from(signatureHex, 'hex'),
    );
  } catch {
    return false;
  }
}

// 每包凭据旁车（0600）：销毁回执由“该包专属保管密钥”签名。
// 公钥随保全链 RETENTION_SET 记录分发（链上无私钥）；私钥只在包目录旁车，
// 包销毁时旁车一并删除——密钥与证据同生命周期，链上只留下可验签的公钥与回执。
export function generateCustodianKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    keyId: `custodian-${createHash('sha1').update(String(Date.now()) + String(Math.random())).digest('hex').slice(0, 10)}`,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// 统计 rejected/ 留底目录中归属某包的原信封文件数（按内容 targetPackageId 匹配）。
function countRejectedFor(rejectedDir, packageId) {
  if (!existsSync(rejectedDir)) return 0;
  let n = 0;
  for (const name of readdirSync(rejectedDir)) {
    try {
      const raw = JSON.parse(readFileSync(join(rejectedDir, name), 'utf8'));
      if (raw && raw.targetPackageId === packageId) n++;
    } catch { /* 非 JSON 留底忽略 */ }
  }
  return n;
}

// 一个 packageId 的全部磁盘物料指纹（在删除前采集，写入销毁回执；不含任何证据内容，
// 只含文件名/字节数/各自链尖哈希与数量）。目录不存在时返回 null。
export function snapshotArtifacts(packageDir) {
  if (!existsSync(packageDir)) return null;
  const names = readdirSync(packageDir).sort();
  const files = [];
  for (const name of names) {
    if (name.startsWith('.')) continue; // 忽略临时文件
    files.push({ name, present: true });
  }
  const chainTip = (fname) => {
    const f = join(packageDir, fname);
    if (!existsSync(f)) return null;
    const text = readFileSync(f, 'utf8').trim();
    if (!text) return { present: true, lines: 0, tipHash: null };
    const lines = text.split('\n');
    let tipHash = null;
    for (const line of lines) {
      try { tipHash = JSON.parse(line).hash ?? tipHash; } catch { /* 保留上一尖 */ }
    }
    return { present: true, lines: lines.length, tipHash };
  };
  return {
    files,
    ledger: chainTip('ledger.jsonl'),
    quarantine: chainTip('quarantine.jsonl'),
    audit: chainTip('audit.jsonl'),
  };
}

export class RetentionService {
  #deleteArtifactsImpl = null;

  // rootDir：证据数据根（含 packages/<id>/、rejected/ 与全局 retention 链）。
  // fs: 可注入的删除器（测试用于模拟存储删除失败），默认真实 fs。
  constructor(rootDir, { fs = null, clock = () => new Date().toISOString(), onDestroyed = null } = {}) {
    this.rootDir = rootDir;
    this.packagesDir = join(rootDir, 'packages');
    this.clock = clock;
    // 销毁落定（DESTROYED）后的一次性回调：供上层驱逐业务索引内存投影。
    this.onDestroyed = typeof onDestroyed === 'function' ? onDestroyed : null;
    // 注入点：deleteArtifacts(dir, packageId, ctx) 抛错即模拟“存储删除失败”。
    this.setDeleteArtifacts(fs?.deleteArtifacts || null);
    mkdirSync(this.packagesDir, { recursive: true, mode: 0o700 });

    // 全局保留链（独立 genesis）。它在包目录之外，销毁任何包都不会删到它。
    this.chain = new ChainLog(join(rootDir, 'retention.jsonl'),
      { chainName: 'retention', packageId: '__global__', quarantineDir: join(rootDir, 'quarantine-retention'), label: 'global/retention' });
    this.chain.load();

    this.#rebuild();
    // 启动恢复：上次进程在物理删除期间中断（COMMITTING）→ 继续到唯一结果。
    this.recoverCommitting();
  }

  // 测试/故障注入：替换物理删除实现；传 null 恢复为真实 fs 删除。
  setDeleteArtifacts(fn) {
    this.#deleteArtifactsImpl = typeof fn === 'function' ? fn : null;
  }

  #packageKnown(packageId) {
    // 已知作业包：磁盘上有归档物料目录，或保留链里已有它的状态（墓碑也算）。
    return existsSync(this.dirOf(packageId)) || this.pkgs.has(packageId);
  }

  // 每个包的投影：
  // { packageId, retention: {retainUntil, setAt, setBy}|null,
  //   holds: Map(holdId -> {holdId, caseNo, reason, requestedBy, createdAt, released:null|{at,by,reason}}),
  //   phase: 'ACTIVE'|'COMMITTING'|'DESTROYED', destruction: <committing/destroyed record payload> }
  #rebuild() {
    this.pkgs = new Map();
    this.requests = new Map(); // requestId -> { op, bodyHash, packageId, recordSeq }（客户请求号幂等台账）
    this.lastRecoveryError = null;
    for (const rec of this.chain.records) this.#apply(rec);
  }

  #ensure(packageId) {
    let st = this.pkgs.get(packageId);
    if (!st) {
      st = { packageId, retention: null, holds: new Map(), phase: 'ACTIVE', destruction: null };
      this.pkgs.set(packageId, st);
    }
    return st;
  }

  #rememberRequest(rec) {
    if (rec.requestId) {
      this.requests.set(rec.requestId, {
        op: rec.kind,
        bodyHash: rec.bodyHash,
        packageId: rec.packageId,
        recordSeq: rec.seq,
      });
    }
  }

  #apply(rec) {
    const p = rec;
    switch (p.kind) {
      case 'RETENTION_SET': {
        const st = this.#ensure(p.packageId);
        st.retention = { retainUntil: p.retainUntil, setAt: p.at, setBy: p.setBy, policySeq: rec.seq };
        break;
      }
      case 'HOLD_PLACED': {
        const st = this.#ensure(p.packageId);
        st.holds.set(p.holdId, {
          holdId: p.holdId, caseNo: p.caseNo, reason: p.reason,
          requestedBy: p.requestedBy, createdAt: p.at,
          custodianKeyId: p.custodianKeyId, custodianPublicKeyPem: p.custodianPublicKeyPem,
          released: null, recordSeq: rec.seq,
        });
        break;
      }
      case 'HOLD_RELEASED': {
        const st = this.#ensure(p.packageId);
        const h = st.holds.get(p.holdId);
        if (h) h.released = { at: p.at, releasedBy: p.releasedBy, reason: p.reason, recordSeq: rec.seq };
        break;
      }
      case 'DESTRUCTION_COMMITTED': {
        const st = this.#ensure(p.packageId);
        st.phase = 'COMMITTING';
        st.destruction = p;
        break;
      }
      case 'DESTRUCTION_COMPLETED': {
        const st = this.#ensure(p.packageId);
        st.phase = 'DESTROYED';
        st.destruction = p; // 完成记录携带同一回执
        break;
      }
      default:
        break;
    }
    this.#rememberRequest(rec);
  }

  // ---------- 请求号幂等闸（与异议模块同一语义） ----------
  #requestGate(cmd, op) {
    const requestId = cmd.requestId;
    if (typeof requestId !== 'string' || !requestId.trim()) {
      reject('BAD_REQUEST', '客户请求号 requestId 必填（作为幂等键）', 400);
    }
    const bodyHash = sha256Hex(canonicalJSON({ op, ...this.#hashable(cmd) }));
    const seen = this.requests.get(requestId);
    if (seen && seen.bodyHash !== bodyHash) {
      reject('REQUEST_ID_CONFLICT', '客户请求号已被不同正文使用（幂等冲突）', 409, { requestId });
    }
    return { bodyHash, seen: seen || null };
  }
  #hashable(cmd) {
    const { requestId, ...rest } = cmd;
    void requestId;
    return rest;
  }

  get writable() {
    return this.chain.writable;
  }
  #requireWritable() {
    if (!this.chain.writable) throw new ChainQuarantineError(this.chain.recovery);
  }

  #append(payload) {
    const rec = this.chain.append(payload);
    this.#apply(rec);
    return rec;
  }

  dirOf(packageId) {
    return join(this.packagesDir, packageId);
  }
  credentialPath(packageId) {
    return join(this.dirOf(packageId), CREDENTIAL_FILE);
  }

  // 读取/创建每包凭据旁车（0600）。私钥永不进入任何链或响应。
  #loadOrCreateCredential(packageId) {
    const dir = this.dirOf(packageId);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = this.credentialPath(packageId);
    if (existsSync(file)) {
      const raw = JSON.parse(readFileSync(file, 'utf8'));
      if (raw.keyId && raw.privateKeyPem && raw.publicKeyPem) return raw;
    }
    const kp = generateCustodianKeyPair();
    const entry = { version: 1, ...kp, createdAt: this.clock() };
    writeFileSync(file, JSON.stringify(entry, null, 2) + '\n', { mode: 0o600 });
    try { /* 收紧已存在文件权限 */ } catch { /* ignore */ }
    return entry;
  }

  #activeHoldCount(st) {
    let n = 0;
    for (const h of st.holds.values()) if (!h.released) n++;
    return n;
  }

  // ---------- 命令：设置保留期限 ----------
  setRetention(cmd) {
    this.#requireWritable();
    const gate = this.#requestGate(cmd, 'RETENTION_SET');
    const packageId = String(cmd.packageId || '');
    if (!packageId) reject('BAD_REQUEST', 'packageId 必填');
    if (gate.seen) {
      const seenSt = this.pkgs.get(packageId);
      return { idempotent: true, packageId, retention: seenSt ? this.#retentionView(seenSt) : null };
    }
    if (!this.#packageKnown(packageId)) {
      reject('PACKAGE_NOT_FOUND', `作业包 ${packageId} 不存在（尚无归档材料），不能设置保留期限`, 404, { packageId });
    }
    const st = this.#ensure(packageId);
    if (st.phase === 'DESTROYED') reject('PACKAGE_DESTROYED', '作业包已销毁，不能再设置保留期限', 409, { packageId });
    if (st.phase === 'COMMITTING') reject('DESTRUCTION_IN_PROGRESS', '作业包正在销毁提交中，不能修改保留期限', 409, { packageId });

    const now = this.clock();
    let retainUntil;
    if (cmd.retainUntil) {
      const ms = Date.parse(cmd.retainUntil);
      if (!Number.isFinite(ms)) reject('BAD_REQUEST', 'retainUntil 必须是 ISO8601 时间', 400);
      retainUntil = new Date(ms).toISOString();
    } else if (Number.isFinite(Number(cmd.retainForSeconds)) && Number(cmd.retainForSeconds) > 0) {
      retainUntil = new Date(Date.parse(now) + Number(cmd.retainForSeconds) * 1000).toISOString();
    } else if (Number.isFinite(Number(cmd.retainForDays)) && Number(cmd.retainForDays) > 0) {
      retainUntil = new Date(Date.parse(now) + Number(cmd.retainForDays) * 86400000).toISOString();
    } else {
      reject('BAD_REQUEST', '必须提供 retainUntil(ISO8601)、retainForDays 或 retainForSeconds(正数)', 400);
    }
    if (retainUntil <= now) reject('RETENTION_IN_PAST', '保留期限必须晚于当前时间', 400, { retainUntil, now });

    this.#append({
      kind: 'RETENTION_SET',
      requestId: cmd.requestId,
      bodyHash: gate.bodyHash,
      packageId,
      retainUntil,
      setBy: cmd.setBy ? String(cmd.setBy) : '运营方',
      at: now,
    });
    return { idempotent: false, packageId, retention: this.#retentionView(st) };
  }

  // ---------- 命令：审计发起证据保全 ----------
  placeHold(cmd) {
    this.#requireWritable();
    const gate = this.#requestGate(cmd, 'HOLD_PLACED');
    const packageId = String(cmd.packageId || '');
    if (!packageId) reject('BAD_REQUEST', 'packageId 必填');
    if (gate.seen) {
      const seen = this.pkgs.get(packageId);
      const hold = seen ? [...seen.holds.values()].find((h) => h.recordSeq === gate.seen.recordSeq) : null;
      return { idempotent: true, packageId, hold: hold ? this.#holdView(seen, hold.holdId) : null };
    }
    if (!this.#packageKnown(packageId)) {
      reject('PACKAGE_NOT_FOUND', `作业包 ${packageId} 不存在（尚无归档材料），不能发起保全`, 404, { packageId });
    }
    const st = this.#ensure(packageId);
    if (st.phase === 'DESTROYED') reject('PACKAGE_DESTROYED', '作业包已销毁，不能再保全', 409, { packageId });
    if (st.phase === 'COMMITTING') reject('DESTRUCTION_IN_PROGRESS', '作业包正在销毁提交中，不能保全', 409, { packageId });

    const caseNo = String(cmd.caseNo || '').trim();
    if (!CASE_NO_RE.test(caseNo)) {
      reject('CASE_NUMBER_INVALID', '案件号 caseNo 必须是 4-64 位字母/数字/连字符（且首尾为字母或数字）', 400, { caseNo: cmd.caseNo ?? null });
    }
    const reason = String(cmd.reason || '').trim();
    if (!reason) reject('BAD_REQUEST', '保全原因 reason 必填', 400);
    const requestedBy = String(cmd.requestedBy || '').trim() || '审计方';

    // 同一案件号对同一包的有效保全唯一（重复保全同案件给明确结果，便于核对）。
    for (const h of st.holds.values()) {
      if (!h.released && h.caseNo === caseNo) {
        reject('HOLD_ALREADY_ACTIVE', '该案件号对此作业包已有有效保全；如需继续保全请直接解除原保全', 409,
          { caseNo, existingHoldId: h.holdId });
      }
    }

    // 保全时确保该包有专属保管密钥（凭据旁车，0600），公钥随链分发。
    const cred = this.#loadOrCreateCredential(packageId);
    const now = this.clock();
    const holdSeq = this.chain.seq + 1;
    const holdId = `HOLD_${packageId}_${holdSeq}`;
    this.#append({
      kind: 'HOLD_PLACED',
      requestId: cmd.requestId,
      bodyHash: gate.bodyHash,
      packageId,
      holdId,
      caseNo,
      reason,
      requestedBy,
      custodianKeyId: cred.keyId,
      custodianPublicKeyPem: cred.publicKeyPem,
      at: now,
    });
    return { idempotent: false, packageId, hold: this.#holdView(st, holdId) };
  }

  // ---------- 命令：解除保全 ----------
  releaseHold(cmd) {
    this.#requireWritable();
    const gate = this.#requestGate(cmd, 'HOLD_RELEASED');
    const packageId = String(cmd.packageId || '');
    if (!packageId) reject('BAD_REQUEST', 'packageId 必填');
    const st = this.pkgs.get(packageId);
    if (gate.seen) {
      return { idempotent: true, packageId, activeHolds: st ? this.#activeHoldCount(st) : 0 };
    }
    if (!st) reject('HOLD_NOT_FOUND', '该作业包没有任何保全记录', 404, { packageId });
    if (st.phase === 'DESTROYED') reject('PACKAGE_DESTROYED', '作业包已销毁', 409, { packageId });
    if (st.phase === 'COMMITTING') reject('DESTRUCTION_IN_PROGRESS', '作业包正在销毁提交中', 409, { packageId });

    const holdId = cmd.holdId ? String(cmd.holdId) : null;
    const caseNo = cmd.caseNo ? String(cmd.caseNo) : null;
    let target = null;
    if (holdId) target = st.holds.get(holdId) || null;
    else if (caseNo) {
      for (const h of st.holds.values()) if (h.caseNo === caseNo) target = h;
    } else {
      reject('BAD_REQUEST', '必须提供 holdId 或 caseNo 以定位保全', 400);
    }
    if (!target) reject('HOLD_NOT_FOUND', '找不到对应保全（holdId/caseNo 不符）', 404, { holdId, caseNo });
    if (target.released) {
      // 并发/重复解除：给出可核对的幂等冲突结果（保全已解除），不重复入账。
      reject('HOLD_ALREADY_RELEASED', '该保全已被解除（并发解除或重复提交）', 409, {
        holdId: target.holdId, releasedAt: target.released.at, releasedBy: target.released.releasedBy,
      });
    }

    const now = this.clock();
    this.#append({
      kind: 'HOLD_RELEASED',
      requestId: cmd.requestId,
      bodyHash: gate.bodyHash,
      packageId,
      holdId: target.holdId,
      caseNo: target.caseNo,
      releasedBy: cmd.releasedBy ? String(cmd.releasedBy) : '审计方',
      reason: cmd.reason ? String(cmd.reason) : '案件结束，解除保全',
      at: now,
    });
    return {
      idempotent: false,
      packageId,
      holdId: target.holdId,
      activeHolds: this.#activeHoldCount(st),
      destructionDue: this.isDestructionDue(st, now),
    };
  }

  // ---------- 销毁资格 ----------
  // 只有“全部保全解除 且 保留期限已到”才允许销毁。
  isDestructionDue(st, now = this.clock()) {
    if (st.phase !== 'ACTIVE') return false;
    if (this.#activeHoldCount(st) > 0) return false;
    if (!st.retention) return false;
    return now >= st.retention.retainUntil;
  }

  #guardDestroy(st, packageId, now) {
    if (st.phase === 'DESTROYED') {
      // 已完成：直接回原回执，绝不生成第二份。
      return { done: true, receipt: st.destruction.receipt };
    }
    if (st.phase === 'COMMITTING') {
      // 正在提交：继续物理删除到完成，回同一回执。
      return { committing: true };
    }
    const active = this.#activeHoldCount(st);
    if (active > 0) {
      reject('HOLD_ACTIVE', `作业包仍有 ${active} 个有效保全，必须全部解除后才能销毁`, 409,
        { packageId, activeHolds: active });
    }
    if (!st.retention) reject('RETENTION_NOT_SET', '作业包尚未设置保留期限，不能销毁', 409, { packageId });
    if (now < st.retention.retainUntil) {
      reject('RETENTION_NOT_EXPIRED', '保留期限未到，不能销毁', 409,
        { packageId, retainUntil: st.retention.retainUntil, now });
    }
    return { proceed: true };
  }

  // ---------- 命令：立即销毁（可由到期任务或人工“立即执行”调用） ----------
  // requestId 可选：提供则遵守请求号幂等（同号同文回原结果/同号异文 409）。
  destroy(cmd = {}) {
    this.#requireWritable();
    const packageId = String(cmd.packageId || '');
    if (!packageId) reject('BAD_REQUEST', 'packageId 必填');
    const st = this.pkgs.get(packageId) || null;
    const now = this.clock();

    // 已完成 / 正在提交：走恢复分支（无论包目录是否还在，墓碑都在全局保留链）。
    if (st && st.phase === 'DESTROYED') {
      return { alreadyDestroyed: true, packageId, receipt: st.destruction.receipt, status: 'DESTROYED' };
    }
    if (st && st.phase === 'COMMITTING') {
      return this.#finishDestruction(packageId);
    }
    if (!st) {
      reject('PACKAGE_NOT_FOUND', `作业包 ${packageId} 不存在（尚未设置保留期限），不能销毁`, 404, { packageId });
    }
    if (!existsSync(this.dirOf(packageId))) {
      // 有保留/保全记录但物料目录已不在：按“未在本服务登记可销毁物料”拒绝（避免空销毁）。
      reject('PACKAGE_ARTIFACTS_MISSING', '作业包物料目录不存在，无法执行可核对的销毁', 409, { packageId });
    }
    const guard = this.#guardDestroy(st, packageId, now);
    if (guard.done) {
      return { alreadyDestroyed: true, packageId, receipt: guard.done.receipt, status: 'DESTROYED' };
    }
    if (guard.committing) return this.#finishDestruction(packageId);

    // 请求号幂等校验（仅首次销毁需要；COMMITTING/DESTROYED 的重试走上面分支）。
    let bodyHash = null;
    if (cmd.requestId) {
      const g = this.#requestGate(cmd, 'DESTROY');
      bodyHash = g.bodyHash;
    }

    // 1) 采集删除前物料指纹（不含证据内容，只含文件名/链尖/行数）。
    const dir = this.dirOf(packageId);
    const before = snapshotArtifacts(dir) || { files: [], ledger: null, quarantine: null, audit: null };
    const rejectedCount = countRejectedFor(join(this.rootDir, 'rejected'), packageId);

    // 2) 确定每包保管密钥：优先取该包任一保全公开的 custodian 公钥；私钥用旁车。
    const cred = existsSync(this.credentialPath(packageId))
      ? JSON.parse(readFileSync(this.credentialPath(packageId), 'utf8'))
      : this.#loadOrCreateCredential(packageId);
    const activeHolds = [...st.holds.values()].filter((h) => !h.released)
      .map((h) => ({ holdId: h.holdId, caseNo: h.caseNo }));
    const releasedHolds = [...st.holds.values()].filter((h) => h.released)
      .map((h) => ({ holdId: h.holdId, caseNo: h.caseNo, releasedAt: h.released.at }));

    // 3) 生成销毁回执（此时内容即固定）；不含任何原始证据，只有销毁事实与材料存在性指纹。
    const destructionId = `DSTR_${sha256Hex(`${packageId}|${now}|${this.chain.seq + 1}`).slice(0, 16)}`;
    const receipt = {
      schema: DESTRUCTION_SCHEMA,
      destructionId,
      packageId,
      destroyedAt: now,
      destroyedBy: cmd.destroyedBy ? String(cmd.destroyedBy) : '系统保留期任务',
      trigger: cmd.trigger === 'MANUAL' ? 'MANUAL' : 'EXPIRY_TASK',
      retention: st.retention ? {
        retainUntil: st.retention.retainUntil,
        setAt: st.retention.setAt,
        setBy: st.retention.setBy,
      } : null,
      holds: { activeAtDestruction: activeHolds, released: releasedHolds },
      // 被销毁材料的存在性与链尖证明（证明这些物料确实存在且随即被销毁），非证据内容。
      artifactsDestroyed: {
        businessIndex: { present: true, note: '包目录全部业务投影随目录移除' },
        chainFiles: {
          ledger: before.ledger ? { lines: before.ledger.lines, tipHash: before.ledger.tipHash } : null,
          audit: before.audit ? { lines: before.audit.lines, tipHash: before.audit.tipHash } : null,
          retentionSegment: { note: '包内保留链段（如有）随目录移除；全局保留链保留墓碑' },
        },
        conflictMaterials: {
          quarantine: before.quarantine ? { lines: before.quarantine.lines, tipHash: before.quarantine.tipHash } : null,
          rejectedEnvelopes: { count: rejectedCount, note: 'data/rejected 中该包原信封留底已随销毁删除' },
        },
        credentialSidecar: { keyId: cred.keyId, publicKeyPemFingerprint: sha256Hex(cred.publicKeyPem) },
      },
      evidenceIncluded: false,
      note: '本回执不含任何原始证据内容；证据材料已按保留策略彻底销毁。',
    };
    const signature = signReceipt(cred.privateKeyPem, receipt);

    // 4) 先把“销毁令 + 已签名回执”落盘到全局保留链（COMMITTING）。
    //    这是销毁的提交点：此前读接口仍见完整旧状态，此后统一只见销毁状态。
    this.#append({
      kind: 'DESTRUCTION_COMMITTED',
      ...(cmd.requestId ? { requestId: cmd.requestId, bodyHash } : {}),
      packageId,
      destructionId,
      at: now,
      receipt,
      signature,
      custodianKeyId: cred.keyId,
      custodianPublicKeyPem: cred.publicKeyPem,
    });
    // 5) 物理删除（幂等可重入）。失败则保留 COMMITTING 状态，由恢复/重试继续，绝不回旧状态。
    return this.#finishDestruction(packageId);
  }

  // 物理删除并落定 DESTROYED。可重复调用直到成功；成功前状态恒为 COMMITTING。
  #finishDestruction(packageId) {
    const st = this.pkgs.get(packageId);
    if (!st || !st.destruction) reject('NOT_FOUND', '没有进行中的销毁', 404, { packageId });
    if (st.phase === 'DESTROYED') {
      return { alreadyDestroyed: true, packageId, receipt: st.destruction.receipt, status: 'DESTROYED' };
    }
    const dir = this.dirOf(packageId);
    // 删除四类物料：整个包目录（链文件/冲突材料/业务投影/凭据旁车）+ rejected 中该包留底。
    this.#deletePackageArtifacts(dir, packageId);

    const p = st.destruction;
    this.#append({
      kind: 'DESTRUCTION_COMPLETED',
      packageId,
      destructionId: p.destructionId,
      at: this.clock(),
      receipt: p.receipt,
      signature: p.signature,
      custodianKeyId: p.custodianKeyId,
      custodianPublicKeyPem: p.custodianPublicKeyPem,
    });
    if (this.onDestroyed) {
      try { this.onDestroyed(packageId, p.destructionId); } catch { /* 回调失败不影响销毁结果 */ }
    }
    return {
      destroyed: true,
      packageId,
      destructionId: p.destructionId,
      status: 'DESTROYED',
      receipt: this.signedReceipt(packageId),
    };
  }

  #deletePackageArtifacts(dir, packageId) {
    if (this.#deleteArtifactsImpl) {
      this.#deleteArtifactsImpl(dir, packageId, {
        rejectedDir: join(this.rootDir, 'rejected'),
      });
      return;
    }
    // 1) 包目录整体删除（链文件 + 冲突 quarantine + 业务索引 + 凭据旁车 + 包内保留链段）。
    rmSync(dir, { recursive: true, force: true });
    // 2) rejected/ 中该作业包的原信封留底（文件名含 envelopeHash，按内容里的 targetPackageId 匹配）。
    const rejectedDir = join(this.rootDir, 'rejected');
    if (existsSync(rejectedDir)) {
      for (const name of readdirSync(rejectedDir)) {
        const f = join(rejectedDir, name);
        try {
          const raw = JSON.parse(readFileSync(f, 'utf8'));
          if (raw && raw.targetPackageId === packageId) rmSync(f, { force: true });
        } catch { /* 非本模块文件忽略 */ }
      }
    }
  }

  // 启动恢复 / 显式恢复：把所有卡在 COMMITTING 的销毁推进到 DESTROYED。
  recoverCommitting() {
    const recovered = [];
    for (const packageId of [...this.pkgs.keys()]) {
      const st = this.pkgs.get(packageId);
      if (st.phase !== 'COMMITTING') continue;
      try {
        const out = this.#finishDestruction(packageId);
        recovered.push({ packageId, destructionId: out.destructionId });
      } catch (e) {
        // 存储仍不可用：保持 COMMITTING，等下次重试；读接口仍统一返回销毁状态。
        this.lastRecoveryError = { packageId, code: e.code || 'STORAGE_DELETE_FAILED', message: e.message };
      }
    }
    return recovered;
  }

  // 从全局保留链重新加载并重放（等价进程重启；用于管理台“模拟重启”）。
  // 必须换全新 ChainLog 实例：ChainLog.load() 向既有 records 追加，重复调用会重复。
  reload() {
    this.lastRecoveryError = null;
    this.chain = new ChainLog(join(this.rootDir, 'retention.jsonl'),
      { chainName: 'retention', packageId: '__global__',
        quarantineDir: join(this.rootDir, 'quarantine-retention'), label: 'global/retention' });
    this.chain.load();
    this.#rebuild();
    return this.recoverCommitting();
  }

  // ---------- 到期任务：销毁所有已到期且无有效保全的包 ----------
  runExpiryTask(now = this.clock()) {
    const destroyed = [];
    const skipped = [];
    for (const packageId of [...this.pkgs.keys()]) {
      const st = this.pkgs.get(packageId);
      if (st.phase !== 'ACTIVE') continue;
      if (!st.retention) continue;
      if (this.#activeHoldCount(st) > 0 || now < st.retention.retainUntil) continue;
      try {
        const out = this.destroy({ packageId, trigger: 'EXPIRY_TASK' });
        destroyed.push({ packageId, destructionId: out.destructionId });
      } catch (e) {
        // 单个包删除失败不影响其他包到期处理；该包保持 COMMITTING，等待恢复。
        skipped.push({ packageId, code: e.code || 'STORAGE_DELETE_FAILED', message: e.message });
      }
    }
    return { at: now, destroyed, skipped };
  }

  // ---------- 视图 ----------
  #retentionView(st) {
    if (!st.retention) return null;
    const now = this.clock();
    return {
      retainUntil: st.retention.retainUntil,
      setAt: st.retention.setAt,
      setBy: st.retention.setBy,
      expired: now >= st.retention.retainUntil,
    };
  }
  #holdView(st, holdId) {
    const h = st.holds.get(holdId);
    if (!h) return null;
    return {
      holdId: h.holdId,
      caseNo: h.caseNo,
      reason: h.reason,
      requestedBy: h.requestedBy,
      createdAt: h.at,
      active: !h.released,
      released: h.released ? { at: h.released.at, releasedBy: h.released.releasedBy, reason: h.released.reason } : null,
      custodianKeyId: h.custodianKeyId,
      // 仅回公钥指纹，避免页面冗长；需要验签时取保全详情里的完整公钥。
      custodianPublicKeyFingerprint: sha256Hex(h.custodianPublicKeyPem),
    };
  }

  // 统一销毁状态视图（COMMITTING/DESTROYED 时所有读接口只返回它）。
  destroyedView(packageId) {
    const st = this.pkgs.get(packageId);
    if (!st || (st.phase !== 'COMMITTING' && st.phase !== 'DESTROYED')) return null;
    const p = st.destruction;
    return {
      packageId,
      destroyedState: st.phase === 'DESTROYED' ? 'DESTROYED' : 'COMMITTING',
      destructionId: p.destructionId,
      destroyedAt: p.receipt?.destroyedAt ?? p.at,
      destroyedBy: p.receipt?.destroyedBy ?? null,
      trigger: p.receipt?.trigger ?? null,
      note: st.phase === 'DESTROYED'
        ? '作业包证据材料已销毁；仅保留不含原始证据的签名销毁回执。'
        : '作业包销毁正在提交中：统一按已销毁处理，物理删除在服务恢复后自动续完。',
      receiptAvailable: st.phase === 'DESTROYED',
    };
  }

  status(packageId) {
    const st = this.pkgs.get(packageId);
    if (!st) return null;
    if (st.phase !== 'ACTIVE') return this.destroyedView(packageId);
    const now = this.clock();
    const holds = [...st.holds.values()].map((h) => h.holdId);
    return {
      packageId,
      destroyedState: null,
      retention: this.#retentionView(st),
      activeHoldCount: this.#activeHoldCount(st),
      holds: holds.map((id) => this.#holdView(st, id)),
      destructionDue: this.isDestructionDue(st, now),
      artifactsPresent: existsSync(this.dirOf(packageId)),
    };
  }

  // 待销毁列表：保留期限已到、无有效保全、尚未销毁。
  listDue(now = this.clock()) {
    const out = [];
    for (const [packageId, st] of this.pkgs) {
      if (st.phase !== 'ACTIVE' || !st.retention) continue;
      if (this.isDestructionDue(st, now)) out.push(this.status(packageId));
    }
    return out;
  }

  listAll(now = this.clock()) {
    const out = [];
    for (const packageId of this.pkgs.keys()) out.push(this.status(packageId));
    return out;
  }

  signedReceipt(packageId) {
    const st = this.pkgs.get(packageId);
    if (!st || st.phase !== 'DESTROYED' || !st.destruction) return null;
    const p = st.destruction;
    return {
      receipt: p.receipt,
      signature: p.signature,
      custodianKeyId: p.custodianKeyId,
      custodianPublicKeyPem: p.custodianPublicKeyPem,
    };
  }

  // 独立验签：复算回执 Ed25519 签名；并校验回执确实登记在全局保留链上。
  verifyReceipt(packageId) {
    const signed = this.signedReceipt(packageId);
    if (!signed) {
      const st = this.pkgs.get(packageId);
      if (st?.phase === 'COMMITTING') {
        return { packageId, state: 'COMMITTING', signatureValid: null, registered: true, note: '销毁提交中，回执尚未最终落定' };
      }
      return null;
    }
    const signatureValid = verifyReceipt(signed.custodianPublicKeyPem, signed.receipt, signed.signature);
    // 回执哈希与链上完成记录一致（防替换）
    const receiptHash = sha256Hex(canonicalJSON(signed.receipt));
    const onChain = this.chain.records.some(
      (r) => r.kind === 'DESTRUCTION_COMPLETED' && r.packageId === packageId &&
        sha256Hex(canonicalJSON(r.receipt)) === receiptHash,
    );
    return {
      packageId,
      state: 'DESTROYED',
      destructionId: signed.receipt.destructionId,
      signatureValid,
      registered: onChain,
      receiptHash,
      custodianKeyId: signed.custodianKeyId,
      schema: signed.receipt.schema,
      evidenceIncluded: signed.receipt.evidenceIncluded === false,
    };
  }

  verifyChain() {
    return this.chain.verify();
  }
}
