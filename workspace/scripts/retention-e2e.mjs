// 证据保全与到期销毁端到端（真实 HTTP + 真实进程重启）：
//   保留期限设置 → 保全（原因+案件号）幂等/409/错案件号 → 多保全约束与并发解除
//   → 未到期/保全中禁止销毁 → 到期任务/立即执行 → 销毁覆盖四类物料
//   → 销毁回执不含原始证据且可验签 → 读接口提交前完整/提交后统一已销毁
//   → 存储删除失败：COMMITTING 恢复续完、重启自动续、回执唯一 → 重启幂等。
//
// 用法：node scripts/retention-e2e.mjs                 临时服务，演完即停
//       BASE=http://127.0.0.1:8092 node scripts/retention-e2e.mjs --external
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

const { buildEnvelope, manifestHashOf, R, generateGatewayKeyPair } = await import(
  new URL('../evidence/pack.js', import.meta.url).href);

let BASE = process.env.BASE || '';
const external = process.argv.includes('--external');
const SECRET = 'e2e-retention-secret-' + 'b'.repeat(20);
let child = null;
let tmpDir = null;
function cleanupProcess() { try { child?.kill('SIGKILL'); } catch { /* ignore */ } }
process.on('exit', cleanupProcess);
process.on('SIGINT', () => { cleanupProcess(); process.exit(130); });
process.on('SIGTERM', () => { cleanupProcess(); process.exit(143); });

let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('  ✅', name, extra); }
  else { fail++; console.log('  ❌', name, extra); }
}
function eq(name, a, b) { check(name, a === b, `${JSON.stringify(a)} ${a === b ? '==' : '!='} ${JSON.stringify(b)}`); }

async function api(path, { method, body, secret = SECRET, headers = {} } = {}) {
  const m = method || (body === undefined ? 'GET' : 'POST');
  const h = {};
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (secret !== null) h['X-Upload-Secret'] = SECRET;
  Object.assign(h, headers);
  const res = await fetch(BASE + path, {
    method: m, headers: h, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) throw Object.assign(new Error(typeof data === 'object' ? data.error : text), {
    status: res.status, code: data?.code, raw: data, text,
  });
  return data;
}
async function apiRaw(path, { method, body, secret = SECRET } = {}) {
  const m = method || (body === undefined ? 'GET' : 'POST');
  const h = {};
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (secret !== null) h['X-Upload-Secret'] = SECRET;
  const res = await fetch(BASE + path, {
    method: m, headers: h, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data, text };
}
async function expectCode(name, fn, code, status) {
  try { await fn(); check(name, false, '未拒绝'); }
  catch (e) {
    const ok = e.code === code && (status == null || e.status === status);
    check(name, ok, `${e.code || e.status}/${e.status}（期望 ${code}${status != null ? '/' + status : ''}）`);
    return e;
  }
}

async function startServer() {
  if (!tmpDir) tmpDir = mkdtempSync(join(tmpdir(), 'retention-e2e-'));
  child = spawn(process.execPath, ['evidence/server.js'], {
    env: { ...process.env, EVIDENCE_DIR: tmpDir, EVIDENCE_PORT: '0', EVIDENCE_HOST: '127.0.0.1',
      EVIDENCE_UPLOAD_SECRET: SECRET, EVIDENCE_DEMO: '1' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  let buf = '';
  const port = await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/localhost:(\d+)\//);
      if (m) resolve(Number(m[1]));
    });
    child.on('exit', (code) => reject(new Error('服务提前退出 code=' + code)));
    setTimeout(() => reject(new Error('服务启动超时')), 5000);
  });
  BASE = `http://127.0.0.1:${port}`;
  await new Promise((r) => setTimeout(r, 50));
}
async function stopServer() {
  if (!child) return;
  child.kill('SIGTERM');
  await Promise.race([once(child, 'exit').catch(() => {}), new Promise((r) => setTimeout(r, 1500))]);
  if (child.exitCode === null && child.signalCode === null) {
    try { child.kill('SIGKILL'); } catch { /* ignore */ }
    await once(child, 'exit').catch(() => {});
  }
  child = null;
}
async function restartServer() { await stopServer(); await startServer(); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- 素材 ----------
const gw = generateGatewayKeyPair();
const KID = 'gw-key-1';
const T = '2026-10-01T08:00:00Z';
const PKG = 'PKG-RET-001';
const PKG2 = 'PKG-RET-002';
const PKG3 = 'PKG-RET-003';
function manifestFor(id) {
  return {
    entries: [{ seq: 0, deviceId: 'DEV-1' }, { seq: 1, deviceId: 'DEV-2' }],
    issuedAt: T, validUntil: '2026-10-03T00:00:00Z',
  };
}
async function archivePackage(id) {
  const manifest = manifestFor(id);
  const env1 = buildEnvelope({
    packageId: id, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gw.privateKeyPem,
    records: [
      R.manifest(T, manifest, manifestHashOf(manifest)),
      R.fence(T, 'fence-A', 1, 'CREATED', null, '首次领取'),
      R.segment(T, 'fence-A', 1, 1, [
        { seq: 0, deviceId: 'DEV-1', outcome: 'EXECUTED', note: 'ok' },
        { seq: 1, deviceId: 'DEV-2', outcome: 'FAILED', note: 'secret=' + SECRET },
      ]),
      R.checkpoint(T, 'fence-A', 1, 1, { EXECUTED: 1, SKIPPED: 0, FAILED: 1 }),
    ],
  });
  const r = await api(`/api/packages/${id}/import`, { body: env1 });
  return r;
}

console.log('① 启动服务 / 网关注册 / 归档三个作业包');
if (!external) await startServer();
else BASE = BASE || 'http://127.0.0.1:8092';
await api('/api/gateways', { body: { gatewayId: 'gw-A', keyId: KID, publicKeyPem: gw.publicKeyPem } });
await archivePackage(PKG);
await archivePackage(PKG2);
await archivePackage(PKG3);
const reportBefore = await api(`/api/packages/${PKG}/report`);
check('归档后可读取完整证据报告', Array.isArray(reportBefore.timeline) && reportBefore.timeline.length === 4);

// 制造“被拒信封留底”（422 业务拒绝 → data/rejected 落盘 0600）：PKG3 与 PKG2 各一份。
// 销毁 PKG3 时其留底应删除，PKG2 的留底必须原样保留（不跨包误删）。
function rejectedEnvFor(packageId) {
  return buildEnvelope({
    packageId, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gw.privateKeyPem,
    records: [
      // seq 越界（清单仅 0..1）→ 过信封哈希/验签后在结构业务校验阶段 422
      R.segment(T, 'fence-A', 1, 9, [{ seq: 9, deviceId: 'DEV-9', outcome: 'EXECUTED' }]),
    ],
  });
}
let rejectedPKG3 = null;
try { await api(`/api/packages/${PKG3}/import`, { body: rejectedEnvFor(PKG3) }); }
catch (e) { rejectedPKG3 = e; }
eq('PKG3 被拒信封 422（留底）', rejectedPKG3?.status, 422);
let rejectedPKG2 = null;
try { await api(`/api/packages/${PKG2}/import`, { body: rejectedEnvFor(PKG2) }); }
catch (e) { rejectedPKG2 = e; }
eq('PKG2 被拒信封 422（留底）', rejectedPKG2?.status, 422);
const rejectedFilesBefore = () => readdirSync(join(tmpDir, 'rejected')).filter((n) => n.endsWith('.json'));
check('rejected 目录有两份留底', rejectedFilesBefore().length >= 2, String(rejectedFilesBefore().length));

console.log('② 设置保留期限（幂等 / 409 / 校验）');
// 证据服务用真实墙钟：用相对当前的未来/过去时刻。
const FUTURE = new Date(Date.now() + 30 * 86400000).toISOString();
const FAR_FUTURE = '2099-01-01T00:00:00.000Z';
const PAST = new Date(Date.now() - 2 * 86400000).toISOString();
const retainUntil = FUTURE; // PKG 先设未来（受保全约束）；⑤解除保全后再改成已到期
const ret1 = await api(`/api/packages/${PKG}/retention`, { body: { requestId: 'REQ-RET-1', retainUntil, setBy: 'ops-A' } });
eq('首次设置 201 语义（idempotent=false）', ret1.idempotent, false);
const ret1dup = await api(`/api/packages/${PKG}/retention`, { body: { requestId: 'REQ-RET-1', retainUntil, setBy: 'ops-A' } });
eq('同请求号同文幂等 idempotent=true', ret1dup.idempotent, true);
await expectCode('同请求号不同文 → 409 REQUEST_ID_CONFLICT',
  () => api(`/api/packages/${PKG}/retention`, { body: { requestId: 'REQ-RET-1', retainUntil: PAST, setBy: 'ops-A' } }),
  'REQUEST_ID_CONFLICT', 409);
await expectCode('未知包设置保留期 → 404',
  () => api('/api/packages/NO-SUCH/retention', { body: { requestId: 'REQ-X', retainUntil } }),
  'PACKAGE_NOT_FOUND', 404);
await expectCode('保留期在过去 → 400',
  () => api(`/api/packages/${PKG2}/retention`, { body: { requestId: 'REQ-RET-2', retainUntil: '2000-01-01T00:00:00Z' } }),
  'RETENTION_IN_PAST', 400);
// PKG2 未到期；PKG3 设置 1 秒短保留期（随后等待到期）
await api(`/api/packages/${PKG2}/retention`, { body: { requestId: 'REQ-RET-3', retainUntil: FAR_FUTURE } });
await api(`/api/packages/${PKG3}/retention`, { body: { requestId: 'REQ-RET-4', retainForSeconds: 1 } });
await sleep(1100);

console.log('③ 审计发起保全（原因 + 案件号；幂等 / 409 / 错案件号 / 同案件唯一）');
const hold1 = await api(`/api/packages/${PKG}/holds`, {
  body: { requestId: 'REQ-HOLD-1', caseNo: 'CASE-2026-0001', reason: '涉刑案件冻结', requestedBy: 'auditor-A' },
});
eq('保全创建 active=true', hold1.hold.active, true);
check('保全返回 holdId', Boolean(hold1.hold.holdId));
check('保全生成每包保管密钥', Boolean(hold1.hold.custodianKeyId));
const hold1dup = await api(`/api/packages/${PKG}/holds`, {
  body: { requestId: 'REQ-HOLD-1', caseNo: 'CASE-2026-0001', reason: '涉刑案件冻结', requestedBy: 'auditor-A' },
});
eq('保全同请求号同文幂等', hold1dup.idempotent, true);
eq('幂等返回同一 holdId', hold1dup.hold.holdId, hold1.hold.holdId);
await expectCode('保全同请求号不同文 → 409',
  () => api(`/api/packages/${PKG}/holds`, { body: { requestId: 'REQ-HOLD-1', caseNo: 'CASE-9999-0000', reason: '别的', requestedBy: 'auditor-A' } }),
  'REQUEST_ID_CONFLICT', 409);
await expectCode('错误案件号（太短/非法字符）→ CASE_NUMBER_INVALID',
  () => api(`/api/packages/${PKG}/holds`, { body: { requestId: 'REQ-HOLD-BAD', caseNo: 'x', reason: 'r' } }),
  'CASE_NUMBER_INVALID', 400);
await expectCode('缺少保全原因 → 400',
  () => api(`/api/packages/${PKG}/holds`, { body: { requestId: 'REQ-HOLD-NR', caseNo: 'CASE-2026-0099', reason: '' } }),
  'BAD_REQUEST', 400);
await expectCode('同案件号重复有效保全 → HOLD_ALREADY_ACTIVE',
  () => api(`/api/packages/${PKG}/holds`, { body: { requestId: 'REQ-HOLD-2', caseNo: 'CASE-2026-0001', reason: '又保全' } }),
  'HOLD_ALREADY_ACTIVE', 409);
// 第二个有效保全（多保全约束）
const hold2 = await api(`/api/packages/${PKG}/holds`, {
  body: { requestId: 'REQ-HOLD-3', caseNo: 'CASE-2026-0002', reason: '行政调查', requestedBy: 'auditor-B' },
});
const stHeld = await api(`/api/packages/${PKG}/retention`);
eq('两个有效保全计数=2', stHeld.activeHoldCount, 2);

console.log('④ 保全中 / 未到期 → 禁止销毁，结果可核对');
await expectCode('保全中的包立即销毁 → HOLD_ACTIVE',
  () => api(`/api/packages/${PKG}/destroy`, { body: { requestId: 'D1' } }), 'HOLD_ACTIVE', 409);
await expectCode('未到期包立即销毁 → RETENTION_NOT_EXPIRED',
  () => api(`/api/packages/${PKG2}/destroy`, { body: {} }), 'RETENTION_NOT_EXPIRED', 409);

console.log('⑤ 解除保全（幂等 / 并发解除 409 / 全部解除才放行）');
const rel1 = await api(`/api/packages/${PKG}/holds/release`, {
  body: { requestId: 'REQ-REL-1', caseNo: 'CASE-2026-0001', releasedBy: 'auditor-A' },
});
eq('解除一个后剩余有效保全=1', rel1.activeHolds, 1);
await expectCode('并发/重复解除同一保全 → HOLD_ALREADY_RELEASED',
  () => api(`/api/packages/${PKG}/holds/release`, { body: { requestId: 'REQ-REL-X', caseNo: 'CASE-2026-0001' } }),
  'HOLD_ALREADY_RELEASED', 409);
// 同请求号重放解除 → 幂等 200
const rel1dup = await api(`/api/packages/${PKG}/holds/release`, {
  body: { requestId: 'REQ-REL-1', caseNo: 'CASE-2026-0001', releasedBy: 'auditor-A' },
});
eq('解除同请求号幂等', rel1dup.idempotent, true);
// 仍有一个保全 → 仍不可销毁
await expectCode('仍有 1 个有效保全 → HOLD_ACTIVE',
  () => api(`/api/packages/${PKG}/destroy`, { body: {} }), 'HOLD_ACTIVE', 409);
await api(`/api/packages/${PKG}/holds/release`, {
  body: { requestId: 'REQ-REL-2', holdId: hold2.hold.holdId, releasedBy: 'auditor-B' },
});
// 全部保全解除后，运营用新请求号把保留期改到 1 秒后届满（模拟保留期到期）
await api(`/api/packages/${PKG}/retention`, { body: { requestId: 'REQ-RET-EXPIRED', retainForSeconds: 1 } });
await sleep(1100);
const stDue = await api(`/api/packages/${PKG}/retention`);
eq('全部解除后 activeHoldCount=0', stDue.activeHoldCount, 0);
eq('已过保留期 destructionDue=true', stDue.destructionDue, true);

console.log('⑥ 待销毁列表');
const due = await api('/api/retention/due');
const dueIds = due.packages.map((p) => p.packageId).sort();
check('待销毁含已到期无保全的包', dueIds.includes(PKG) && dueIds.includes(PKG3), JSON.stringify(dueIds));
check('待销毁不含未到期包', !dueIds.includes(PKG2));

console.log('⑦ 到期任务只销毁符合条件的包（保留期已到 + 无有效保全）');
const task = await api('/api/retention/expiry-task', { body: {} });
const destroyedIds = task.destroyed.map((x) => x.packageId).sort();
check('到期任务销毁 PKG/PKG3', destroyedIds.includes(PKG) && destroyedIds.includes(PKG3), JSON.stringify(destroyedIds));

console.log('⑧ 销毁后读接口统一返回已销毁状态（410），看不到部分删除');
const rep410 = await apiRaw(`/api/packages/${PKG}/report`);
eq('报告接口 410', rep410.status, 410);
eq('410 代码 PACKAGE_DESTROYED', rep410.data.code, 'PACKAGE_DESTROYED');
eq('410 状态 DESTROYED', rep410.data.details.destroyedState, 'DESTROYED');
for (const suf of ['timeline', 'conflicts', 'imports', 'verify', 'report.json', 'report.txt'] ) {
  const r = await apiRaw(`/api/packages/${PKG}/${suf}`);
  check(`${suf} 销毁后 410`, r.status === 410, String(r.status));
}
// 销毁后导入新证据也被拒
await expectCode('销毁后导入证据 → PACKAGE_DESTROYED',
  () => api(`/api/packages/${PKG}/import`, { body: {} }), 'PACKAGE_DESTROYED', 410);
// 销毁后保全/设置保留期 409
await expectCode('销毁后保全 409',
  () => api(`/api/packages/${PKG}/holds`, { body: { requestId: 'NH', caseNo: 'CASE-2026-1000', reason: 'r' } }),
  'PACKAGE_DESTROYED', 409);

console.log('⑨ 销毁回执：不含原始证据、可独立验签、登记上链');
const receipt = await api(`/api/packages/${PKG}/destruction-receipt`);
check('回执有 128-hex Ed25519 签名', /^[0-9a-f]{128}$/.test(receipt.signature));
check('回执含保管公钥', receipt.custodianPublicKeyPem.includes('BEGIN PUBLIC KEY'));
eq('回执 evidenceIncluded=false', receipt.receipt.evidenceIncluded, false);
const blob = JSON.stringify(receipt.receipt);
check('回执不含设备号/原始证据', !blob.includes('DEV-1') && !blob.includes('fence-A'));
check('回执记录被销毁链文件的链尖指纹', Boolean(receipt.receipt.artifactsDestroyed.chainFiles.ledger?.tipHash));
check('回执记录凭据旁车销毁（密钥指纹）', Boolean(receipt.receipt.artifactsDestroyed.credentialSidecar?.publicKeyPemFingerprint));
check('回执不含 upload secret', !blob.includes(SECRET));
const vf = await api(`/api/packages/${PKG}/destruction-receipt/verify`);
eq('回执验签通过', vf.signatureValid, true);
eq('回执登记在保留链上', vf.registered, true);
eq('验签确认回执不含证据', vf.evidenceIncluded, true);

console.log('⑩ 销毁物理覆盖四类物料 + 文件权限核对');
const pkgDir = join(tmpDir, 'packages', PKG);
check('包目录（链文件/业务索引/凭据旁车/冲突材料）已删除', !existsSync(pkgDir));
// rejected 留底（制造过一个冲突更充分；这里核对该包目录下三链与旁车已不存在）
check('ledger.jsonl 已删除', !existsSync(join(pkgDir, 'ledger.jsonl')));
check('quarantine.jsonl 已删除', !existsSync(join(pkgDir, 'quarantine.jsonl')));
check('retention-credential.json 旁车已删除', !existsSync(join(pkgDir, 'retention-credential.json')));
// 其他包不受影响
check('未到期包 PKG2 物料仍在', existsSync(join(tmpDir, 'packages', PKG2, 'ledger.jsonl')));
// rejected 冲突留底：被销毁包（PKG3）的留底删除，未销毁包（PKG2）的留底原样保留（不跨包误删）
const rejectedTargetsAfter = readdirSync(join(tmpDir, 'rejected'))
  .filter((n) => n.endsWith('.json'))
  .map((n) => JSON.parse(readFileSync(join(tmpDir, 'rejected', n), 'utf8')).targetPackageId)
  .sort();
check('rejected 仅保留未销毁包 PKG2 的留底',
  JSON.stringify(rejectedTargetsAfter) === JSON.stringify([PKG2]), JSON.stringify(rejectedTargetsAfter));
// 全局保留链仍在且 0600
check('全局保留链 retention.jsonl 存在', existsSync(join(tmpDir, 'retention.jsonl')));
eq('保留链文件权限 0600', statSync(join(tmpDir, 'retention.jsonl')).mode & 0o777, 0o600);

console.log('⑪ 重复销毁不产生第二份回执（同号/不同号都唯一）');
const seqLog = readFileSync(join(tmpDir, 'retention.jsonl'), 'utf8').trim().split('\n').length;
const dAgain1 = await api(`/api/packages/${PKG}/destroy`, { body: { requestId: 'DUP-D-1' } });
eq('重复销毁 alreadyDestroyed', dAgain1.alreadyDestroyed, true);
eq('重复销毁回同一 destructionId', dAgain1.receipt.destructionId, receipt.receipt.destructionId);
const dAgain2 = await api(`/api/packages/${PKG}/destroy`, { body: { requestId: 'DUP-D-2' } });
eq('不同请求号重复销毁仍同一回执', dAgain2.receipt.destructionId, receipt.receipt.destructionId);
const seqLogAfter = readFileSync(join(tmpDir, 'retention.jsonl'), 'utf8').trim().split('\n').length;
eq('重复销毁不追加保留链记录', seqLogAfter, seqLog);

console.log('⑫ 真实进程重启：墓碑/待销毁/回执验签一致，PKG2 到期后由启动恢复语义保持');
const dueP2Before = (await api('/api/retention/due')).packages.map((p) => p.packageId);
check('重启前 PKG2 不在待销毁', !dueP2Before.includes(PKG2));
// 把 PKG2 保留期改为 1 秒后到期（同号会 409，用新请求号即“重新设置”）
await api(`/api/packages/${PKG2}/retention`, { body: { requestId: 'REQ-RET-5', retainForSeconds: 1 } });
await sleep(1100);
await restartServer();
// 重启后已销毁包仍 410、回执仍可验
const repAfter = await apiRaw(`/api/packages/${PKG}/report`);
eq('重启后销毁包仍 410', repAfter.status, 410);
const vfAfter = await api(`/api/packages/${PKG}/destruction-receipt/verify`);
eq('重启后回执验签仍通过', vfAfter.signatureValid, true);
eq('重启后回执仍登记上链', vfAfter.registered, true);
// 重启不会自动跑到期任务（仅恢复中断的销毁）；PKG2 现在在待销毁列表
const dueAfter = (await api('/api/retention/due')).packages.map((p) => p.packageId);
check('重启后 PKG2 进入待销毁', dueAfter.includes(PKG2));
// 包列表包含销毁墓碑
const list = await api('/api/packages');
const tomb = list.packages.find((p) => p.packageId === PKG);
eq('包列表含销毁墓碑 destroyedState=DESTROYED', tomb.destroyedState, 'DESTROYED');
const p2 = list.packages.find((p) => p.packageId === PKG2);
check('PKG2 列表仍有保留信息', p2.retention && p2.retention.destructionDue === true);

console.log('⑬ 存储删除失败：提交后 COMMITTING，读统一已销毁；恢复续完，回执唯一');
// PKG2 立即执行，但先注入“删除 PKG2 失败”
await api('/api/demo/fault/delete', { body: { mode: 'fail-package', packageId: PKG2 } });
const failRes = await apiRaw(`/api/packages/${PKG2}/destroy`, { body: { requestId: 'DESTROY-P2-1' } });
eq('删除失败返回 500/STORAGE_DELETE_FAILED', failRes.status, 500);
eq('错误码 STORAGE_DELETE_FAILED', failRes.data.code, 'STORAGE_DELETE_FAILED');
// 状态为 COMMITTING；物料仍在磁盘
const st2commit = await api(`/api/packages/${PKG2}/retention`);
eq('状态 COMMITTING（正在提交）', st2commit.destroyedState, 'COMMITTING');
check('COMMITTING 期间物理物料尚未删净（故障注入导致）', existsSync(join(tmpDir, 'packages', PKG2, 'ledger.jsonl')));
// 所有证据读取此刻统一 410（不会看到部分删除）
const rep410b = await apiRaw(`/api/packages/${PKG2}/report`);
eq('COMMITTING 时报告接口也 410', rep410b.status, 410);
eq('410 标注 COMMITTING', rep410b.data.details.destroyedState, 'COMMITTING');
// 回执尚未最终落定
const receiptPending = await apiRaw(`/api/packages/${PKG2}/destruction-receipt`);
eq('COMMITTING 取回执 409', receiptPending.status, 409);
// 同请求号在 COMMITTING 期间重复提交：销毁不支持请求号分支（已在提交），仍尝试续完→仍失败 500
const retryCommit = await apiRaw(`/api/packages/${PKG2}/destroy`, { body: { requestId: 'DESTROY-P2-1' } });
eq('故障未恢复时重试仍失败 500', retryCommit.status, 500);
// 保留链里只有一条 COMMITTED（没有第二份销毁令/回执）
const committingCount = readFileSync(join(tmpDir, 'retention.jsonl'), 'utf8')
  .split('\n').filter((l) => l.includes('"DESTRUCTION_COMMITTED"') && l.includes(PKG2)).length;
eq('PKG2 只有一条销毁提交记录', committingCount, 1);

console.log('⑭ 故障恢复（不重启，显式恢复接口）→ 续完到 DESTROYED，回执不变');
await api('/api/demo/fault/delete', { body: { mode: 'off' } });
// 在恢复前先取提交时刻的 destructionId（经状态接口）
const committingId = st2commit.destructionId;
const rec = await api('/api/retention/recover', { body: {} });
check('恢复报告含 PKG2', rec.recovered.some((x) => x.packageId === PKG2));
eq('恢复后状态 DESTROYED', (await api(`/api/packages/${PKG2}/retention`)).destroyedState, 'DESTROYED');
check('恢复后物料删除净', !existsSync(join(tmpDir, 'packages', PKG2)));
const receipt2 = await api(`/api/packages/${PKG2}/destruction-receipt`);
eq('续完回执 destructionId 与提交时一致', receipt2.receipt.destructionId, committingId);
const vf2 = await api(`/api/packages/${PKG2}/destruction-receipt/verify`);
eq('PKG2 回执验签通过', vf2.signatureValid, true);

console.log('⑮ COMMITTING 期间真实进程重启 → 启动自动续完到唯一结果');
// 再造一个包，制造 COMMITTING 后直接杀进程
const PKG4 = 'PKG-RET-004';
await archivePackage(PKG4);
await api(`/api/packages/${PKG4}/retention`, { body: { requestId: 'REQ-RET-6', retainForSeconds: 1 } });
await sleep(1100);
// 用持久化的“环境级”失败做不到（故障注入仅内存）；因此：先在内存注入失败拿到 COMMITTING，
// 重启后注入失效（新进程默认真实删除）→ 启动恢复自动续完。
await api('/api/demo/fault/delete', { body: { mode: 'fail-package', packageId: PKG4 } });
const c4 = await apiRaw(`/api/packages/${PKG4}/destroy`, { body: {} });
eq('PKG4 删除失败进入 COMMITTING', c4.status, 500);
const id4 = (await api(`/api/packages/${PKG4}/retention`)).destructionId;
await restartServer(); // 新进程无故障注入 → 构造函数自动 recoverCommitting
eq('重启后 PKG4 已 DESTROYED（启动自动续完）', (await api(`/api/packages/${PKG4}/retention`)).destroyedState, 'DESTROYED');
const r4 = await api(`/api/packages/${PKG4}/destruction-receipt`);
eq('PKG4 回执与提交时同一 destructionId', r4.receipt.destructionId, id4);
eq('PKG4 回执验签通过', (await api(`/api/packages/${PKG4}/destruction-receipt/verify`)).signatureValid, true);

console.log('⑯ 全局保留链独立核验 + 导出脱敏仍有效');
const chain = await api('/api/chain/verify');
eq('全局保留链 OK', chain.retention.ok, true);
// 未销毁包的报告导出仍脱敏
const txt = await apiRaw(`/api/packages/PKG-RET-002/report.txt`).catch(() => null);
// PKG2 已销毁 → 410（这里验证销毁后导出也不泄漏）
if (txt) eq('已销毁包 TXT 导出 410', txt.status, 410);

if (!external) {
  await stopServer();
  rmSync(tmpDir, { recursive: true, force: true });
}
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
if (fail) process.exitCode = 1;
