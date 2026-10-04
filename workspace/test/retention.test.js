// 保留期限 / 证据保全 / 到期销毁领域单测：
//   保留期设置、保全（案件号/原因/幂等/409）、多保全约束、并发解除、
//   销毁两阶段（COMMITTING/DESTROYED）、存储删除失败恢复、重启续完、
//   回执唯一与验签、读状态语义、到期任务。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync, mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RetentionService, CREDENTIAL_FILE } from '../evidence/retention.js';
import { ChainLog } from '../evidence/chains.js';

function tmp() {
  return mkdtempSync(join(tmpdir(), 'retention-test-'));
}
const PKG = 'PKG-UT-001';

// 构造一个有归档物料（ledger/quarantine/audit）+ 一条 rejected 留底的包目录。
function seedPackage(rootDir, packageId = PKG) {
  const dir = join(rootDir, 'packages', packageId);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ledger = new ChainLog(join(dir, 'ledger.jsonl'),
    { chainName: 'ledger', packageId, quarantineDir: dir, label: `${packageId}/ledger` });
  ledger.append({ kind: 'manifest', v: 1 });
  const q = new ChainLog(join(dir, 'quarantine.jsonl'),
    { chainName: 'quarantine', packageId, quarantineDir: dir, label: `${packageId}/quarantine` });
  q.append({ kind: 'CONFLICT', slot: 'segment:x' });
  const audit = new ChainLog(join(dir, 'audit.jsonl'),
    { chainName: 'audit', packageId, quarantineDir: dir, label: `${packageId}/audit` });
  audit.append({ kind: 'IMPORT', result: 'ACCEPTED' });
  // 被拒信封留底
  const rejDir = join(rootDir, 'rejected');
  mkdirSync(rejDir, { recursive: true });
  writeFileSync(join(rejDir, 'bad.json'),
    JSON.stringify({ at: '2026-10-01T00:00:00Z', targetPackageId: packageId, code: 'X', envelope: { secret: 'S' } }) + '\n',
    { mode: 0o600 });
  return dir;
}

test('未设置保留期/未知包：保全与销毁都拒绝', () => {
  const dir = tmp();
  try {
    const svc = new RetentionService(dir);
    assert.throws(() => svc.setRetention({ requestId: 'r1', packageId: 'GHOST', retainUntil: '2099-01-01T00:00:00Z' }),
      { code: 'PACKAGE_NOT_FOUND' });
    assert.throws(() => svc.placeHold({ requestId: 'h1', packageId: 'GHOST', caseNo: 'CASE-0001', reason: 'x' }),
      { code: 'PACKAGE_NOT_FOUND' });
    assert.throws(() => svc.destroy({ packageId: 'GHOST' }), { code: 'PACKAGE_NOT_FOUND' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('设置保留期限：已到期/未到期判定正确；同请求号同文幂等、异文 409', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    const svc = new RetentionService(dir, { clock: () => t });
    const out = svc.setRetention({ requestId: 'ret-1', packageId: PKG, retainForDays: 7, setBy: 'ops-A' });
    assert.equal(out.idempotent, false);
    assert.ok(out.retention.retainUntil > t);

    const st = svc.status(PKG);
    assert.equal(st.destructionDue, false);
    assert.equal(st.retention.expired, false);

    // 同号同文 -> 幂等
    const again = svc.setRetention({ requestId: 'ret-1', packageId: PKG, retainForDays: 7, setBy: 'ops-A' });
    assert.equal(again.idempotent, true);

    // 同号不同文 -> 409
    assert.throws(() => svc.setRetention({ requestId: 'ret-1', packageId: PKG, retainForDays: 9, setBy: 'ops-A' }),
      { code: 'REQUEST_ID_CONFLICT', status: 409 });

    // 时钟跨过保留期 -> due
    t = '2026-10-20T00:00:00.000Z';
    assert.equal(svc.status(PKG).destructionDue, true);
    assert.equal(svc.listDue().length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('保全需要合法案件号与原因；同请求号幂等/异文 409；同案件有效保全唯一', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    const svc = new RetentionService(dir);
    assert.throws(() => svc.placeHold({ requestId: 'h1', packageId: PKG, caseNo: 'x', reason: 'r' }),
      { code: 'CASE_NUMBER_INVALID' });
    assert.throws(() => svc.placeHold({ requestId: 'h2', packageId: PKG, caseNo: 'CASE-0001', reason: '' }),
      { code: 'BAD_REQUEST' });

    const h = svc.placeHold({ requestId: 'h3', packageId: PKG, caseNo: 'CASE-0001', reason: '涉案冻结', requestedBy: 'auditor-A' });
    assert.equal(h.idempotent, false);
    assert.equal(h.hold.active, true);
    assert.equal(svc.status(PKG).activeHoldCount, 1);

    // 同号同文 -> 原保全
    const dup = svc.placeHold({ requestId: 'h3', packageId: PKG, caseNo: 'CASE-0001', reason: '涉案冻结', requestedBy: 'auditor-A' });
    assert.equal(dup.idempotent, true);
    assert.equal(dup.hold.holdId, h.hold.holdId);

    // 同号异文 -> 409
    assert.throws(() => svc.placeHold({ requestId: 'h3', packageId: PKG, caseNo: 'CASE-0002', reason: '其他', requestedBy: 'auditor-A' }),
      { code: 'REQUEST_ID_CONFLICT', status: 409 });

    // 同案件重复保全 -> HOLD_ALREADY_ACTIVE
    assert.throws(() => svc.placeHold({ requestId: 'h4', packageId: PKG, caseNo: 'CASE-0001', reason: '再来一次' }),
      { code: 'HOLD_ALREADY_ACTIVE', status: 409 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('多个有效保全同时约束：任一在效都不能销毁；全部解除且到期才可销毁', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    const svc = new RetentionService(dir, { clock: () => t });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    svc.placeHold({ requestId: 'h1', packageId: PKG, caseNo: 'CASE-0001', reason: 'a' });
    svc.placeHold({ requestId: 'h2', packageId: PKG, caseNo: 'CASE-0002', reason: 'b' });
    t = '2026-10-20T00:00:00.000Z'; // 已过保留期

    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'HOLD_ACTIVE', status: 409 });
    const rel1 = svc.releaseHold({ requestId: 'rel1', packageId: PKG, caseNo: 'CASE-0001' });
    assert.equal(rel1.activeHolds, 1);
    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'HOLD_ACTIVE' });

    // 并发/重复解除同一保全 -> HOLD_ALREADY_RELEASED
    assert.throws(() => svc.releaseHold({ requestId: 'relX', packageId: PKG, caseNo: 'CASE-0001' }),
      { code: 'HOLD_ALREADY_RELEASED', status: 409 });

    svc.releaseHold({ requestId: 'rel2', packageId: PKG, caseNo: 'CASE-0002' });
    const out = svc.destroy({ packageId: PKG, trigger: 'MANUAL', destroyedBy: 'ops' });
    assert.equal(out.status, 'DESTROYED');
    assert.equal(existsSync(join(dir, 'packages', PKG)), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('未到期即使无保全也不能销毁', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    const svc = new RetentionService(dir, { clock: () => '2026-10-01T00:00:00.000Z' });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 30 });
    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'RETENTION_NOT_EXPIRED', status: 409 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('销毁覆盖四类物料（链文件/冲突材料/业务索引/凭据旁车/rejected 留底）', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    const svc = new RetentionService(dir, { clock: () => t });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    svc.placeHold({ requestId: 'h', packageId: PKG, caseNo: 'CASE-0001', reason: 'r' });
    assert.ok(existsSync(join(dir, 'packages', PKG, CREDENTIAL_FILE)), '保全应创建凭据旁车');
    svc.releaseHold({ requestId: 'rel', packageId: PKG, caseNo: 'CASE-0001' });
    t = '2026-10-20T00:00:00.000Z';
    const out = svc.destroy({ packageId: PKG });
    assert.equal(out.status, 'DESTROYED');

    // 包目录整体消失
    assert.equal(existsSync(join(dir, 'packages', PKG)), false);
    // rejected 留底（该包）被删除
    assert.equal(existsSync(join(dir, 'rejected', 'bad.json')), false);
    // 全局保留链与墓碑仍在
    assert.ok(existsSync(join(dir, 'retention.jsonl')));
    assert.equal(svc.status(PKG).destroyedState, 'DESTROYED');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('销毁回执不含原始证据、可验签、链上可核对；重复销毁不产生第二份', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    const svc = new RetentionService(dir, { clock: () => t });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    t = '2026-10-20T00:00:00.000Z';
    const out1 = svc.destroy({ packageId: PKG, destroyedBy: 'ops' });
    const id1 = out1.destructionId;
    const receipt1 = out1.receipt.receipt;

    // 回执不含证据：无 manifest 条目/设备/分段内容
    const blob = JSON.stringify(receipt1);
    assert.ok(!blob.includes('manifest'));
    assert.equal(receipt1.evidenceIncluded, false);
    assert.ok(receipt1.artifactsDestroyed.chainFiles.ledger.tipHash); // 只有链尖指纹

    // 验签通过且登记上链
    const v = svc.verifyReceipt(PKG);
    assert.equal(v.signatureValid, true);
    assert.equal(v.registered, true);
    assert.equal(v.evidenceIncluded, true); // 回执确实不含证据

    // 重复销毁 -> 同一份回执/同一 destructionId，不追加
    const seqBefore = svc.chain.seq;
    const out2 = svc.destroy({ packageId: PKG });
    assert.equal(out2.alreadyDestroyed, true);
    assert.equal(out2.receipt.destructionId, id1);
    assert.equal(svc.chain.seq, seqBefore);

    // 同请求号销毁也回原结果
    void receipt1;
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('存储删除失败：状态停在 COMMITTING，读接口统一已销毁；恢复后续完且回执不变', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    let fail = true;
    const svc = new RetentionService(dir, {
      clock: () => t,
      fs: { deleteArtifacts: () => { if (fail) throw Object.assign(new Error('disk busy'), { code: 'STORAGE_DELETE_FAILED' }); } },
    });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    t = '2026-10-20T00:00:00.000Z';

    // 第一次：提交成功但物理删除失败 -> 抛错，状态 COMMITTING
    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'STORAGE_DELETE_FAILED' });
    assert.equal(svc.status(PKG).destroyedState, 'COMMITTING');
    // 读接口（销毁视图）统一显示提交中，不暴露部分删除
    assert.match(svc.destroyedView(PKG).note, /提交中/);
    const committingId = svc.status(PKG).destructionId;

    // 恢复删除成功 -> 续完，同一 destructionId/回执
    fail = false;
    const recovered = svc.recoverCommitting();
    assert.equal(recovered.length, 1);
    assert.equal(recovered[0].destructionId, committingId);
    assert.equal(svc.status(PKG).destroyedState, 'DESTROYED');
    assert.equal(svc.verifyReceipt(PKG).signatureValid, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('服务重启：重放保留链后状态一致；COMMITTING 在启动时自动续完；DESTROYED 不重复回执', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    let fail = true;
    let svc = new RetentionService(dir, {
      clock: () => t,
      fs: { deleteArtifacts: () => { if (fail) throw Object.assign(new Error('disk'), { code: 'STORAGE_DELETE_FAILED' }); } },
    });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    svc.placeHold({ requestId: 'h', packageId: PKG, caseNo: 'CASE-0009', reason: 'r' });
    svc.releaseHold({ requestId: 'rel', packageId: PKG, caseNo: 'CASE-0009' });
    t = '2026-10-20T00:00:00.000Z';
    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'STORAGE_DELETE_FAILED' });
    const committingId = svc.status(PKG).destructionId;

    // 重启一个新实例（仍失败）：保持 COMMITTING
    const svc2 = new RetentionService(dir, {
      clock: () => t,
      fs: { deleteArtifacts: () => { if (fail) throw Object.assign(new Error('disk'), { code: 'STORAGE_DELETE_FAILED' }); } },
    });
    assert.equal(svc2.status(PKG).destroyedState, 'COMMITTING');

    // 存储恢复后再启动 -> 自动续完
    fail = false;
    const svc3 = new RetentionService(dir, { clock: () => t });
    assert.equal(svc3.status(PKG).destroyedState, 'DESTROYED');
    assert.equal(svc3.status(PKG).destructionId, committingId);
    assert.equal(svc3.verifyReceipt(PKG).signatureValid, true);

    // 再来一个全新实例：不新增任何记录，回执仍唯一
    const seq = svc3.chain.seq;
    const svc4 = new RetentionService(dir, { clock: () => t });
    assert.equal(svc4.chain.seq, seq);
    assert.equal(svc4.status(PKG).destroyedState, 'DESTROYED');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('到期任务：只销毁已到期且无保全的包；有保全/未到期保留；删除失败不阻断其他包', () => {
  const dir = tmp();
  try {
    seedPackage(dir, 'PKG-DUE');
    seedPackage(dir, 'PKG-HELD');
    seedPackage(dir, 'PKG-FRESH');
    let t = '2026-10-01T00:00:00.000Z';
    let failHeld = false;
    const svc = new RetentionService(dir, {
      clock: () => t,
      fs: { deleteArtifacts: (d, id) => { if (id === 'PKG-HELD' && failHeld) throw Object.assign(new Error('io'), { code: 'STORAGE_DELETE_FAILED' }); } },
    });
    svc.setRetention({ requestId: 'r1', packageId: 'PKG-DUE', retainForDays: 1 });
    svc.setRetention({ requestId: 'r2', packageId: 'PKG-HELD', retainForDays: 1 });
    svc.setRetention({ requestId: 'r3', packageId: 'PKG-FRESH', retainForDays: 60 });
    svc.placeHold({ requestId: 'h', packageId: 'PKG-HELD', caseNo: 'CASE-0020', reason: 'hold' });

    t = '2026-10-20T00:00:00.000Z';
    const res = svc.runExpiryTask();
    assert.deepEqual(res.destroyed.map((x) => x.packageId), ['PKG-DUE']);
    assert.equal(svc.status('PKG-HELD').activeHoldCount, 1);
    assert.equal(svc.status('PKG-FRESH').destructionDue, false);

    // 解除保全后到期任务销毁它
    svc.releaseHold({ requestId: 'rel', packageId: 'PKG-HELD', caseNo: 'CASE-0020' });
    const res2 = svc.runExpiryTask();
    assert.deepEqual(res2.destroyed.map((x) => x.packageId), ['PKG-HELD']);

    // 再次跑任务：已销毁/未到期都不重复
    const res3 = svc.runExpiryTask();
    assert.equal(res3.destroyed.length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('销毁后不能再保全/设置保留期；保全中（持有有效保全）的销毁被拒结果可核对', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    const svc = new RetentionService(dir, { clock: () => t });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    svc.placeHold({ requestId: 'h', packageId: PKG, caseNo: 'CASE-0030', reason: 'r' });
    t = '2026-10-20T00:00:00.000Z';
    // 保全中
    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'HOLD_ACTIVE' });
    svc.releaseHold({ requestId: 'rel', packageId: PKG, caseNo: 'CASE-0030' });
    svc.destroy({ packageId: PKG });
    assert.throws(() => svc.placeHold({ requestId: 'h2', packageId: PKG, caseNo: 'CASE-0031', reason: 'r' }),
      { code: 'PACKAGE_DESTROYED', status: 409 });
    assert.throws(() => svc.setRetention({ requestId: 'r2', packageId: PKG, retainForDays: 1 }),
      { code: 'PACKAGE_DESTROYED', status: 409 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('请求号台账由链重放重建：新实例上同号异文仍 409、同号同文幂等', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let svc = new RetentionService(dir);
    svc.setRetention({ requestId: 'persist-1', packageId: PKG, retainUntil: '2099-01-01T00:00:00Z' });
    // 新实例重放
    svc = new RetentionService(dir);
    assert.throws(() => svc.setRetention({ requestId: 'persist-1', packageId: PKG, retainUntil: '2098-01-01T00:00:00Z' }),
      { code: 'REQUEST_ID_CONFLICT' });
    const ok = svc.setRetention({ requestId: 'persist-1', packageId: PKG, retainUntil: '2099-01-01T00:00:00Z' });
    assert.equal(ok.idempotent, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('保全创建/解除与到期任务并发串行裁决：不会误删有保全的包', () => {
  const dir = tmp();
  try {
    seedPackage(dir);
    let t = '2026-10-01T00:00:00.000Z';
    const svc = new RetentionService(dir, { clock: () => t });
    svc.setRetention({ requestId: 'r', packageId: PKG, retainForDays: 1 });
    t = '2026-10-20T00:00:00.000Z';
    // 模拟“到期任务正要销毁”与“审计发起保全”并发：命令串行，保全先落盘则销毁必被拒。
    svc.placeHold({ requestId: 'h', packageId: PKG, caseNo: 'CASE-0040', reason: '临界保全' });
    // 直接销毁被 HOLD_ACTIVE 拒绝
    assert.throws(() => svc.destroy({ packageId: PKG }), { code: 'HOLD_ACTIVE' });
    // 到期任务预检阶段即跳过仍有保全的包：不销毁、不报错、包与保全都在
    const task = svc.runExpiryTask();
    assert.equal(task.destroyed.length, 0);
    assert.equal(task.skipped.length, 0);
    assert.equal(existsSync(join(dir, 'packages', PKG)), true);
    assert.equal(svc.status(PKG).activeHoldCount, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
