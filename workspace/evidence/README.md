# 证据归档与冲突核验模块（现场网关离线作业包）

断网期间多个现场网关各自保存**同一作业包**的清单、围栏变更、分段回执与检查点。运营人员通过
网页或 HTTP 接口导入这些**带签名的证据包**；模块校验规范化签名与哈希链后，按 `packageId` 归档，
并生成**可阅读、可下载的核验报告**。零依赖，纯 Node.js ≥ 20，独立进程（默认端口 **8092**）。

```bash
npm run evidence                 # 启动服务 → http://localhost:8092/
npm run demo:evidence            # 一键演示 9 个场景（有效/重复/冲突/多围栏/倒退/篡改/错签）
npm run demo:evidence -- --print # 输出可直接粘到网页的示例信封（含两个网关公钥）
npm run test:e2e:evidence        # 88 项真实 HTTP 断言（含真实进程重启）
npm run test:e2e:retention       # 90 项证据保全与到期销毁真实 HTTP 断言（含真实进程重启/删除故障恢复）
```

## 信任模型与密钥纪律

- **网关私钥（Ed25519）只存在于网关/制包工具侧**，服务从不接收；注册接口只收 SPKI 公钥 PEM，
  收到私钥材料直接 `PRIVATE_KEY_REJECTED`。
- **upload secret** 用于导入鉴权，仅经请求头 `X-Upload-Secret` 传输，常量时间比较；
  存于 `data/evidence/upload-secret.json`（**0600**；环境变量 `EVIDENCE_UPLOAD_SECRET` 优先），
  任何响应、页面、日志、导出报告都**不回显**该值。
- 被拒绝的信封原样落盘到 `data/evidence/rejected/`（**0600**，仅审计用），不进入证据链。

## 证据信封（可独立复算）

```jsonc
{
  "schema": "offline-evidence/1",
  "packageId": "PKG-001",
  "gatewayId": "gw-A",
  "keyId": "gw-key-1",
  "records": [ /* manifest / fence / segment / checkpoint */ ],
  "envelopeHash": "<sha256(canonicalJSON({schema,packageId,gatewayId,keyId,records}))>",
  "signature": "<Ed25519 网关私钥对 envelopeHash hex 文本的签名>"
}
```

规范化规则：键名字典序、无多余空白（见 `hashing.js#canonicalJSON`，任意语言可复算）。
记录字段有**严格白名单**，夹带未知字段整包拒绝。四类记录：

| kind | 关键字段 |
| --- | --- |
| `manifest` | `manifest.entries[{seq,deviceId}]`、`issuedAt`、`validUntil`、`manifestHash`（内容不自洽即 `MANIFEST_HASH_MISMATCH`） |
| `fence` | `fenceId`、`version`（全局只增、必须连续）、`action: CREATED/REVISED/CLOSED`、`prevVersion` |
| `segment` | `fenceId`、`fenceVersion`、`segSeq`（同围栏严格递增）、`entries[{seq,deviceId,outcome,note?}]`（序号/设备必须与清单一致） |
| `checkpoint` | `fenceVersion`、`lastSeq`、`counts{EXECUTED,SKIPPED,FAILED}` |

## 裁决流水线（严格顺序）

1. **结构**：信封/记录形状、字段白名单；
2. **信封哈希**：规范化复算，任何字节被改 → `ENVELOPE_HASH_MISMATCH`；
3. **注册表 + Ed25519 验签**：未知网关 `GATEWAY_UNKNOWN`，keyId 不符 `SIGNATURE_KEY_MISMATCH`，
   签名失败 `SIGNATURE_INVALID`（**先验签后查重复**，错签信封不能借"同哈希重复"放行）；
4. **重复导入**：同一 `envelopeHash` 返回**首次裁决原结果**（同 `importId`、同首次时间、同 disposition）；
5. **业务规则**：manifest 首位、序号/设备范围、围栏版本连续（`FENCE_VERSION_GAP`）、
   引用围栏存在（`FENCE_UNKNOWN`）、分段号递增；
6. **槽位裁决（原子）**：
   - 同槽位（manifest / `fence:id:v#` / `segment:id:v#:seg#` / `checkpoint:id:v#`）**同语义指纹** → 幂等跳过；
   - **不同指纹 → 冲突隔离**：原证据写入 `quarantine.jsonl`（保留外来+已存双指纹），
     **已存证据绝不覆盖**；
   - 检查点跨围栏**不倒退**：新版本 `lastSeq` 低于历史最高 → `CHECKPOINT_REGRESSED` 隔离；
   - `CLOSED` 是围栏生命周期推进（独立槽），重复 CLOSED 幂等。

> **语义指纹**只覆盖业务字段（不含 `ts`、网关身份、信封哈希），所以同内容由不同网关、
> 不同时刻重传判为**重复**而非冲突；同分段号但 outcome/note 不同则判**冲突**。

## 落盘与重启（摘要不变）

每个包目录 `data/evidence/packages/<packageId>/` 下三条独立 SHA-256 哈希链（各自 genesis 锚定
`packageId`，跨包/跨链调换即断）：

```
ledger.jsonl      已接受证据（只增，永不覆盖/删除）
quarantine.jsonl  冲突隔离的原证据（含已存证据指纹）
audit.jsonl       每次导入裁决（ACCEPTED / DUPLICATE / CONFLICTS）
```

- 进程重启时逐行重放重建全部投影；**报告摘要 `reportDigest`、冲突列表、链尖重启前后完全一致**。
- 链文件**中途损坏/断链/哈希不符** → 该链只读隔离（503 `CHAIN_QUARANTINED`），文件原样保留；
- 仅文件**末尾单条无换行残尾**（断电）→ 原始字节归档到同目录旁证后截断续链。

## 核验报告

- **确定性时间线**：按 `(围栏版本, 事件类别, 分段序号, ts, ledgerSeq)` 排序，
  围栏创建/关闭、分段回执、检查点交错呈现；
- **多围栏合并**：当前围栏=最高版本；当前检查点从高版本向低版本取第一个有效水位，
  高版本尚无检查点时**沿用上一围栏水位（carried）**，绝不因新围栏把水位归零；
- **旧围栏证据仍可查询**（`GET .../fences/:version`），但显式标注"不得作为当前进度"；
- 报告导出三种格式，**全部经递归脱敏**（敏感键名、私钥 PEM、密钥字面量一律打码）：
  - `GET /api/packages/:id/report.json`（下载，带 `redaction.applied`）
  - `GET /api/packages/:id/report.txt`（可阅读文本）
  - `GET /api/packages/:id/report.html`（可内嵌 HTML 片段）
- `reportDigest = sha256(canonicalJSON(确定性语义字段 + 三链链尖 + 时间线 + 冲突 + 裁决))`，
  不含生成时间/接收时间等易变项——重复导入与重启都不改变它。

## 证据保全与到期销毁（保留期限 / legal hold / 可恢复销毁）

在归档证据之上叠加一套**事件溯源的保留策略状态机**，全部状态落在数据根目录一条独立哈希链
`data/evidence/retention.jsonl`（**0600**，genesis 与业务三链不同）；即使某包材料被整体销毁，
链上仍保留可核对的**墓碑**与**签名销毁回执**。

- **保留期限（运营方）**：`POST /api/packages/:id/retention`，`{requestId, retainUntil|retainForDays|retainForSeconds, setBy}`。
  期限必须晚于当前（`RETENTION_IN_PAST`）；只能对已归档包设置（未知包 404）。
- **证据保全（审计方）**：`POST /api/packages/:id/holds`，`{requestId, caseNo, reason, requestedBy}`。
  - 案件号 `caseNo` 必须是 4–64 位字母/数字/连字符（首尾为字母数字），否则 `CASE_NUMBER_INVALID`；原因必填。
  - 同一案件号对同一包只允许一个**有效保全**（`HOLD_ALREADY_ACTIVE`）；一个包可被**多个不同案件的有效保全**同时约束。
  - 首次保全时生成该包专属 **Ed25519 保管密钥**，私钥仅写入包目录旁车 `retention-credential.json`（**0600**），
    公钥随保全记录上保留链；该密钥用于给本包销毁回执签名。
- **解除保全**：`POST /api/packages/:id/holds/release`，用 `holdId` 或 `caseNo` 定位。
  并发/重复解除同一保全 → `HOLD_ALREADY_RELEASED(409)`（结果可核对，不重复入账）。
- **客户请求号幂等（三个命令均遵守）**：同 `requestId` + 同正文 → 返回原结果（不追加记录）；
  同 `requestId` + 不同正文 → `409 REQUEST_ID_CONFLICT`。台账由保留链重放重建，重启后语义不变。
- **销毁资格**：必须同时满足 **保留期已到 且 全部有效保全已解除**，否则
  `RETENTION_NOT_EXPIRED / RETENTION_NOT_SET / HOLD_ACTIVE(409)`。

### 销毁是两阶段、可恢复、结果唯一的事务

```
ACTIVE ──destroy（资格通过）──▶ COMMITTING ──物理删除成功──▶ DESTROYED
                                  │  ▲
                                  │  └── 存储删除失败：停留 COMMITTING，由恢复/重启/重试续完
                                  └── 销毁令 + 已签名回执先落保留链（提交点）
```

- **提交点（COMMITTING）前**，所有读接口仍返回**完整旧报告**；**提交点后**（含 COMMITTING 与 DESTROYED），
  报告/时间线/冲突/导入历史/围栏/验签/导出/再导入**统一返回 `410 PACKAGE_DESTROYED` + 销毁状态**，
  不可能看到部分删除。
- **销毁物理覆盖四类物料**（删除整个 `packages/<id>/` 目录 + `rejected/` 中该包留底）：
  1. 业务索引（归档链重建的全部投影）；2. 链文件 `ledger/quarantine/audit`；
  3. 冲突材料（`quarantine.jsonl` 与 `rejected/` 原信封留底，只删本包、绝不跨包误删）；
  4. 凭据旁车 `retention-credential.json`（每包私钥与证据同生命周期销毁）。
  其他包目录与全局 `gateways.json / upload-secret.json / retention.jsonl` 不受影响。
- **中断可判态并续到唯一结果**：服务重启重放保留链即可区分「尚未开始 / COMMITTING / DESTROYED」；
  构造时自动把卡在 COMMITTING 的销毁继续到 DESTROYED。也可 `POST /api/retention/recover` 显式恢复。
  回执在 COMMITTING 时即已确定并签名，**重复执行 / 多次重试 / 重启都只返回同一份回执**，绝不产生第二份。
- **签名销毁回执（不含原始证据）**：`GET /api/packages/:id/destruction-receipt`。
  内容只有销毁事实（时间/操作人/触发方式）、保留策略、已解除保全、被销毁材料的**链尖与行数指纹**、
  保管公钥指纹；`evidenceIncluded:false`，**不含任何清单条目/设备/围栏/回执内容/密钥原文**。
  `GET /api/packages/:id/destruction-receipt/verify` 用每包保管公钥复算 Ed25519 签名，
  并校验回执哈希确已登记在保留链上（`signatureValid && registered`）。
- **到期任务**：`POST /api/retention/expiry-task` 扫描并销毁所有「已到期且无有效保全」的包；
  待销毁列表 `GET /api/retention/due`；全部保留状态 `GET /api/retention`。
  保全创建/解除与到期任务、立即销毁在单进程内严格串行裁决——先落盘的有效保全一定阻止销毁，不会误删。
- **存储删除失败演练**（仅 `EVIDENCE_DEMO=1`）：`POST /api/demo/fault/delete`
  `{mode:'fail-package'|'fail-all'|'off', packageId}` 注入物理删除故障，验证 COMMITTING 恢复。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/gateways` | 登记网关公钥（需 `X-Upload-Secret`；拒收私钥） |
| GET | `/api/gateways` | 已登记网关列表 |
| POST | `/api/packages/:id/import` | 导入证据信封（201 ACCEPTED / 200 CONFLICTS或DUPLICATE；拒绝 4xx；已销毁 410） |
| GET | `/api/packages` | 包列表（摘要/当前围栏/水位/冲突数 + 保留/保全/销毁状态与墓碑） |
| GET | `/api/packages/:id/report` | 完整脱敏报告（JSON；已销毁 410） |
| GET | `/api/packages/:id/report.{json,txt,html}` | 下载/预览脱敏报告（已销毁 410） |
| GET | `/api/packages/:id/timeline` | 确定性时间线（已销毁 410） |
| GET | `/api/packages/:id/conflicts` | 冲突隔离清单（已销毁 410） |
| GET | `/api/packages/:id/fences/:version` | 指定围栏证据（旧围栏标注"不充当进度"；已销毁 410） |
| GET | `/api/packages/:id/imports` | 导入裁决历史（已销毁 410） |
| GET | `/api/packages/:id/verify` | 三包哈希链校验（已销毁 410） |
| GET | `/api/chain/verify` | 全部包链校验 + 全局保留链校验 |
| POST | `/api/packages/:id/retention` | 运营设置保留期限（幂等；需 secret） |
| GET | `/api/packages/:id/retention` | 该包保留/保全/销毁状态（销毁后返回墓碑） |
| POST | `/api/packages/:id/holds` | 审计发起证据保全（案件号+原因；幂等；需 secret） |
| POST | `/api/packages/:id/holds/release` | 解除保全（holdId 或 caseNo；幂等/并发 409；需 secret） |
| POST | `/api/packages/:id/destroy` | 立即销毁（保留期已到且无有效保全；需 secret） |
| GET | `/api/packages/:id/destruction-receipt` | 签名销毁回执（不含原始证据；COMMITTING 时 409） |
| GET | `/api/packages/:id/destruction-receipt/verify` | 回执 Ed25519 验签 + 上链核对 |
| GET | `/api/retention` | 全部包保留/保全/销毁状态 |
| GET | `/api/retention/due` | 待销毁列表（已到期 + 无有效保全） |
| POST | `/api/retention/expiry-task` | 执行到期销毁任务（需 secret） |
| POST | `/api/retention/recover` | 恢复所有卡在 COMMITTING 的销毁到唯一结果（需 secret） |
| POST | `/api/demo/fault/delete` | 存储删除故障注入（仅 EVIDENCE_DEMO=1；需 secret） |
| POST | `/api/admin/restart` | 丢弃内存投影并从磁盘重放（等价进程重启，便于页面核对） |

环境变量：`EVIDENCE_PORT`（默认 8092）、`EVIDENCE_HOST`、`EVIDENCE_DIR`
（默认 `data/evidence`）、`EVIDENCE_UPLOAD_SECRET`、`EVIDENCE_DEMO=1`（开启本机密钥对演示接口）。

## 目录

```
evidence/
  hashing.js   规范化 JSON / 记录哈希 / 语义指纹 / 槽位 / 递归脱敏 / 安全日志字段
  crypto.js    Ed25519 验签、upload secret sidecar(0600)、网关公钥注册表、常量时间比较
  pack.js      网关侧制包 SDK（buildEnvelope/R.manifest/R.fence/...），供任意实现对照
  chains.js    通用 JSONL 哈希链（残尾恢复 / 损坏只读隔离）
  archive.js   归档内核：校验流水线、槽位去重/冲突、三链落账、ArchiveManager
  retention.js 保留期限/证据保全/两阶段可恢复销毁状态机（全局保留链 + 每包凭据旁车 + 签名回执）
  report.js    报告纯函数投影 + 确定性摘要 + JSON/TXT/HTML 脱敏渲染
  server.js    HTTP API + 网页 + 脱敏结构化日志
  demo.mjs     9 场景一键演示 / --print 输出示例信封
  public/      运营页面（index.html + app.js，含保留/保全/销毁面板）
scripts/evidence-e2e.mjs   88 项真实 HTTP 端到端断言（含真实进程重启）
scripts/retention-e2e.mjs  90 项保全/到期销毁真实 HTTP 断言（删除故障/COMMITTING 恢复/重启续完/回执验签）
test/evidence.test.js      22 个归档领域单测
test/retention.test.js     13 个保留/保全/销毁领域单测
```
