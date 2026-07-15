# Knowledge base changelog

## 1.0.0 - 2026-07-14

- 将原 Python 嵌套字典拆分为可审计的结构化 raw knowledge 和 JSON Schema。
- 引入稳定 `entry_id`，每条知识包含指标、条件、阈值、症状、根因、动作、严重度、来源与审核信息。
- 将 Python 进程随机 `hash()` 替换为 SHA-256 签名特征哈希，保证跨进程确定性。
- 当前数据规模采用版本化全量重建。`chunk_id={entry_id}::main` 保持稳定，`content_hash` 跟踪内容，为未来增量构建预留兼容键。
- 新增 staging、checksum manifest、golden-set 评测门禁、原子 current/previous 指针与 rollback。
- 迁移时如 schema/tokenizer/embedding/chunking 不兼容，从 raw snapshot 全量重建，不复制不可信的旧向量索引。

## Candidate review policy

DeepSeek 或其他模型只能产出 `knowledge/candidates/` 中的 draft。发布前必须由审核人确认来源、阈值和处置动作，将 `review_status` 置为 `approved`，并为每个新 `entry_id` 增加 golden case，再执行 promote。
