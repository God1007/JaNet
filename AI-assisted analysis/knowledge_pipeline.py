#!/usr/bin/env python3
"""
文件职责：管理结构化网络知识的校验、可复现向量化、评测、发布、回滚与迁移。

核心链路只依赖 Python 标准库；FAISS/jsonschema/LangChain 均是可选增强，
因此构建机和迁移目标机即使没有安装完整 AI 依赖也能执行校验、评测和回滚。
"""

import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import shutil
import sys
import unicodedata
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

import fcntl


MODULE_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = MODULE_DIR.parent
DEFAULT_KNOWLEDGE_ROOT = MODULE_DIR / "knowledge"
DEFAULT_RAW_PATH = DEFAULT_KNOWLEDGE_ROOT / "raw" / "network_knowledge.json"
DEFAULT_SCHEMA_PATH = DEFAULT_KNOWLEDGE_ROOT / "schema" / "knowledge_entry.schema.json"
DEFAULT_GOLDEN_PATH = DEFAULT_KNOWLEDGE_ROOT / "golden_set.json"
DEFAULT_ARTIFACT_ROOT = DEFAULT_KNOWLEDGE_ROOT / "artifacts"

PIPELINE_VERSION = "2.0.0"
MANIFEST_VERSION = "2.0.0"
TOKENIZER_VERSION = "weaknet-unicode-word-cjk-bigram-v1"
EMBEDDING_MODEL = "stable-feature-hash-sha256-v1"
CHUNKING_VERSION = "one-approved-entry-one-chunk-v2-source-anchored"
DEFAULT_DIMENSION = 384
DEFAULT_TOP_K = 4
DEFAULT_MIN_SCORE = 0.08

MINIMUM_EVALUATION_GATES = {
    "recall_at_4": 0.9,
    "mrr_at_4": 0.8,
    "citation_support_rate": 1.0,
    "diagnosis_accuracy": 0.85,
}
REQUIRED_GOLDEN_CASES = {
    "high-rtt": ("unhealthy", {"net.rtt.high"}),
    "tcp-retransmission": ("unhealthy", {"net.tcp.retransmission_elevated"}),
    "weak-wifi": ("unhealthy", {"net.wifi.rssi_weak"}),
    "interface-down": ("unhealthy", {"net.interface.down"}),
    "zero-traffic": ("unhealthy", {"net.traffic.zero"}),
    "ebpf-unavailable": ("degraded", {"net.ebpf.collector_unavailable"}),
    "multi-interface-default-route-switch": ("degraded", {"net.interface.default_route_switched"}),
    "healthy-normal-observation": ("healthy", set()),
}
REQUIRED_GOLDEN_RETRIEVAL = {
    case_id: ({"net.rtt.high"} if case_id == "healthy-normal-observation" else set(diagnosis_ids))
    for case_id, (_status, diagnosis_ids) in REQUIRED_GOLDEN_CASES.items()
}
REQUIRED_GOLDEN_INPUT_SHA256 = {
    "high-rtt": "f8e1f21bee437f5bdfe20064a50de0007bc6c25d0b8928b7e451c3f9ca56f746",
    "tcp-retransmission": "a96382d38374f2881fce3ec0544e9e8f42df4beff50614a05cf63925f86378f2",
    "weak-wifi": "3b3b4d662e6e05df5449ad1ccf1dd140ecd05cd8439eb27714ed75317c0bdd2e",
    "interface-down": "c6302ce488568141b1f66a2eb921353b2893d6d6e186ad04ff3e821615750d5f",
    "zero-traffic": "cc6b778f9614201fccf0f394db0aa5e057066b13e582059a72ef8dd9be8e290e",
    "ebpf-unavailable": "7cde8f2bff4fca5338526d015bf23f51a69007618fbe58da54790601101de60b",
    "multi-interface-default-route-switch": "30802187362c0ac368dff30592e353687c74573380e141e0add00101124fa852",
    "healthy-normal-observation": "e2882268640e64a47ca73bb9cc07235bc4d00d45478cec13db5bd30117ab4d48",
}

ENTRY_REQUIRED_FIELDS = (
    "entry_id",
    "metric",
    "condition",
    "threshold",
    "unit",
    "symptoms",
    "root_causes",
    "actions",
    "severity",
    "tags",
    "source",
    "source_revision",
    "source_anchor",
    "updated_at",
    "review_status",
    "reviewed_by",
    "reviewed_at",
    "reviewed_by_human",
)
SEVERITIES = {"info", "low", "medium", "high", "critical"}
THRESHOLD_OPERATORS = {"gt", "ge", "lt", "le", "eq", "between", "none"}
ENTRY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
IMMUTABLE_REVISION_RE = re.compile(r"^[0-9a-f]{7,64}$", re.IGNORECASE)
MODEL_REVIEWER_RE = re.compile(r"(?:deepseek|qwen|chatgpt|gpt|claude|gemini|llm|\bai\b)", re.IGNORECASE)
ASCII_OR_CJK_RE = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*|[\u3400-\u4dbf\u4e00-\u9fff]+")


class KnowledgeError(RuntimeError):
    """知识库闭环的基础异常。"""


class KnowledgeValidationError(KnowledgeError):
    """原始知识或候选知识不满足 schema/审核门禁。"""


class KnowledgeConflictError(KnowledgeValidationError):
    """同一稳定 ID 或同一触发条件存在互相矛盾的内容。"""


class EvaluationGateError(KnowledgeError):
    """黄金集指标低于发布门禁。"""


class ArtifactIntegrityError(KnowledgeError):
    """索引制品的 checksum、manifest 或指针已损坏。"""


class StaleSourceError(KnowledgeError):
    """原始知识已改变，当前索引不再对应源数据。"""


class IncompatibleArtifactError(KnowledgeError):
    """索引与当前 schema/tokenizer/embedding/chunking 不兼容。"""


def utc_now() -> str:
    """返回稳定的 UTC RFC3339 时间字符串。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    """使用固定键序和分隔符生成可复现的 JSON 字节。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """计算输入字节的 SHA-256 十六进制摘要。"""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """分块读取文件并返回 SHA-256，避免大制品一次性进入内存。"""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    """以 UTF-8 读取 JSON 文件并返回反序列化对象。"""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _fsync_directory(path: Path) -> None:
    """持久化 rename 所在目录；不支持目录 fsync 的平台安全跳过。"""
    try:
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        pass


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """先写同目录临时文件，fsync 后再 os.replace，避免读者看到半份指针。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.%s.tmp" % (path.name, uuid.uuid4().hex))
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_json(path: Path, value: Any) -> None:
    """将对象规范化为 JSON 后复用原子字节写入，避免半份 manifest/指针。"""
    atomic_write_bytes(path, canonical_json_bytes(value) + b"\n")


@contextmanager
def _artifact_lock(artifact_root: Path) -> Iterable[None]:
    """跨进程串行化 current/raw 的状态切换；进程崩溃时 flock 由内核自动释放。"""
    root = Path(artifact_root)
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".lifecycle.lock"
    with lock_path.open("a+b") as handle:
        # 锁覆盖整个 read-build-switch 序列；只锁单个写文件无法阻止两个发布者丢失 previous 指针。
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _package_version(name: str) -> str:
    """返回已安装包版本；可选依赖缺失时返回稳定哨兵值。"""
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _dependency_inventory() -> Dict[str, Any]:
    """把本次构建真实使用/检测到的版本写入 manifest，而不把 requirements 范围当成制品事实。"""
    dependencies = {
        "python": {
            "version": platform.python_version(),
            "role": "core-runtime",
            "runtime_required": True,
            "compatibility": "major.minor",
        },
        "packages": {
            "faiss-cpu": {
                "version": _package_version("faiss-cpu"),
                "role": "optional-compatible-index-artifact",
                "runtime_required": False,
            },
            "numpy": {
                "version": _package_version("numpy"),
                "role": "optional-faiss-build",
                "runtime_required": False,
            },
            "jsonschema": {
                "version": _package_version("jsonschema"),
                "role": "required-build-and-review-validation",
                "runtime_required": False,
            },
            "langchain": {
                "version": _package_version("langchain"),
                "role": "optional-legacy-integration",
                "runtime_required": False,
            },
            "langchain-community": {
                "version": _package_version("langchain-community"),
                "role": "optional-legacy-integration",
                "runtime_required": False,
            },
        },
    }
    runtime_identity = {
        "python_major_minor": ".".join(platform.python_version().split(".")[:2]),
        "packages": {
            name: descriptor["version"]
            for name, descriptor in dependencies["packages"].items()
            if descriptor.get("runtime_required") is True
        },
    }
    dependencies["runtime_fingerprint_sha256"] = sha256_bytes(canonical_json_bytes(runtime_identity))
    dependencies["fingerprint_sha256"] = sha256_bytes(canonical_json_bytes(dependencies))
    return dependencies


class StableTokenizer:
    """对 ASCII 单词与中文字/双字组做固定切分，不受进程随机种子影响。"""

    version = TOKENIZER_VERSION

    def tokenize(self, text: str) -> List[str]:
        """将文本规范化并返回带类型前缀的 ASCII/CJK 稳定 token。"""
        normalized = unicodedata.normalize("NFKC", str(text)).lower()
        tokens: List[str] = []
        for match in ASCII_OR_CJK_RE.finditer(normalized):
            part = match.group(0)
            if part.isascii():
                tokens.append("w:" + part)
                for segment in re.split(r"[._/-]+", part):
                    if segment and segment != part:
                        tokens.append("w:" + segment)
                continue
            characters = list(part)
            tokens.extend("c:" + character for character in characters)
            tokens.extend("b:" + characters[index] + characters[index + 1] for index in range(len(characters) - 1))
        return tokens

    def descriptor(self) -> Dict[str, Any]:
        """返回会影响 token 结果的算法描述，供 manifest 兼容性比较。"""
        return {
            "name": "unicode-normalized-ascii-word-and-cjk-bigram",
            "version": self.version,
            "unicode_normalization": "NFKC",
            "lowercase": True,
        }


class StableHashEmbeddings:
    """用 SHA-256 特征哈希生成本地稳定向量，代替跨进程随机的 Python ``hash()``。"""

    def __init__(self, dimension: int = DEFAULT_DIMENSION, tokenizer: Optional[StableTokenizer] = None):
        """初始化固定维度和 tokenizer；维度必须为正数。"""
        if dimension <= 0:
            raise ValueError("embedding dimension must be positive")
        self.dimension = dimension
        self.tokenizer = tokenizer or StableTokenizer()

    def embed_query(self, text: str) -> List[float]:
        """把单段文本映射为确定性的 L2 归一化特征哈希向量。"""
        counts = Counter(self.tokenizer.tokenize(text))
        vector = [0.0] * self.dimension
        for token, count in counts.items():
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:8], "big") % self.dimension
            sign = 1.0 if digest[8] & 1 else -1.0
            vector[bucket] += sign * (1.0 + math.log(float(count)))
        norm = math.sqrt(sum(value * value for value in vector))
        if norm:
            vector = [value / norm for value in vector]
        return vector

    def embed_documents(self, texts: Sequence[str]) -> List[List[float]]:
        """批量向量化文档，保持输入顺序并返回二维向量列表。"""
        return [self.embed_query(text) for text in texts]

    def __call__(self, texts: Any) -> Any:
        """兼容 embedding callable：字符串返回单向量，序列返回向量矩阵。"""
        return self.embed_query(texts) if isinstance(texts, str) else self.embed_documents(texts)

    def descriptor(self) -> Dict[str, Any]:
        """返回 embedding 算法、维度、加权和归一化描述。"""
        return {
            "provider": "builtin",
            "model": EMBEDDING_MODEL,
            "dimension": self.dimension,
            "hash": "sha256",
            "weighting": "signed-log-tf",
            "normalization": "l2",
        }


def _parse_rfc3339(value: str, field_name: str) -> None:
    """校验字段为 RFC3339 时间；失败时抛带字段名的知识校验异常。"""
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise KnowledgeValidationError("%s must be RFC3339: %r" % (field_name, value)) from error


def _validate_threshold(threshold: Any, entry_id: str) -> None:
    """校验知识阈值对象、操作符及 between 上界的完整性。"""
    if not isinstance(threshold, dict):
        raise KnowledgeValidationError("%s threshold must be an object" % entry_id)
    operator = threshold.get("operator")
    if operator not in THRESHOLD_OPERATORS:
        raise KnowledgeValidationError("%s has unsupported threshold operator %r" % (entry_id, operator))
    if "value" not in threshold:
        raise KnowledgeValidationError("%s threshold.value is required" % entry_id)
    if operator == "between" and "max_value" not in threshold:
        raise KnowledgeValidationError("%s between threshold requires max_value" % entry_id)


def _approved_reviewer_allowlist() -> set[str]:
    """审批人必须来自显式白名单；模型名不能伪装成人工审核人。"""
    configured = os.getenv("RAG_APPROVED_REVIEWERS", "weaknet-maintainer")
    return {item.strip() for item in configured.split(",") if item.strip()}


def _normalized_claim(value: Any) -> str:
    """统一大小写和空白，返回适合来源文本包含比较的声明字符串。"""
    return " ".join(str(value).strip().lower().split())


def _threshold_claim(entry: Dict[str, Any]) -> str:
    """将知识条目的 metric/threshold/unit 渲染为可在来源片段验证的声明。"""
    threshold = entry["threshold"]
    claim = "metric=%s; threshold=%s %s" % (
        entry["metric"], threshold["operator"], threshold.get("value")
    )
    if "max_value" in threshold:
        claim += " %s" % threshold["max_value"]
    return "%s %s" % (claim, entry["unit"])


SEMANTIC_SOURCE_FIELDS = ("condition", "symptoms", "root_causes", "actions")


def _entry_semantic_sha256(entry: Dict[str, Any]) -> Dict[str, str]:
    """把会影响诊断解释/动作的字段规范化后摘要，绑定到人工审核源片段。"""
    result: Dict[str, str] = {}
    for field in SEMANTIC_SOURCE_FIELDS:
        value = entry.get(field)
        normalized: Any
        if isinstance(value, list):
            normalized = [_normalized_claim(item) for item in value]
        else:
            normalized = _normalized_claim(value)
        result[field] = sha256_bytes(canonical_json_bytes(normalized))
    return result


def _validate_source_anchor_shape(entry: Dict[str, Any]) -> Dict[str, Any]:
    """不访问源码树，仅校验 source_anchor 的可移植结构。"""
    anchor = entry.get("source_anchor")
    if not isinstance(anchor, dict):
        raise KnowledgeValidationError("%s.source_anchor must be an object" % entry["entry_id"])
    required = {
        "symbol", "line_start", "line_end", "claim", "excerpt_sha256", "semantic_sha256"
    }
    if set(anchor) != required:
        raise KnowledgeValidationError(
            "%s.source_anchor requires exactly: %s"
            % (entry["entry_id"], ", ".join(sorted(required)))
        )
    start = anchor["line_start"]
    end = anchor["line_end"]
    if not isinstance(start, int) or not isinstance(end, int) or start <= 0 or end < start:
        raise KnowledgeValidationError("%s source anchor has invalid line range" % entry["entry_id"])
    for field in ("symbol", "claim"):
        if not isinstance(anchor[field], str) or not anchor[field].strip():
            raise KnowledgeValidationError(
                "%s source anchor %s must be non-empty" % (entry["entry_id"], field)
            )
    if not re.fullmatch(r"[0-9a-f]{64}", str(anchor["excerpt_sha256"])):
        raise KnowledgeValidationError("%s source excerpt checksum is invalid" % entry["entry_id"])
    semantic = anchor["semantic_sha256"]
    if not isinstance(semantic, dict) or set(semantic) != set(SEMANTIC_SOURCE_FIELDS):
        raise KnowledgeValidationError(
            "%s source semantic checksum fields are invalid" % entry["entry_id"]
        )
    if not all(re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in semantic.values()):
        raise KnowledgeValidationError(
            "%s source semantic checksum is invalid" % entry["entry_id"]
        )
    return anchor


def _validated_local_source_anchor(entry: Dict[str, Any], source_path: Path) -> Dict[str, Any]:
    """验证行范围、片段摘要、阈值及诊断语义都来自被引用文件。"""
    anchor = _validate_source_anchor_shape(entry)
    start = anchor["line_start"]
    end = anchor["line_end"]
    lines = source_path.read_bytes().splitlines(keepends=True)
    if end > len(lines):
        raise KnowledgeValidationError("%s source anchor exceeds file length" % entry["entry_id"])
    excerpt_bytes = b"".join(lines[start - 1:end])
    excerpt_sha = sha256_bytes(excerpt_bytes)
    if excerpt_sha != anchor["excerpt_sha256"]:
        raise KnowledgeValidationError("%s source excerpt checksum mismatch" % entry["entry_id"])
    excerpt = excerpt_bytes.decode("utf-8")
    if _normalized_claim(anchor["claim"]) not in _normalized_claim(excerpt):
        raise KnowledgeValidationError("%s source claim is absent from anchored excerpt" % entry["entry_id"])
    if _normalized_claim(_threshold_claim(entry)) not in _normalized_claim(excerpt):
        raise KnowledgeValidationError(
            "%s metric/threshold/unit are not supported by anchored source" % entry["entry_id"]
        )
    semantic_sha = _entry_semantic_sha256(entry)
    if anchor["semantic_sha256"] != semantic_sha:
        raise KnowledgeValidationError(
            "%s condition/symptoms/root_causes/actions differ from reviewed source semantics"
            % entry["entry_id"]
        )
    normalized_excerpt = _normalized_claim(excerpt)
    for field, digest in semantic_sha.items():
        if "%s=%s" % (field, digest) not in normalized_excerpt:
            raise KnowledgeValidationError(
                "%s source excerpt does not bind reviewed %s semantics" % (entry["entry_id"], field)
            )
        values = entry[field] if isinstance(entry[field], list) else [entry[field]]
        for value in values:
            if _normalized_claim(value) not in normalized_excerpt:
                raise KnowledgeValidationError(
                    "%s source excerpt does not contain readable reviewed %s text: %s"
                    % (entry["entry_id"], field, value)
                )
    symbol = str(anchor["symbol"])
    start_marker = "<!-- weaknet-anchor:%s:start -->" % symbol
    end_marker = "<!-- weaknet-anchor:%s:end -->" % symbol
    if start < 2 or lines[start - 2].decode("utf-8").strip() != start_marker:
        raise KnowledgeValidationError("%s source anchor start marker mismatch" % entry["entry_id"])
    if end >= len(lines) or lines[end].decode("utf-8").strip() != end_marker:
        raise KnowledgeValidationError("%s source anchor end marker mismatch" % entry["entry_id"])
    return {
        "symbol": symbol,
        "line_start": start,
        "line_end": end,
        "claim": anchor["claim"],
        "excerpt_sha256": excerpt_sha,
        "semantic_sha256": semantic_sha,
        "excerpt": excerpt,
    }


def _source_provenance(entry: Dict[str, Any]) -> Dict[str, Any]:
    """验证引用源真实可追溯，并返回写入 chunk 的不可伪造 provenance。"""
    source = str(entry["source"]).strip()
    revision = str(entry["source_revision"]).strip()
    parsed = urlparse(source)
    if parsed.scheme:
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise KnowledgeValidationError(
                "%s.source must be a repository-relative file or HTTPS URI" % entry["entry_id"]
            )
        anchor = "%s?%s#%s" % (parsed.path, parsed.query, parsed.fragment)
        normalized_revision = revision.lower()
        immutable_commit = bool(
            IMMUTABLE_REVISION_RE.fullmatch(revision)
            and normalized_revision in anchor.lower()
        )
        immutable_digest = False
        if normalized_revision.startswith("sha256:"):
            digest = normalized_revision.split(":", 1)[1]
            immutable_digest = bool(
                re.fullmatch(r"[0-9a-f]{64}", digest)
                and digest in anchor.lower()
            )
        if not immutable_commit and not immutable_digest:
            raise KnowledgeValidationError(
                "%s HTTPS source requires an immutable commit or sha256 anchor in the URI"
                % entry["entry_id"]
            )
        raise KnowledgeValidationError(
            "%s external source cannot satisfy offline excerpt verification" % entry["entry_id"]
        )

    if Path(source).is_absolute():
        raise KnowledgeValidationError("%s.source must be repository-relative" % entry["entry_id"])
    repository_root = REPOSITORY_ROOT.resolve()
    source_path = (repository_root / source).resolve()
    try:
        relative = source_path.relative_to(repository_root)
    except ValueError as error:
        raise KnowledgeValidationError("%s.source escapes the repository" % entry["entry_id"]) from error
    if not source_path.is_file():
        raise KnowledgeValidationError(
            "%s.source does not exist as a local file: %s" % (entry["entry_id"], source)
        )
    file_sha = sha256_file(source_path)
    if revision.lower() != "sha256:%s" % file_sha:
        raise KnowledgeValidationError(
            "%s.source_revision must equal sha256 of the cited local file" % entry["entry_id"]
        )
    anchor = _validated_local_source_anchor(entry, source_path)
    return {
        "verified": True,
        "kind": "local_file",
        "path": relative.as_posix(),
        "revision": revision,
        "sha256": file_sha,
        "anchor": {key: value for key, value in anchor.items() if key != "excerpt"},
        "excerpt": anchor["excerpt"],
    }


def validate_knowledge_document(document: Any, schema_path: Path = DEFAULT_SCHEMA_PATH,
                                require_approved: bool = True,
                                require_jsonschema: bool = True,
                                validate_live_sources: bool = True) -> Dict[str, Any]:
    """先尝试 jsonschema 完整校验，再始终执行无依赖的核心不变量校验。"""
    if not isinstance(document, dict):
        raise KnowledgeValidationError("knowledge document must be an object")
    for field in ("schema_version", "kb_version", "entries"):
        if field not in document:
            raise KnowledgeValidationError("knowledge document missing %s" % field)
    if not isinstance(document["entries"], list) or not document["entries"]:
        raise KnowledgeValidationError("knowledge entries must be a non-empty array")

    if schema_path.exists() and require_jsonschema:
        try:
            import jsonschema  # type: ignore

            jsonschema.validate(instance=document, schema=read_json(schema_path))
        except ImportError as error:
            raise KnowledgeValidationError(
                "jsonschema is required for knowledge build/review validation"
            ) from error
        except Exception as error:
            raise KnowledgeValidationError("JSON Schema validation failed: %s" % error) from error

    for index, entry in enumerate(document["entries"]):
        if not isinstance(entry, dict):
            raise KnowledgeValidationError("entries[%d] must be an object" % index)
        missing = [field for field in ENTRY_REQUIRED_FIELDS if field not in entry]
        if missing:
            raise KnowledgeValidationError("entries[%d] missing fields: %s" % (index, ", ".join(missing)))
        entry_id = entry["entry_id"]
        if not isinstance(entry_id, str) or not ENTRY_ID_RE.match(entry_id):
            raise KnowledgeValidationError("invalid stable entry_id: %r" % entry_id)
        for field in ("metric", "condition", "unit", "source", "source_revision"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise KnowledgeValidationError("%s.%s must be a non-empty string" % (entry_id, field))
        for field in ("symptoms", "root_causes", "actions", "tags"):
            value = entry[field]
            if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
                raise KnowledgeValidationError("%s.%s must be a non-empty string array" % (entry_id, field))
            if len(set(value)) != len(value):
                raise KnowledgeValidationError("%s.%s contains duplicates" % (entry_id, field))
        if entry["severity"] not in SEVERITIES:
            raise KnowledgeValidationError("%s has invalid severity %r" % (entry_id, entry["severity"]))
        _validate_threshold(entry["threshold"], entry_id)
        _parse_rfc3339(entry["updated_at"], entry_id + ".updated_at")
        if entry["review_status"] not in {"draft", "approved", "rejected"}:
            raise KnowledgeValidationError("%s has invalid review_status" % entry_id)
        if not isinstance(entry["reviewed_by_human"], bool):
            raise KnowledgeValidationError("%s.reviewed_by_human must be boolean" % entry_id)
        if require_approved and entry["review_status"] != "approved":
            raise KnowledgeValidationError("%s is not approved; candidate review gate rejected it" % entry_id)
        if entry["review_status"] == "approved":
            if not entry["reviewed_by"]:
                raise KnowledgeValidationError("%s approved entry requires reviewed_by" % entry_id)
            reviewer = str(entry["reviewed_by"]).strip()
            if not entry["reviewed_by_human"]:
                raise KnowledgeValidationError("%s approved entry requires explicit human review" % entry_id)
            if MODEL_REVIEWER_RE.search(reviewer) or reviewer not in _approved_reviewer_allowlist():
                raise KnowledgeValidationError(
                    "%s reviewer %r is not an approved human maintainer" % (entry_id, reviewer)
                )
            _parse_rfc3339(entry["reviewed_at"], entry_id + ".reviewed_at")
        _validate_source_anchor_shape(entry)
        if validate_live_sources:
            _source_provenance(entry)

    deduplicate_entries(document["entries"])
    return document


def _trigger_signature(entry: Dict[str, Any]) -> Tuple[str, str]:
    """返回 metric+condition 的规范化触发签名，用于发现跨 ID 冲突。"""
    return (
        entry["metric"].strip().lower(),
        " ".join(entry["condition"].lower().split()),
    )


def deduplicate_entries(entries: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """完全相同的重复项只保留一份；稳定 ID 或触发签名同而内容不同则拒绝构建。"""
    by_id: Dict[str, Dict[str, Any]] = {}
    by_trigger: Dict[Tuple[str, str], Dict[str, Any]] = {}
    duplicates = 0
    for entry in entries:
        entry_id = entry["entry_id"]
        if entry_id in by_id:
            if canonical_json_bytes(by_id[entry_id]) == canonical_json_bytes(entry):
                duplicates += 1
                continue
            raise KnowledgeConflictError("conflicting content for entry_id %s" % entry_id)
        trigger = _trigger_signature(entry)
        if trigger in by_trigger and by_trigger[trigger]["entry_id"] != entry_id:
            previous = by_trigger[trigger]
            if previous["unit"].strip().lower() != entry["unit"].strip().lower():
                raise KnowledgeConflictError(
                    "entries %s and %s use conflicting units for the same metric/condition"
                    % (previous["entry_id"], entry_id)
                )
            if canonical_json_bytes(previous["threshold"]) != canonical_json_bytes(entry["threshold"]):
                raise KnowledgeConflictError(
                    "entries %s and %s use conflicting thresholds for the same metric/condition/unit"
                    % (previous["entry_id"], entry_id)
                )
            raise KnowledgeConflictError(
                "entries %s and %s describe the same trigger with different IDs"
                % (by_trigger[trigger]["entry_id"], entry_id)
            )
        by_id[entry_id] = entry
        by_trigger[trigger] = entry
    return [by_id[key] for key in sorted(by_id)], duplicates


def merge_approved_documents(base: Dict[str, Any], candidates: Sequence[Dict[str, Any]],
                             kb_version: Optional[str] = None,
                             schema_path: Path = DEFAULT_SCHEMA_PATH) -> Dict[str, Any]:
    """把已审核候选项合并到 raw snapshot，同时做去重和冲突检测。"""
    validate_knowledge_document(base, schema_path, require_approved=True)
    merged = list(base["entries"])
    for candidate in candidates:
        validate_knowledge_document(candidate, schema_path, require_approved=True)
        merged.extend(candidate["entries"])
    unique, duplicate_count = deduplicate_entries(merged)
    return {
        "schema_version": base["schema_version"],
        "kb_version": kb_version or base["kb_version"],
        "description": base.get("description", "WeakNet structured diagnostic knowledge"),
        "entries": unique,
        "merge_metadata": {"deduplicated_entries": duplicate_count},
    }


def render_entry(entry: Dict[str, Any]) -> str:
    """用固定字段顺序渲染检索文本，避免 dict 遍历差异影响向量。"""
    threshold = entry["threshold"]
    threshold_text = "%s %s" % (threshold["operator"], threshold.get("value"))
    if "max_value" in threshold:
        threshold_text += " to %s" % threshold["max_value"]
    return "\n".join(
        [
            "entry_id: " + entry["entry_id"],
            "metric: " + entry["metric"],
            "condition: " + entry["condition"],
            "threshold: " + threshold_text + " " + entry["unit"],
            "severity: " + entry["severity"],
            "symptoms: " + "；".join(entry["symptoms"]),
            "root_causes: " + "；".join(entry["root_causes"]),
            "actions: " + "；".join(entry["actions"]),
            "tags: " + " ".join(entry["tags"]),
            "source: %s@%s" % (entry["source"], entry["source_revision"]),
        ]
    )


def _provenance_supports_entry(entry: Dict[str, Any], provenance: Any,
                               require_live_source: bool) -> bool:
    """证明 provenance excerpt 同时支持阈值、可读诊断语义和语义摘要。"""
    verifier = _provenance_is_current if require_live_source else _provenance_is_self_consistent
    if not verifier(provenance):
        return False
    excerpt = _normalized_claim(provenance.get("excerpt", ""))
    anchor = provenance.get("anchor", {})
    semantic_sha = _entry_semantic_sha256(entry)
    if anchor.get("semantic_sha256") != semantic_sha:
        return False
    if _normalized_claim(_threshold_claim(entry)) not in excerpt:
        return False
    return all(
        _normalized_claim(value) in excerpt
        for field in SEMANTIC_SOURCE_FIELDS
        for value in (entry[field] if isinstance(entry[field], list) else [entry[field]])
    )


def build_chunks(entries: Sequence[Dict[str, Any]],
                 provenance_by_entry_id: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """当前规模每条知识一个块；chunk_id 不随文案改变，content_hash 精确跟踪内容。"""
    chunks: List[Dict[str, Any]] = []
    for entry in entries:
        content = render_entry(entry)
        if provenance_by_entry_id is None:
            provenance = _source_provenance(entry)
        else:
            provenance = provenance_by_entry_id.get(entry["entry_id"])
            if not _provenance_supports_entry(entry, provenance, require_live_source=False):
                raise ArtifactIntegrityError(
                    "bundled provenance does not support entry %s" % entry["entry_id"]
                )
        chunks.append(
            {
                "chunk_id": entry["entry_id"] + "::main",
                "entry_id": entry["entry_id"],
                "content_hash": sha256_bytes(content.encode("utf-8")),
                "content": content,
                "metadata": {
                    "metric": entry["metric"],
                    "condition": entry["condition"],
                    "threshold": entry["threshold"],
                    "unit": entry["unit"],
                    "severity": entry["severity"],
                    "actions": entry["actions"],
                    "semantic_sha256": _entry_semantic_sha256(entry),
                    "tags": entry["tags"],
                    "source": entry["source"],
                    "source_revision": entry["source_revision"],
                    "source_provenance": provenance,
                },
            }
        )
    return chunks


def _dot(left: Sequence[float], right: Sequence[float]) -> float:
    """计算两个等维归一化向量的点积，即当前检索使用的余弦相似度。"""
    return sum(a * b for a, b in zip(left, right))


@dataclass(frozen=True)
class Evidence:
    """一条通过分数门禁的不可变检索证据及其来源元数据。"""

    entry_id: str
    chunk_id: str
    content_hash: str
    score: float
    content: str
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class RetrievalResult:
    """一次检索的参数、制品版本、证据列表和证据不足标志。"""

    query: str
    top_k: int
    similarity_threshold: float
    artifact_version: str
    evidence: List[Evidence]
    insufficient_evidence: bool

    def to_dict(self) -> Dict[str, Any]:
        """将不可变结果和 Evidence 转成可直接 JSON 序列化的字典。"""
        return {
            "query": self.query,
            "top_k": self.top_k,
            "similarity_threshold": self.similarity_threshold,
            "artifact_version": self.artifact_version,
            "evidence": [asdict(item) for item in self.evidence],
            "insufficient_evidence": self.insufficient_evidence,
        }


def retrieve_from_vectors(query: str, chunks: Sequence[Dict[str, Any]], vectors: Sequence[Sequence[float]],
                          embeddings: StableHashEmbeddings, top_k: int,
                          min_score: float, artifact_version: str) -> RetrievalResult:
    """向量化查询、稳定排序并返回满足相似度阈值的前 ``top_k`` 条证据。"""
    if top_k <= 0:
        raise ValueError("top_k must be positive")
    query_vector = embeddings.embed_query(query)
    ranked = sorted(
        ((_dot(query_vector, vector), chunk) for chunk, vector in zip(chunks, vectors)),
        key=lambda item: (-item[0], item[1]["chunk_id"]),
    )
    # min_score 是证据可信门禁而非排序参数：低分项即使排进前 K 也不能进入诊断引用。
    evidence = [
        Evidence(
            entry_id=chunk["entry_id"],
            chunk_id=chunk["chunk_id"],
            content_hash=chunk["content_hash"],
            score=round(float(score), 8),
            content=chunk["content"],
            metadata=chunk["metadata"],
        )
        for score, chunk in ranked
        if score >= min_score
    ][:top_k]
    return RetrievalResult(
        query=query,
        top_k=top_k,
        similarity_threshold=min_score,
        artifact_version=artifact_version,
        evidence=evidence,
        insufficient_evidence=not evidence,
    )


class _VectorKnowledgeStore:
    """构建期内存 store；与发布后 VersionedKnowledgeStore 复用同一诊断函数。"""

    def __init__(self, chunks: Sequence[Dict[str, Any]], vectors: Sequence[Sequence[float]],
                 embeddings: StableHashEmbeddings, artifact_version: str):
        """复制构建期 chunk/vector，并绑定生成它们的 embedding 与制品版本。"""
        self.chunks = list(chunks)
        self.vectors = [list(vector) for vector in vectors]
        self.embeddings = embeddings
        self.artifact_version = artifact_version

    def retrieve(self, query: str, top_k: Optional[int] = None,
                 similarity_threshold: Optional[float] = None) -> RetrievalResult:
        """按显式参数或默认门禁检索，并返回带制品版本的结果。"""
        return retrieve_from_vectors(
            query,
            self.chunks,
            self.vectors,
            self.embeddings,
            top_k if top_k is not None else DEFAULT_TOP_K,
            similarity_threshold if similarity_threshold is not None else DEFAULT_MIN_SCORE,
            self.artifact_version,
        )


def _provenance_is_self_consistent(provenance: Any) -> bool:
    """无需源码树即可验证 artifact 内固化的 excerpt、revision 与 anchor 结构。"""
    if not isinstance(provenance, dict) or provenance.get("verified") is not True:
        return False
    if provenance.get("kind") == "local_file":
        anchor = provenance.get("anchor")
        excerpt = provenance.get("excerpt")
        if not isinstance(anchor, dict) or not isinstance(excerpt, str):
            return False
        if sha256_bytes(excerpt.encode("utf-8")) != anchor.get("excerpt_sha256"):
            return False
        if _normalized_claim(anchor.get("claim")) not in _normalized_claim(excerpt):
            return False
        semantic_sha = anchor.get("semantic_sha256")
        if not isinstance(semantic_sha, dict) or set(semantic_sha) != set(SEMANTIC_SOURCE_FIELDS):
            return False
        normalized_excerpt = _normalized_claim(excerpt)
        if not all(
            re.fullmatch(r"[0-9a-f]{64}", str(digest))
            and "%s=%s" % (field, digest) in normalized_excerpt
            for field, digest in semantic_sha.items()
        ):
            return False
        return provenance.get("revision") == "sha256:%s" % provenance.get("sha256")
    return False


def _provenance_is_current(provenance: Any) -> bool:
    """在完整源码树中进一步比较 live 文件、行范围和 whole-file SHA。"""
    if not _provenance_is_self_consistent(provenance):
        return False
    if provenance.get("kind") == "local_file":
        path = (REPOSITORY_ROOT / str(provenance.get("path", ""))).resolve()
        try:
            path.relative_to(REPOSITORY_ROOT.resolve())
        except ValueError:
            return False
        if not path.is_file() or sha256_file(path) != provenance.get("sha256"):
            return False
        anchor = provenance["anchor"]
        lines = path.read_bytes().splitlines(keepends=True)
        start = anchor.get("line_start")
        end = anchor.get("line_end")
        if not isinstance(start, int) or not isinstance(end, int) or end > len(lines):
            return False
        return b"".join(lines[start - 1:end]).decode("utf-8") == provenance.get("excerpt")
    return False


def _citation_has_verified_source(item: Dict[str, Any], chunk: Dict[str, Any]) -> bool:
    """引用必须来自本次诊断 evidence，且源文件摘要仍与构建时一致。"""
    if item.get("chunk_id") != chunk.get("chunk_id"):
        return False
    if item.get("content_hash") != chunk.get("content_hash"):
        return False
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    provenance = metadata.get("source_provenance")
    anchor = provenance.get("anchor") if isinstance(provenance, dict) else {}
    return (
        metadata.get("semantic_sha256") == anchor.get("semantic_sha256")
        and _provenance_is_current(provenance)
    )


def _citation_has_bundled_source(item: Dict[str, Any], chunk: Dict[str, Any]) -> bool:
    """artifact-only 迁移评测使用已被源 artifact checksum 固化的自包含 provenance。"""
    if item.get("chunk_id") != chunk.get("chunk_id"):
        return False
    if item.get("content_hash") != chunk.get("content_hash"):
        return False
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    provenance = metadata.get("source_provenance")
    anchor = provenance.get("anchor") if isinstance(provenance, dict) else {}
    return (
        metadata.get("semantic_sha256") == anchor.get("semantic_sha256")
        and _provenance_is_self_consistent(provenance)
    )


def evaluate_golden_set(golden: Dict[str, Any], chunks: Sequence[Dict[str, Any]],
                        vectors: Sequence[Sequence[float]], embeddings: StableHashEmbeddings,
                        artifact_version: str, enforce_release_contract: bool = True,
                        require_live_sources: bool = True) -> Dict[str, Any]:
    """计算 Recall@4、MRR@4、引用支持率和确定性诊断正确率，并生成发布门禁结论。"""
    cases = golden.get("cases", [])
    if not cases:
        raise KnowledgeValidationError("golden set must contain at least one case")
    top_k = int(golden.get("top_k", 4))
    if top_k != 4:
        raise KnowledgeValidationError("golden set top_k must be 4 so Recall@4/MRR@4 remain comparable")
    gates = golden.get("gates")
    if not isinstance(gates, dict):
        raise KnowledgeValidationError("golden set requires explicit immutable-minimum gates")
    for name, minimum in MINIMUM_EVALUATION_GATES.items():
        if name not in gates or float(gates[name]) < minimum:
            raise KnowledgeValidationError(
                "golden gate %s cannot be missing or lower than %.2f" % (name, minimum)
            )
    case_ids = [str(case.get("case_id", "")) for case in cases if isinstance(case, dict)]
    if len(case_ids) != len(set(case_ids)):
        raise KnowledgeValidationError("golden case_id values must be unique")
    if enforce_release_contract:
        by_case_id = {str(case.get("case_id")): case for case in cases if isinstance(case, dict)}
        missing = sorted(set(REQUIRED_GOLDEN_CASES) - set(by_case_id))
        if missing:
            raise KnowledgeValidationError("golden release contract missing cases: %s" % ", ".join(missing))
        for case_id, (expected_status, expected_ids) in REQUIRED_GOLDEN_CASES.items():
            case = by_case_id[case_id]
            input_sha = sha256_bytes(canonical_json_bytes({
                "query": case.get("query"),
                "snapshot": case.get("snapshot"),
            }))
            if input_sha != REQUIRED_GOLDEN_INPUT_SHA256[case_id]:
                raise KnowledgeValidationError(
                    "golden case %s changed immutable query/typed-snapshot input" % case_id
                )
            if case.get("expected_status") != expected_status:
                raise KnowledgeValidationError("golden case %s changed required status" % case_id)
            if set(case.get("expected_diagnosis_entry_ids", [])) != expected_ids:
                raise KnowledgeValidationError("golden case %s changed required diagnosis IDs" % case_id)
            if set(case.get("expected_evidence_entry_ids", [])) != expected_ids:
                raise KnowledgeValidationError("golden case %s changed required evidence IDs" % case_id)
            if set(case.get("expected_entry_ids", [])) != REQUIRED_GOLDEN_RETRIEVAL[case_id]:
                raise KnowledgeValidationError("golden case %s changed required retrieval IDs" % case_id)
    min_score = float(golden.get("min_score", DEFAULT_MIN_SCORE))
    recalls: List[float] = []
    reciprocal_ranks: List[float] = []
    citation_support: List[float] = []
    diagnosis_correct: List[float] = []
    case_results: List[Dict[str, Any]] = []
    required_case_failures: Dict[str, Dict[str, Any]] = {}
    chunk_by_id = {chunk["chunk_id"]: chunk for chunk in chunks}
    store = _VectorKnowledgeStore(chunks, vectors, embeddings, artifact_version)

    for case in cases:
        result = retrieve_from_vectors(
            case["query"], chunks, vectors, embeddings, top_k, min_score, artifact_version
        )
        retrieved_ids = [item.entry_id for item in result.evidence]
        expected = list(case["expected_entry_ids"])
        snapshot = case.get("snapshot")
        if not isinstance(snapshot, dict) or not snapshot:
            raise KnowledgeValidationError("golden case %s requires a typed snapshot" % case.get("case_id"))
        if "expected_status" not in case:
            raise KnowledgeValidationError("golden case %s requires expected_status" % case.get("case_id"))
        expected_diagnosis = list(case.get("expected_diagnosis_entry_ids", []))
        expected_evidence = set(case.get("expected_evidence_entry_ids", expected_diagnosis))
        recall = len(set(retrieved_ids) & set(expected)) / float(len(set(expected)))
        rank = next((index + 1 for index, entry_id in enumerate(retrieved_ids) if entry_id in expected), 0)
        reciprocal_rank = 1.0 / rank if rank else 0.0
        diagnosis = _diagnose_snapshot_with_store(
            snapshot,
            store,
            top_k=max(top_k, len(chunks)),
            min_score=min_score,
        )
        diagnosis_evidence = [item for item in diagnosis.get("evidence", []) if isinstance(item, dict)]
        valid_supporting_citations = {
            str(item.get("entry_id"))
            for item in diagnosis_evidence
            if str(item.get("entry_id")) in expected_evidence
            and item.get("chunk_id") in chunk_by_id
            and (
                _citation_has_verified_source(item, chunk_by_id[item["chunk_id"]])
                if require_live_sources
                else _citation_has_bundled_source(item, chunk_by_id[item["chunk_id"]])
            )
        }
        # 健康 case 不应伪造知识引用；空期望且空 evidence 才算完全满足。
        citation_ratio = (
            len(valid_supporting_citations) / float(len(expected_evidence))
            if expected_evidence
            else (1.0 if not diagnosis_evidence else 0.0)
        )
        actual_diagnosis_ids = list(diagnosis.get("knowledge_entry_ids", []))
        correct = (
            diagnosis.get("status") == case["expected_status"]
            and set(actual_diagnosis_ids) == set(expected_diagnosis)
        )
        if enforce_release_contract and case["case_id"] in REQUIRED_GOLDEN_CASES \
                and (not correct or citation_ratio < 1.0 or recall < 1.0 or rank == 0):
            required_case_failures[case["case_id"]] = {
                "diagnosis_correct": correct,
                "citation_support_ratio": round(citation_ratio, 6),
                "recall_at_4": round(recall, 6),
                "rank_at_4": rank,
                "actual_status": diagnosis.get("status"),
                "actual_diagnosis_entry_ids": actual_diagnosis_ids,
            }
        recalls.append(recall)
        reciprocal_ranks.append(reciprocal_rank)
        citation_support.append(citation_ratio)
        diagnosis_correct.append(1.0 if correct else 0.0)
        case_results.append(
            {
                "case_id": case["case_id"],
                "input_sha256": sha256_bytes(canonical_json_bytes({
                    "query": case["query"], "snapshot": case["snapshot"]
                })),
                "retrieved_entry_ids": retrieved_ids,
                "expected_entry_ids": expected,
                "recall_at_4": round(recall, 6),
                "reciprocal_rank_at_4": round(reciprocal_rank, 6),
                "expected_status": case["expected_status"],
                "actual_status": diagnosis.get("status"),
                "expected_diagnosis_entry_ids": expected_diagnosis,
                "actual_diagnosis_entry_ids": actual_diagnosis_ids,
                "expected_evidence_entry_ids": sorted(expected_evidence),
                "valid_supporting_citation_ids": sorted(valid_supporting_citations),
                "citation_support_ratio": round(citation_ratio, 6),
                "diagnosis_correct": correct,
            }
        )

    metrics = {
        "recall_at_4": round(sum(recalls) / len(recalls), 6),
        "mrr_at_4": round(sum(reciprocal_ranks) / len(reciprocal_ranks), 6),
        "citation_support_rate": round(sum(citation_support) / len(citation_support), 6),
        "diagnosis_accuracy": round(sum(diagnosis_correct) / len(diagnosis_correct), 6),
    }
    failures = {
        name: {"actual": metrics.get(name, 0.0), "required": float(required)}
        for name, required in gates.items()
        if metrics.get(name, 0.0) < float(required)
    }
    if required_case_failures:
        failures["required_cases"] = required_case_failures
    return {
        "evaluation_version": "2.0.0",
        "metric_definitions": {
            "recall_at_4": "mean fraction of expected_entry_ids retrieved in the first four results",
            "mrr_at_4": "mean reciprocal rank of the first expected entry in the first four results",
            "citation_support_rate": "mean fraction of expected evidence emitted by actual typed-snapshot diagnosis with verified source provenance",
            "diagnosis_accuracy": "fraction of typed snapshots whose actual diagnosis status and knowledge IDs exactly match expectations",
        },
        "top_k": top_k,
        "min_score": min_score,
        "case_count": len(cases),
        "metrics": metrics,
        "gates": gates,
        "passed": not failures,
        "failures": failures,
        "cases": case_results,
    }


@dataclass(frozen=True)
class BuildResult:
    """隔离 staging 构建的目录、manifest 和黄金集评测结果。"""

    staging_dir: Path
    manifest: Dict[str, Any]
    evaluation: Dict[str, Any]


def _compatibility_descriptor(schema_version: str, schema_sha256: str,
                              embeddings: StableHashEmbeddings) -> Dict[str, Any]:
    """汇总所有会改变 chunk/vector 语义的版本和摘要，供加载时精确兼容性比较。"""
    return {
        "pipeline": {
            "version": PIPELINE_VERSION,
            "source_sha256": sha256_file(Path(__file__).resolve()),
        },
        "schema": {"version": schema_version, "sha256": schema_sha256},
        "tokenizer": embeddings.tokenizer.descriptor(),
        "embedding": embeddings.descriptor(),
        "chunking": {
            "strategy": "one-approved-entry-one-source-anchored-chunk",
            "version": CHUNKING_VERSION,
            "stable_chunk_id": "{entry_id}::main",
            "content_fingerprint": "sha256",
        },
    }


def _optional_faiss_index(path: Path, vectors: Sequence[Sequence[float]]) -> Dict[str, Any]:
    """有 FAISS 时写 IndexFlatIP；无 FAISS 时 vectors.json 仍是完整可运行制品。"""
    try:
        import faiss  # type: ignore
        import numpy as np  # type: ignore

        matrix = np.asarray(vectors, dtype="float32")
        index = faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        faiss.write_index(index, str(path))
        return {
            "available_at_build": True,
            "version": getattr(faiss, "__version__", _package_version("faiss-cpu")),
            "numpy_version": getattr(np, "__version__", _package_version("numpy")),
            "index_type": "IndexFlatIP",
            "metric": "cosine-via-normalized-inner-product",
            "index_file": path.name,
        }
    except (ImportError, ModuleNotFoundError):
        return {
            "available_at_build": False,
            "version": "not-installed",
            "numpy_version": _package_version("numpy"),
            "index_type": None,
            "metric": "cosine-via-normalized-inner-product",
            "index_file": None,
        }


def _faiss_output_identity(index_path: Path, faiss_info: Dict[str, Any]) -> Dict[str, Any]:
    """把可选索引的实际格式、构建依赖状态和输出字节纳入逻辑版本身份。"""
    descriptor = dict(faiss_info)
    descriptor["index_sha256"] = (
        sha256_file(index_path) if faiss_info.get("index_file") else None
    )
    descriptor["identity_sha256"] = sha256_bytes(canonical_json_bytes(descriptor))
    return descriptor


class KnowledgeLifecycle:
    """用 staging + checksum + 原子指针管理知识制品的完整生命周期。"""

    def __init__(self, raw_path: Path = DEFAULT_RAW_PATH, schema_path: Path = DEFAULT_SCHEMA_PATH,
                 golden_path: Path = DEFAULT_GOLDEN_PATH, artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
                 embeddings: Optional[StableHashEmbeddings] = None,
                 enforce_release_golden_contract: bool = True,
                 bundled_provenance: Optional[Dict[str, Dict[str, Any]]] = None,
                 build_mode: str = "versioned-full-rebuild"):
        """绑定 raw/schema/golden/制品目录及构建策略，不在初始化阶段执行 I/O。"""
        self.raw_path = Path(raw_path)
        self.schema_path = Path(schema_path)
        self.golden_path = Path(golden_path)
        self.artifact_root = Path(artifact_root)
        self.embeddings = embeddings or StableHashEmbeddings()
        self.enforce_release_golden_contract = enforce_release_golden_contract
        self.bundled_provenance = bundled_provenance
        self.build_mode = build_mode

    @property
    def versions_dir(self) -> Path:
        """返回发布后不可变版本目录的根路径。"""
        return self.artifact_root / "versions"

    def build_staging(self, enforce_evaluation: bool = True) -> BuildResult:
        """全量校验、向量化和评测，在隔离 staging 中返回尚未发布的构建结果。"""
        raw = read_json(self.raw_path)
        validate_knowledge_document(
            raw,
            self.schema_path,
            require_approved=True,
            validate_live_sources=self.bundled_provenance is None,
        )
        entries, duplicate_count = deduplicate_entries(raw["entries"])
        snapshot = {
            "schema_version": raw["schema_version"],
            "kb_version": raw["kb_version"],
            "description": raw.get("description", "WeakNet structured diagnostic knowledge"),
            "entries": entries,
        }
        schema_sha = sha256_file(self.schema_path)
        compatibility = _compatibility_descriptor(raw["schema_version"], schema_sha, self.embeddings)
        dependencies = _dependency_inventory()
        # 版本身份不能只看 kb_version：源内容、算法兼容性、运行时、黄金集、来源证据和
        # 可选 FAISS 输出任一改变都必须生成不同 artifact_version，杜绝同名异物。
        source_sha = sha256_bytes(canonical_json_bytes(snapshot))
        compatibility_sha = sha256_bytes(canonical_json_bytes(compatibility))
        chunks = build_chunks(entries, self.bundled_provenance)
        provenance_sha = sha256_bytes(canonical_json_bytes([
            chunk["metadata"]["source_provenance"] for chunk in chunks
        ]))
        golden = read_json(self.golden_path)
        golden_sha = sha256_bytes(canonical_json_bytes(golden))
        gates_sha = sha256_bytes(canonical_json_bytes(golden.get("gates", {})))
        evaluation_identity_sha = sha256_bytes(canonical_json_bytes({
            "golden_sha256": golden_sha,
            "gates_sha256": gates_sha,
        }))
        vectors = self.embeddings.embed_documents([chunk["content"] for chunk in chunks])
        staging_parent = self.artifact_root / "staging"
        staging_parent.mkdir(parents=True, exist_ok=True)
        build_nonce = uuid.uuid4().hex
        provisional_dir = staging_parent / ("build-" + build_nonce)
        provisional_dir.mkdir(parents=False, exist_ok=False)
        faiss_info = _faiss_output_identity(
            provisional_dir / "index.faiss",
            _optional_faiss_index(provisional_dir / "index.faiss", vectors),
        )
        artifact_version = "%s-%s-%s-%s-%s-%s-%s" % (
            raw["kb_version"],
            source_sha[:12],
            compatibility_sha[:8],
            dependencies["runtime_fingerprint_sha256"][:8],
            evaluation_identity_sha[:8],
            provenance_sha[:8],
            faiss_info["identity_sha256"][:8],
        )
        evaluation = evaluate_golden_set(
            golden,
            chunks,
            vectors,
            self.embeddings,
            artifact_version,
            enforce_release_contract=self.enforce_release_golden_contract,
            require_live_sources=self.bundled_provenance is None,
        )

        staging_dir = staging_parent / (artifact_version + "-" + build_nonce)
        os.replace(provisional_dir, staging_dir)
        # 同时保留原文件字节与 canonical snapshot：前者保证 rollback 后源 checksum 立即恢复。
        atomic_write_bytes(staging_dir / "raw_source.json", self.raw_path.read_bytes())
        atomic_write_bytes(staging_dir / "schema_snapshot.json", self.schema_path.read_bytes())
        atomic_write_json(staging_dir / "raw_snapshot.json", snapshot)
        atomic_write_json(staging_dir / "chunks.json", chunks)
        source_evidence = [
            {
                "entry_id": chunk["entry_id"],
                "source": chunk["metadata"]["source"],
                "source_revision": chunk["metadata"]["source_revision"],
                "source_provenance": chunk["metadata"]["source_provenance"],
            }
            for chunk in chunks
        ]
        atomic_write_json(staging_dir / "source_evidence.json", source_evidence)
        atomic_write_json(staging_dir / "vectors.json", vectors)
        atomic_write_json(staging_dir / "evaluation.json", evaluation)
        atomic_write_json(staging_dir / "golden_snapshot.json", golden)
        artifact_files = [
            "raw_source.json", "schema_snapshot.json", "raw_snapshot.json", "chunks.json",
            "source_evidence.json", "vectors.json", "evaluation.json", "golden_snapshot.json",
        ]
        if faiss_info["index_file"]:
            artifact_files.append(faiss_info["index_file"])
        checksums = {name: sha256_file(staging_dir / name) for name in sorted(artifact_files)}
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "artifact_version": artifact_version,
            "kb_version": raw["kb_version"],
            "schema": {
                "version": raw["schema_version"],
                "path": self.schema_path.name,
                "sha256": schema_sha,
            },
            "source": {
                "aggregate_sha256": source_sha,
                "inputs": [{"name": self.raw_path.name, "sha256": sha256_file(self.raw_path)}],
                "entry_count": len(entries),
                "approved_entry_count": len(entries),
                "deduplicated_entry_count": duplicate_count,
                "provenance_sha256": provenance_sha,
            },
            "embedding": self.embeddings.descriptor(),
            "tokenizer": self.embeddings.tokenizer.descriptor(),
            "chunking": compatibility["chunking"],
            "faiss": faiss_info,
            "langchain": {
                "version": _package_version("langchain"),
                "community_version": _package_version("langchain-community"),
                "required_for_core_runtime": False,
            },
            "dependencies": dependencies,
            "build": {
                "pipeline_version": PIPELINE_VERSION,
                "pipeline_source_sha256": compatibility["pipeline"]["source_sha256"],
                "mode": self.build_mode,
                "built_at": utc_now(),
                "python": platform.python_version(),
                "python_executable": sys.executable,
                "platform": platform.platform(),
                "output_identity_sha256": faiss_info["identity_sha256"],
            },
            "compatibility": compatibility,
            "evaluation": {
                "passed": evaluation["passed"],
                "metrics": evaluation["metrics"],
                "gates": evaluation["gates"],
                "golden_sha256": golden_sha,
                "gates_sha256": gates_sha,
                "identity_sha256": evaluation_identity_sha,
            },
            "artifact_checksums": checksums,
            "artifact_checksum": sha256_bytes(canonical_json_bytes(checksums)),
        }
        atomic_write_json(staging_dir / "manifest.json", manifest)
        result = BuildResult(staging_dir=staging_dir, manifest=manifest, evaluation=evaluation)
        if enforce_evaluation and not evaluation["passed"]:
            raise EvaluationGateError(
                "evaluation gate failed; staging retained at %s: %s" % (staging_dir, evaluation["failures"])
            )
        return result

    def _pointer(self, version_dir: Path) -> Dict[str, Any]:
        """为不可变版本生成带 manifest 校验和的轻量 current/previous 指针。"""
        manifest_path = version_dir / "manifest.json"
        manifest = read_json(manifest_path)
        return {
            "artifact_version": manifest["artifact_version"],
            "manifest_sha256": sha256_file(manifest_path),
            "switched_at": utc_now(),
        }

    def _append_history(self, event: str, pointer: Dict[str, Any]) -> None:
        """追加并 fsync 一条发布/回滚审计事件，不覆盖已有历史。"""
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        history_path = self.artifact_root / "release_history.jsonl"
        line = canonical_json_bytes({"event": event, "at": utc_now(), **pointer}) + b"\n"
        with history_path.open("ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def _publish_unlocked(self, build: BuildResult) -> Dict[str, Any]:
        """校验 staging 后原子提升版本并切换指针；调用方必须持有 lifecycle 锁。"""
        if not build.evaluation["passed"]:
            raise EvaluationGateError("cannot publish a staging build that failed evaluation")
        validate_artifact_directory(build.staging_dir, self.schema_path, self.embeddings, validate_source_path=None)
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        destination = self.versions_dir / build.manifest["artifact_version"]
        if destination.exists():
            existing = read_json(destination / "manifest.json")
            if existing["artifact_checksum"] != build.manifest["artifact_checksum"]:
                raise ArtifactIntegrityError("artifact version collision: %s" % destination.name)
            shutil.rmtree(build.staging_dir)
        else:
            os.replace(str(build.staging_dir), str(destination))
            _fsync_directory(self.versions_dir)

        # 先把完整目录提升为不可变版本，再更新 previous/current；读者永远不会指向半份制品。
        new_pointer = self._pointer(destination)
        current_path = self.artifact_root / "current.json"
        previous_path = self.artifact_root / "previous.json"
        old_pointer = read_json(current_path) if current_path.exists() else None
        if old_pointer and old_pointer["artifact_version"] != new_pointer["artifact_version"]:
            atomic_write_json(previous_path, old_pointer)
        atomic_write_json(current_path, new_pointer)
        self._append_history("publish", new_pointer)
        return new_pointer

    def publish(self, build: BuildResult) -> Dict[str, Any]:
        """在跨进程锁内发布给定 staging 构建，并返回新 current 指针。"""
        with _artifact_lock(self.artifact_root):
            return self._publish_unlocked(build)

    def release(self) -> Dict[str, Any]:
        """在同一锁内完成全量构建和发布，避免 build/publish 间被其他进程插队。"""
        with _artifact_lock(self.artifact_root):
            return self._publish_unlocked(self.build_staging(enforce_evaluation=True))

    def _rollback_unlocked(self, artifact_version: Optional[str] = None) -> Dict[str, Any]:
        """恢复指定或 previous 版本的 raw/current；调用方必须持有 lifecycle 锁。"""
        current_path = self.artifact_root / "current.json"
        previous_path = self.artifact_root / "previous.json"
        if not current_path.exists():
            raise ArtifactIntegrityError("current pointer does not exist")
        current = read_json(current_path)
        if artifact_version:
            target_dir = self.versions_dir / artifact_version
            target = self._pointer(target_dir)
        else:
            if not previous_path.exists():
                raise ArtifactIntegrityError("previous pointer does not exist")
            target = read_json(previous_path)
            target_dir = self.versions_dir / target["artifact_version"]
        validate_artifact_directory(target_dir, self.schema_path, self.embeddings, validate_source_path=None)
        if sha256_file(target_dir / "manifest.json") != target["manifest_sha256"]:
            raise ArtifactIntegrityError("rollback target manifest checksum mismatch")
        # raw 与 current 是一个逻辑状态：先保存旧 raw，任何指针切换前异常都可精确回补。
        old_raw = self.raw_path.read_bytes()
        try:
            # 先恢复与目标 manifest 精确对应的 raw bytes，异常时回补旧 raw。
            atomic_write_bytes(self.raw_path, (target_dir / "raw_source.json").read_bytes())
            atomic_write_json(previous_path, current)
            target = dict(target)
            target["switched_at"] = utc_now()
            atomic_write_json(current_path, target)
            self._append_history("rollback", target)
            return target
        except Exception:
            current_after_error = read_json(current_path) if current_path.exists() else {}
            if current_after_error.get("artifact_version") != target.get("artifact_version"):
                atomic_write_bytes(self.raw_path, old_raw)
            raise

    def rollback(self, artifact_version: Optional[str] = None) -> Dict[str, Any]:
        """在跨进程锁内执行回滚并返回目标 current 指针。"""
        with _artifact_lock(self.artifact_root):
            return self._rollback_unlocked(artifact_version)

    def ensure_current(self, rebuild_on_incompatible: bool = True) -> "VersionedKnowledgeStore":
        """加载可用 current；缺失、陈旧或不兼容时按策略从可审计 raw 全量重建。"""
        with _artifact_lock(self.artifact_root):
            _recover_promotion_transactions(self.artifact_root)
            store = VersionedKnowledgeStore(
                artifact_root=self.artifact_root,
                raw_path=self.raw_path,
                schema_path=self.schema_path,
                embeddings=self.embeddings,
            )
            try:
                store.load_current(validate_source=True)
                live_golden_sha = sha256_bytes(canonical_json_bytes(read_json(self.golden_path)))
                if store.manifest.get("evaluation", {}).get("golden_sha256") != live_golden_sha:
                    raise StaleSourceError("live golden set changed; rebuild evaluation artifact")
                return store
            except (FileNotFoundError, ArtifactIntegrityError, StaleSourceError, IncompatibleArtifactError):
                if not rebuild_on_incompatible:
                    raise
            # 不兼容时不复制旧 FAISS 文件，而是从可审计 raw 全量重建。
            self._publish_unlocked(self.build_staging(enforce_evaluation=True))
            store.load_current(validate_source=True)
            return store


def _artifact_source_embeddings(manifest: Dict[str, Any]) -> StableHashEmbeddings:
    """按源 manifest 恢复确定性 embedding，用于验证 artifact 的派生向量而非目标运行配置。"""
    descriptor = manifest.get("embedding")
    if not isinstance(descriptor, dict):
        raise ArtifactIntegrityError("manifest embedding descriptor must be an object")
    try:
        dimension = int(descriptor["dimension"])
    except (KeyError, TypeError, ValueError) as error:
        raise ArtifactIntegrityError("manifest embedding dimension is invalid") from error
    if dimension <= 0:
        raise ArtifactIntegrityError("manifest embedding dimension must be positive")
    source_embeddings = StableHashEmbeddings(dimension)
    if source_embeddings.descriptor() != descriptor:
        raise IncompatibleArtifactError(
            "source artifact embedding algorithm is not reproducible by this pipeline"
        )
    if source_embeddings.tokenizer.descriptor() != manifest.get("tokenizer"):
        raise IncompatibleArtifactError(
            "source artifact tokenizer is not reproducible by this pipeline"
        )
    compatibility = manifest.get("compatibility")
    if not isinstance(compatibility, dict) \
            or compatibility.get("embedding") != descriptor \
            or compatibility.get("tokenizer") != manifest.get("tokenizer") \
            or compatibility.get("chunking") != manifest.get("chunking"):
        raise ArtifactIntegrityError("manifest compatibility descriptors are internally inconsistent")
    return source_embeddings


def validate_artifact_directory(version_dir: Path, schema_path: Path,
                                embeddings: StableHashEmbeddings,
                                validate_source_path: Optional[Path],
                                enforce_runtime_compatibility: bool = True) -> Dict[str, Any]:
    """逐层验证制品结构、摘要、纯派生物、来源与运行时兼容性，并返回可信 manifest。"""
    manifest_path = Path(version_dir) / "manifest.json"
    if not manifest_path.exists():
        raise ArtifactIntegrityError("manifest missing from %s" % version_dir)
    manifest = read_json(manifest_path)
    required_manifest_fields = {
        "manifest_version", "artifact_version", "kb_version", "schema", "source",
        "embedding", "tokenizer", "chunking", "faiss", "langchain", "dependencies", "build",
        "compatibility", "evaluation", "artifact_checksums", "artifact_checksum",
    }
    missing_manifest_fields = sorted(required_manifest_fields - set(manifest))
    if missing_manifest_fields:
        raise ArtifactIntegrityError("manifest missing required fields: %s" % ", ".join(missing_manifest_fields))
    checksums = manifest["artifact_checksums"]
    if not isinstance(checksums, dict):
        raise ArtifactIntegrityError("artifact_checksums must be an object")
    required_artifacts = {
        "raw_source.json", "schema_snapshot.json", "raw_snapshot.json", "chunks.json",
        "source_evidence.json", "vectors.json", "evaluation.json", "golden_snapshot.json",
    }
    missing_artifacts = sorted(required_artifacts - set(checksums))
    if missing_artifacts:
        raise ArtifactIntegrityError("manifest missing required artifact checksums: %s" % ", ".join(missing_artifacts))
    for field in ("version", "sha256"):
        if not manifest["schema"].get(field):
            raise ArtifactIntegrityError("manifest schema.%s is required" % field)
    for field in (
        "pipeline_version", "pipeline_source_sha256", "mode", "built_at",
        "python", "python_executable", "platform", "output_identity_sha256",
    ):
        if not manifest["build"].get(field):
            raise ArtifactIntegrityError("manifest build.%s is required" % field)
    for field in ("aggregate_sha256", "inputs", "entry_count", "approved_entry_count", "provenance_sha256"):
        if field not in manifest["source"]:
            raise ArtifactIntegrityError("manifest source.%s is required" % field)
    if not manifest["source"]["inputs"]:
        raise ArtifactIntegrityError("manifest source.inputs must not be empty")
    if sha256_file(Path(version_dir) / "raw_source.json") != manifest["source"]["inputs"][0].get("sha256"):
        raise ArtifactIntegrityError("raw_source.json does not match manifest source input checksum")
    if manifest["faiss"].get("index_file") and manifest["faiss"]["index_file"] not in checksums:
        raise ArtifactIntegrityError("FAISS index file is not covered by artifact_checksums")
    faiss_identity = dict(manifest["faiss"])
    recorded_faiss_identity = faiss_identity.pop("identity_sha256", None)
    index_file = faiss_identity.get("index_file")
    index_path = Path(version_dir) / index_file if index_file else None
    actual_index_sha = sha256_file(index_path) if index_path and index_path.exists() else None
    if faiss_identity.get("index_sha256") != actual_index_sha:
        raise ArtifactIntegrityError("FAISS index output checksum mismatch")
    if (
        not recorded_faiss_identity
        or sha256_bytes(canonical_json_bytes(faiss_identity)) != recorded_faiss_identity
        or manifest["build"].get("output_identity_sha256") != recorded_faiss_identity
        or not str(manifest["artifact_version"]).endswith(recorded_faiss_identity[:8])
    ):
        raise ArtifactIntegrityError("FAISS build-output identity mismatch")
    dependency_inventory = dict(manifest["dependencies"])
    dependency_fingerprint = dependency_inventory.pop("fingerprint_sha256", None)
    if not dependency_fingerprint or sha256_bytes(canonical_json_bytes(dependency_inventory)) != dependency_fingerprint:
        raise ArtifactIntegrityError("manifest dependency inventory fingerprint mismatch")
    # 完整性回答“文件是否被篡改”，兼容性回答“当前代码能否按同一语义解释它”；两者不能混用。
    if enforce_runtime_compatibility:
        current_dependencies = _dependency_inventory()
        built_python = str(manifest["dependencies"].get("python", {}).get("version", ""))
        current_python = str(current_dependencies["python"]["version"])
        if built_python.split(".")[:2] != current_python.split(".")[:2]:
            raise IncompatibleArtifactError(
                "Python runtime major.minor changed: built=%s current=%s" % (built_python, current_python)
            )
        for name, descriptor in manifest["dependencies"].get("packages", {}).items():
            if descriptor.get("runtime_required") is not True:
                continue
            current = current_dependencies["packages"].get(name, {}).get("version", "not-installed")
            if current != descriptor.get("version"):
                raise IncompatibleArtifactError(
                    "runtime dependency %s changed: built=%s current=%s"
                    % (name, descriptor.get("version"), current)
                )
    for name, expected in checksums.items():
        path = Path(version_dir) / name
        if not path.exists() or sha256_file(path) != expected:
            raise ArtifactIntegrityError("artifact checksum mismatch: %s" % name)
    if sha256_bytes(canonical_json_bytes(checksums)) != manifest["artifact_checksum"]:
        raise ArtifactIntegrityError("aggregate artifact checksum mismatch")
    if not manifest.get("evaluation", {}).get("passed"):
        raise ArtifactIntegrityError("artifact did not pass evaluation gate")
    golden_snapshot = read_json(Path(version_dir) / "golden_snapshot.json")
    golden_sha = sha256_bytes(canonical_json_bytes(golden_snapshot))
    gates_sha = sha256_bytes(canonical_json_bytes(golden_snapshot.get("gates", {})))
    evaluation_identity_sha = sha256_bytes(canonical_json_bytes({
        "golden_sha256": golden_sha,
        "gates_sha256": gates_sha,
    }))
    if manifest["evaluation"].get("golden_sha256") != golden_sha:
        raise ArtifactIntegrityError("golden snapshot checksum does not match manifest")
    if manifest["evaluation"].get("gates_sha256") != gates_sha:
        raise ArtifactIntegrityError("golden gate checksum does not match manifest")
    if manifest["evaluation"].get("identity_sha256") != evaluation_identity_sha:
        raise ArtifactIntegrityError("evaluation identity checksum does not match manifest")
    bundled_schema_path = Path(version_dir) / "schema_snapshot.json"
    bundled_schema_sha = sha256_file(bundled_schema_path)
    if bundled_schema_sha != manifest["schema"]["sha256"]:
        raise ArtifactIntegrityError("bundled schema checksum does not match manifest")
    if enforce_runtime_compatibility and Path(schema_path).exists() \
            and sha256_file(schema_path) != bundled_schema_sha:
        raise IncompatibleArtifactError("live schema differs from bundled artifact schema")
    # schema、tokenizer、embedding、chunking 或 pipeline 源码改变都要求重建，禁止复用旧向量。
    expected_compatibility = _compatibility_descriptor(
        manifest["schema"]["version"], bundled_schema_sha, embeddings
    )
    if enforce_runtime_compatibility and manifest.get("compatibility") != expected_compatibility:
        raise IncompatibleArtifactError("schema/tokenizer/embedding/chunking descriptor changed")
    snapshot = read_json(Path(version_dir) / "raw_snapshot.json")
    # 已发布 snapshot 的完整 JSON Schema 结果已由 manifest/checksum 固化；轻量运行时重验核心不变量。
    validate_knowledge_document(
        snapshot,
        bundled_schema_path,
        require_approved=True,
        require_jsonschema=False,
        validate_live_sources=False,
    )
    if sha256_bytes(canonical_json_bytes(snapshot)) != manifest["source"]["aggregate_sha256"]:
        raise ArtifactIntegrityError("raw snapshot checksum does not match manifest")
    chunks = read_json(Path(version_dir) / "chunks.json")
    entries_by_id = {
        entry["entry_id"]: entry for entry in snapshot.get("entries", []) if isinstance(entry, dict)
    }
    source_evidence = read_json(Path(version_dir) / "source_evidence.json")
    if not isinstance(source_evidence, list) or len(source_evidence) != len(entries_by_id):
        raise ArtifactIntegrityError("source evidence must contain exactly one row per raw entry")
    bundled_provenance: Dict[str, Dict[str, Any]] = {}
    for row in source_evidence:
        if not isinstance(row, dict) or set(row) != {
            "entry_id", "source", "source_revision", "source_provenance"
        }:
            raise ArtifactIntegrityError("source evidence row shape is invalid")
        entry_id = row.get("entry_id")
        entry = entries_by_id.get(entry_id)
        if entry is None or entry_id in bundled_provenance:
            raise ArtifactIntegrityError("source evidence entry IDs are missing or duplicated")
        if row.get("source") != entry["source"] \
                or row.get("source_revision") != entry["source_revision"] \
                or not _provenance_supports_entry(
                    entry, row.get("source_provenance"), require_live_source=False
                ):
            raise ArtifactIntegrityError(
                "bundled provenance does not support raw snapshot semantics"
            )
        bundled_provenance[entry_id] = row["source_provenance"]

    # chunks 是 raw + source provenance 的纯派生物；exact equality 阻断阈值/动作/正文伪造。
    canonical_chunks = build_chunks(snapshot["entries"], bundled_provenance)
    if chunks != canonical_chunks:
        raise ArtifactIntegrityError("chunks differ from canonical raw/provenance derivation")
    provenance = [
        chunk.get("metadata", {}).get("source_provenance")
        for chunk in canonical_chunks
        if isinstance(chunk, dict)
    ]
    if sha256_bytes(canonical_json_bytes(provenance)) != manifest["source"]["provenance_sha256"]:
        raise ArtifactIntegrityError("source provenance checksum does not match manifest")
    if not all(_provenance_is_self_consistent(item) for item in provenance):
        raise ArtifactIntegrityError("bundled source evidence is internally inconsistent")
    expected_source_evidence = [
        {
            "entry_id": chunk["entry_id"],
            "source": chunk["metadata"]["source"],
            "source_revision": chunk["metadata"]["source_revision"],
            "source_provenance": chunk["metadata"]["source_provenance"],
        }
        for chunk in canonical_chunks
    ]
    if source_evidence != expected_source_evidence:
        raise ArtifactIntegrityError("source evidence bundle does not match chunks")

    # vectors 同样必须是 canonical chunk content 在源 manifest embedding 下的精确派生结果。
    source_embeddings = _artifact_source_embeddings(manifest)
    vectors = read_json(Path(version_dir) / "vectors.json")
    dimension = source_embeddings.dimension
    if not isinstance(vectors, list) or len(vectors) != len(canonical_chunks) or not all(
        isinstance(vector, list)
        and len(vector) == dimension
        and all(
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            for value in vector
        )
        for vector in vectors
    ):
        raise ArtifactIntegrityError("vector matrix shape, dimension or values are invalid")
    expected_vectors = source_embeddings.embed_documents(
        [chunk["content"] for chunk in canonical_chunks]
    )
    if vectors != expected_vectors:
        raise ArtifactIntegrityError("vectors differ from canonical chunk embedding derivation")
    if validate_source_path is not None:
        if not all(_provenance_is_current(item) for item in provenance):
            raise StaleSourceError("a cited source changed or disappeared; refuse stale evidence")
        inputs = manifest["source"].get("inputs", [])
        if len(inputs) != 1 or not validate_source_path.exists():
            raise StaleSourceError("live raw source is missing or source layout changed")
        if sha256_file(validate_source_path) != inputs[0]["sha256"]:
            raise StaleSourceError("live raw knowledge changed; refuse stale index")
    return manifest


class VersionedKnowledgeStore:
    """只从已发布 current 制品检索，加载时强制校验源、兼容性和 checksum。"""

    def __init__(self, artifact_root: Path = DEFAULT_ARTIFACT_ROOT, raw_path: Path = DEFAULT_RAW_PATH,
                 schema_path: Path = DEFAULT_SCHEMA_PATH, embeddings: Optional[StableHashEmbeddings] = None,
                 top_k: Optional[int] = None, similarity_threshold: Optional[float] = None):
        """配置制品路径和检索门禁；实例须先 ``load_current`` 才能查询。"""
        self.artifact_root = Path(artifact_root)
        self.raw_path = Path(raw_path)
        self.schema_path = Path(schema_path)
        self.embeddings = embeddings or StableHashEmbeddings()
        self.top_k = top_k if top_k is not None else int(os.getenv("RAG_TOP_K", str(DEFAULT_TOP_K)))
        self.similarity_threshold = (
            similarity_threshold
            if similarity_threshold is not None
            else float(os.getenv("RAG_SIMILARITY_THRESHOLD", str(DEFAULT_MIN_SCORE)))
        )
        self.artifact_version = ""
        self.manifest: Dict[str, Any] = {}
        self.chunks: List[Dict[str, Any]] = []
        self.vectors: List[List[float]] = []

    def load_current(self, validate_source: bool = True) -> "VersionedKnowledgeStore":
        """校验 current 指针及整套制品后加载 chunk/vector，并返回当前 store。"""
        pointer_path = self.artifact_root / "current.json"
        pointer = read_json(pointer_path)
        version_dir = self.artifact_root / "versions" / pointer["artifact_version"]
        manifest_path = version_dir / "manifest.json"
        if sha256_file(manifest_path) != pointer["manifest_sha256"]:
            raise ArtifactIntegrityError("current pointer manifest checksum mismatch")
        self.manifest = validate_artifact_directory(
            version_dir,
            self.schema_path,
            self.embeddings,
            self.raw_path if validate_source else None,
        )
        self.artifact_version = self.manifest["artifact_version"]
        self.chunks = read_json(version_dir / "chunks.json")
        self.vectors = read_json(version_dir / "vectors.json")
        if len(self.chunks) != len(self.vectors):
            raise ArtifactIntegrityError("chunk/vector count mismatch")
        return self

    def retrieve(self, query: str, top_k: Optional[int] = None,
                 similarity_threshold: Optional[float] = None) -> RetrievalResult:
        """使用调用级覆盖值或 store 默认门禁执行检索，未加载时拒绝查询。"""
        if not self.artifact_version:
            raise ArtifactIntegrityError("store is not loaded")
        return retrieve_from_vectors(
            query=query,
            chunks=self.chunks,
            vectors=self.vectors,
            embeddings=self.embeddings,
            top_k=top_k if top_k is not None else self.top_k,
            min_score=similarity_threshold if similarity_threshold is not None else self.similarity_threshold,
            artifact_version=self.artifact_version,
        )


def _recover_promotion_transactions(artifact_root: Path) -> None:
    """按 WAL 与新旧 raw 校验和恢复崩溃事务，先于任何 current 加载执行。"""
    transaction_root = Path(artifact_root) / "transactions"
    if not transaction_root.exists():
        return
    for transaction_dir in sorted(transaction_root.iterdir()):
        marker_path = transaction_dir / "transaction.json"
        if not marker_path.exists():
            continue
        marker = read_json(marker_path)
        if marker.get("status") not in {"evaluated", "raw_switching", "raw_switched"}:
            continue
        current_path = Path(artifact_root) / "current.json"
        current = read_json(current_path) if current_path.exists() else {}
        backup_path = transaction_dir / "old_raw.bin"
        new_raw_path = transaction_dir / "new_raw.json"
        raw_path = Path(marker["raw_path"])
        old_sha = marker.get("old_raw_sha256") or (
            sha256_file(backup_path) if backup_path.exists() else None
        )
        new_sha = marker.get("new_raw_sha256") or (
            sha256_file(new_raw_path) if new_raw_path.exists() else None
        )
        raw_sha = sha256_file(raw_path) if raw_path.exists() else None
        if current.get("artifact_version") == marker.get("target_artifact_version"):
            if raw_sha != new_sha and new_raw_path.exists():
                atomic_write_bytes(raw_path, new_raw_path.read_bytes())
            marker["status"] = "committed"
            marker["recovered_at"] = utc_now()
            atomic_write_json(marker_path, marker)
            continue
        if raw_sha != old_sha and backup_path.exists():
            atomic_write_bytes(raw_path, backup_path.read_bytes())
        marker["status"] = "aborted_and_raw_restored"
        marker["recovered_at"] = utc_now()
        atomic_write_json(marker_path, marker)


def _promote_candidates_unlocked(candidate_path: Path, raw_path: Path = DEFAULT_RAW_PATH,
                                 schema_path: Path = DEFAULT_SCHEMA_PATH,
                                 golden_path: Path = DEFAULT_GOLDEN_PATH,
                                 artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
                                 kb_version: Optional[str] = None,
                                 enforce_release_golden_contract: bool = True) -> Dict[str, Any]:
    """已审核候选先在隔离 raw 上全量构建并过评测，然后事务性切换 raw/current。"""
    raw_path = Path(raw_path)
    schema_path = Path(schema_path)
    golden_path = Path(golden_path)
    artifact_root = Path(artifact_root)
    _recover_promotion_transactions(artifact_root)

    base = read_json(raw_path)
    candidate = read_json(Path(candidate_path))
    validate_knowledge_document(base, schema_path, require_approved=True)
    # DeepSeek 等模型产生的 draft 在这一行被拒绝，不会触碰 raw/current。
    validate_knowledge_document(candidate, schema_path, require_approved=True)
    merged = merge_approved_documents(
        base, [candidate], kb_version=kb_version, schema_path=schema_path
    )
    validate_knowledge_document(merged, schema_path, require_approved=True)
    golden = read_json(golden_path)
    golden_covered_ids: set[str] = set()
    for case in golden.get("cases", []):
        if not isinstance(case, dict):
            continue
        retrieval_ids = set(case.get("expected_entry_ids", []))
        diagnosis_ids = set(case.get("expected_diagnosis_entry_ids", []))
        evidence_ids = set(case.get("expected_evidence_entry_ids", []))
        # 候选必须在同一真实 case 中同时被检索、诊断并作为引用证据；声明式 supporting IDs 不算覆盖。
        golden_covered_ids.update(retrieval_ids & diagnosis_ids & evidence_ids)
    uncovered_candidates = sorted(
        entry["entry_id"] for entry in candidate["entries"] if entry["entry_id"] not in golden_covered_ids
    )
    if uncovered_candidates:
        raise EvaluationGateError(
            "approved candidates require golden coverage before staging: %s" % ", ".join(uncovered_candidates)
        )

    transaction_id = "promote-" + uuid.uuid4().hex
    transaction_dir = artifact_root / "transactions" / transaction_id
    transaction_dir.mkdir(parents=True, exist_ok=False)
    marker_path = transaction_dir / "transaction.json"
    backup_path = transaction_dir / "old_raw.bin"
    new_raw_path = transaction_dir / "new_raw.json"
    old_raw_bytes = raw_path.read_bytes()
    atomic_write_bytes(backup_path, old_raw_bytes)
    atomic_write_json(new_raw_path, merged)
    marker: Dict[str, Any] = {
        "transaction_id": transaction_id,
        "status": "preparing",
        "created_at": utc_now(),
        "raw_path": str(raw_path.resolve()),
        "candidate_path": str(Path(candidate_path).resolve()),
        "kb_version": merged["kb_version"],
    }
    atomic_write_json(marker_path, marker)

    # 此时构建只读 transaction/new_raw.json；评测失败不会让生产 raw 或 current 过期。
    lifecycle = KnowledgeLifecycle(
        raw_path=new_raw_path,
        schema_path=schema_path,
        golden_path=golden_path,
        artifact_root=artifact_root,
        enforce_release_golden_contract=enforce_release_golden_contract,
    )
    build = lifecycle.build_staging(enforce_evaluation=True)
    actual_covered_ids: set[str] = set()
    for case_result in build.evaluation.get("cases", []):
        if not case_result.get("diagnosis_correct"):
            continue
        retrieved = set(case_result.get("retrieved_entry_ids", []))
        diagnosed = set(case_result.get("actual_diagnosis_entry_ids", []))
        cited = set(case_result.get("valid_supporting_citation_ids", []))
        actual_covered_ids.update(retrieved & diagnosed & cited)
    unevaluated_candidates = sorted(
        entry["entry_id"]
        for entry in candidate["entries"]
        if entry["entry_id"] not in actual_covered_ids
    )
    if unevaluated_candidates:
        raise EvaluationGateError(
            "approved candidates were not actually retrieved, diagnosed and source-cited: %s"
            % ", ".join(unevaluated_candidates)
        )
    marker.update(
        {
            "status": "evaluated",
            "target_artifact_version": build.manifest["artifact_version"],
            "staging_dir": str(build.staging_dir),
            "evaluation": build.evaluation["metrics"],
        }
    )
    atomic_write_json(marker_path, marker)

    raw_switched = False
    try:
        # WAL 必须先于 raw replace 持久化；恢复器据此区分 old/new 两个合法状态。
        marker.update({
            "status": "raw_switching",
            "old_raw_sha256": sha256_bytes(old_raw_bytes),
            "new_raw_sha256": sha256_file(new_raw_path),
            "raw_switching_at": utc_now(),
        })
        atomic_write_json(marker_path, marker)
        # new_raw.json 和生产 raw 写入完全相同的 canonical bytes，manifest source checksum 可直接验证。
        atomic_write_bytes(raw_path, new_raw_path.read_bytes())
        raw_switched = True
        if os.getenv("RAG_PROMOTION_FAILPOINT") == "after_raw_replace":
            os._exit(86)
        marker["status"] = "raw_switched"
        marker["raw_switched_at"] = utc_now()
        atomic_write_json(marker_path, marker)
        pointer = lifecycle._publish_unlocked(build)
        marker["status"] = "committed"
        marker["committed_at"] = utc_now()
        marker["pointer"] = pointer
        atomic_write_json(marker_path, marker)
        return {
            "transaction_id": transaction_id,
            "raw": str(raw_path),
            "kb_version": merged["kb_version"],
            "entry_count": len(merged["entries"]),
            "pointer": pointer,
            "evaluation": build.evaluation,
        }
    except Exception:
        current_path = artifact_root / "current.json"
        current = read_json(current_path) if current_path.exists() else {}
        if current.get("artifact_version") == build.manifest["artifact_version"]:
            marker["status"] = "committed_after_recovery_check"
            marker["committed_at"] = utc_now()
            atomic_write_json(marker_path, marker)
        elif raw_switched:
            atomic_write_bytes(raw_path, old_raw_bytes)
            marker["status"] = "aborted_and_raw_restored"
            marker["aborted_at"] = utc_now()
            atomic_write_json(marker_path, marker)
        raise


def promote_candidates(candidate_path: Path, raw_path: Path = DEFAULT_RAW_PATH,
                       schema_path: Path = DEFAULT_SCHEMA_PATH,
                       golden_path: Path = DEFAULT_GOLDEN_PATH,
                       artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
                       kb_version: Optional[str] = None,
                       enforce_release_golden_contract: bool = True) -> Dict[str, Any]:
    """跨进程互斥包装，保证候选合并、raw 切换与 current 发布属于同一串行事务。"""
    with _artifact_lock(Path(artifact_root)):
        return _promote_candidates_unlocked(
            candidate_path, raw_path, schema_path, golden_path, artifact_root, kb_version,
            enforce_release_golden_contract,
        )


def open_default_store(auto_rebuild: bool = True, artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
                       raw_path: Path = DEFAULT_RAW_PATH, schema_path: Path = DEFAULT_SCHEMA_PATH,
                       golden_path: Path = DEFAULT_GOLDEN_PATH) -> VersionedKnowledgeStore:
    """稳定运行时入口；缺失、陈旧或不兼容索引按策略从 raw 重建。"""
    lifecycle = KnowledgeLifecycle(
        raw_path=raw_path,
        schema_path=schema_path,
        golden_path=golden_path,
        artifact_root=artifact_root,
    )
    return lifecycle.ensure_current(rebuild_on_incompatible=auto_rebuild)


def migrate_artifact_only(source_artifact_root: Path, target_artifact_root: Path,
                          embeddings: Optional[StableHashEmbeddings] = None) -> Dict[str, Any]:
    """仅凭 current artifact 内固化的 raw/schema/golden/provenance 全量重建目标制品。"""
    source_root = Path(source_artifact_root).resolve()
    target_root = Path(target_artifact_root).resolve()
    if source_root == target_root:
        raise ValueError("artifact-only migration requires a distinct target artifact root")
    pointer = read_json(source_root / "current.json")
    version_dir = source_root / "versions" / pointer["artifact_version"]
    manifest_path = version_dir / "manifest.json"
    if sha256_file(manifest_path) != pointer.get("manifest_sha256"):
        raise ArtifactIntegrityError("source current pointer manifest checksum mismatch")
    source_embeddings = _artifact_source_embeddings(read_json(manifest_path))
    # 先以源 manifest 的 embedding 验证源 vectors，再使用目标 runtime 配置全量重建。
    source_manifest = validate_artifact_directory(
        version_dir,
        version_dir / "schema_snapshot.json",
        source_embeddings,
        validate_source_path=None,
        enforce_runtime_compatibility=False,
    )
    selected_embeddings = embeddings or StableHashEmbeddings()
    evidence_rows = read_json(version_dir / "source_evidence.json")
    bundled_provenance = {
        row["entry_id"]: row["source_provenance"]
        for row in evidence_rows
        if isinstance(row, dict) and row.get("entry_id")
    }
    input_dir = target_root / "migration_inputs" / pointer["artifact_version"]
    input_dir.mkdir(parents=True, exist_ok=True)
    raw_path = input_dir / "raw_source.json"
    schema_path = input_dir / "schema_snapshot.json"
    golden_path = input_dir / "golden_snapshot.json"
    atomic_write_bytes(raw_path, (version_dir / "raw_source.json").read_bytes())
    atomic_write_bytes(schema_path, (version_dir / "schema_snapshot.json").read_bytes())
    atomic_write_bytes(golden_path, (version_dir / "golden_snapshot.json").read_bytes())
    bundled_golden = read_json(golden_path)
    bundled_case_ids = {
        str(case.get("case_id"))
        for case in bundled_golden.get("cases", [])
        if isinstance(case, dict)
    }
    lifecycle = KnowledgeLifecycle(
        raw_path=raw_path,
        schema_path=schema_path,
        golden_path=golden_path,
        artifact_root=target_root,
        embeddings=selected_embeddings,
        enforce_release_golden_contract=set(REQUIRED_GOLDEN_CASES).issubset(bundled_case_ids),
        bundled_provenance=bundled_provenance,
        build_mode="artifact-only-full-rebuild",
    )
    target_pointer = lifecycle.release()
    return {
        "status": "artifact-only-rebuilt-and-published",
        "source_artifact_version": source_manifest["artifact_version"],
        **target_pointer,
    }


def _flatten_snapshot(snapshot: Dict[str, Any], prefix: str = "") -> Iterable[Tuple[str, Any]]:
    """按稳定键序将 typed snapshot 展平为 ``(字段路径, 叶子值)`` 流。"""
    # 保留完整层级和列表下标，避免不同接口/嵌套状态的同名字段在检索上下文中互相覆盖。
    for key in sorted(snapshot):
        value = snapshot[key]
        path = "%s.%s" % (prefix, key) if prefix else key
        if isinstance(value, dict):
            yield from _flatten_snapshot(value, path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    yield from _flatten_snapshot(item, "%s[%d]" % (path, index))
                else:
                    yield path, item
        else:
            yield path, value


def _snake_case(value: str) -> str:
    """将 proto/Node 的 camelCase 或符号分隔字段统一为 snake_case。"""
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()


def _availability_bool(value: Any) -> bool:
    """将 typed enum、布尔、0/1 和常见文本统一解释为指标可用性布尔值。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) == 1
    normalized = str(value).strip().lower()
    return normalized in {"available", "metric_availability_available", "true", "yes", "ok", "1"}


def _pick_mapping(value: Dict[str, Any], *names: str) -> Any:
    """按优先级读取 camelCase/snake_case 别名，均不存在时返回 ``None``。"""
    for name in names:
        if name in value:
            return value[name]
    return None


def _active_interface(snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """只让当前上行接口触发阈值；其他网卡仅保留为检索上下文。"""
    if _pick_mapping(snapshot, "hasActiveInterface", "has_active_interface") is False:
        return None
    interfaces = snapshot.get("interfaces")
    if not isinstance(interfaces, list):
        return None
    typed_interfaces = [item for item in interfaces if isinstance(item, dict)]
    for item in typed_interfaces:
        if bool(_pick_mapping(item, "usingNow", "using_now")):
            return item
    active_name = _pick_mapping(snapshot, "activeInterface", "active_interface")
    if active_name:
        for item in typed_interfaces:
            if _pick_mapping(item, "interfaceName", "interface_name") == active_name:
                return item
    for item in typed_interfaces:
        if bool(_pick_mapping(item, "isDefaultRoute", "is_default_route")):
            return item
    return typed_interfaces[0] if typed_interfaces else None


def _active_metric_available(interface: Dict[str, Any], leaf: str) -> bool:
    """判断活动接口上的指定指标是否被 typed availability 字段标记为可用。"""
    availability_keys: Dict[str, Tuple[str, str]] = {
        "rtt": ("rttAvailability", "rtt_availability"),
        "rtt_ms": ("rttAvailability", "rtt_availability"),
        "previous_rtt_ms": ("rttAvailability", "rtt_availability"),
        "rssi": ("rssiAvailability", "rssi_availability"),
        "rssi_dbm": ("rssiAvailability", "rssi_availability"),
        "tcp_loss_rate": ("tcpRetransmissionAvailability", "tcp_retransmission_availability"),
        "tcp_retransmission_rate": ("tcpRetransmissionAvailability", "tcp_retransmission_availability"),
        "tcp_retransmission_rate_percent": (
            "tcpRetransmissionAvailability", "tcp_retransmission_availability"
        ),
        "traffic_mbps": ("trafficAvailability", "traffic_availability"),
        "traffic_bps": ("trafficAvailability", "traffic_availability"),
        "traffic_total_bps": ("trafficAvailability", "traffic_availability"),
        "traffic_bytes_per_second": ("trafficAvailability", "traffic_availability"),
        "traffic_rx_bps": ("trafficAvailability", "traffic_availability"),
        "traffic_tx_bps": ("trafficAvailability", "traffic_availability"),
    }
    keys = availability_keys.get(leaf)
    if not keys:
        return True
    availability = _pick_mapping(interface, *keys)
    # canonical bridge 只输出已校验数值，因此缺少 availability 字段时保持兼容。
    return True if availability is None else _availability_bool(availability)


def _snapshot_query(snapshot: Dict[str, Any]) -> Tuple[str, Dict[str, List[Any]]]:
    """把 typed snapshot 转成检索文本，并返回仅可用于阈值判断的规范化观测值。"""
    aliases = {
        "rtt": "rtt",
        "rtt_ms": "rtt",
        "latency_ms": "rtt",
        "previous_rtt_ms": "rtt",
        "tcp_loss_rate": "tcp_retransmission_rate",
        "tcp_retransmission_rate": "tcp_retransmission_rate",
        "tcp_retransmission_rate_percent": "tcp_retransmission_rate",
        "retransmission_rate": "tcp_retransmission_rate",
        "rssi": "rssi",
        "rssi_dbm": "rssi",
        "traffic_mbps": "traffic",
        "traffic_bps": "traffic",
        "traffic_total_bps": "traffic",
        "traffic_bytes_per_second": "traffic",
        "traffic_rx_bps": "traffic",
        "traffic_tx_bps": "traffic",
        "active_flows": "active_flows",
        "expected_network_activity": "expected_network_activity",
        "expected_activity": "expected_network_activity",
        "request_in_flight": "expected_network_activity",
        "bandwidth_utilization": "bandwidth_utilization",
        "interface_state": "interface_state",
        "state": "interface_state",
        "quality": "quality_score",
        "quality_score": "quality_score",
        "score": "quality_score",
        "default_route_changed": "default_route_changed",
        "active_interface_changed": "default_route_changed",
        "interface_switched": "default_route_changed",
        "ebpf_available": "ebpf_available",
        "bpf_available": "ebpf_available",
    }
    values: Dict[str, List[Any]] = {}
    traffic_observation = _pick_mapping(snapshot, "trafficObservation", "traffic_observation")
    traffic_observation = traffic_observation if isinstance(traffic_observation, dict) else {}
    traffic_partial = (
        _pick_mapping(traffic_observation, "captureComplete", "capture_complete") is False
        or _pick_mapping(traffic_observation, "mapReadComplete", "map_read_complete") is False
        or _pick_mapping(traffic_observation, "baselineOnly", "baseline_only") is True
    )
    parts = ["网络诊断 network diagnostics"]
    # 完整快照只进入 context 提升语义召回；真正阈值只读 active/全局观测，避免非活动网卡误报。
    parts.extend("context.%s=%s" % (path, value) for path, value in _flatten_snapshot(snapshot))
    active = _active_interface(snapshot)
    observed_snapshot = {key: value for key, value in snapshot.items() if key != "interfaces"}
    observation_items = list(_flatten_snapshot(observed_snapshot))
    if active is not None:
        observation_items.extend(_flatten_snapshot(active, "active_interface"))

    for path, value in observation_items:
        leaf = _snake_case(re.sub(r"\[\d+\]$", "", path.split(".")[-1]))
        normalized_path = _snake_case(path)
        metric = aliases.get(leaf)
        # canonical proto/Node 的 TrafficObservationStatus 可以通过 availability/valid/BPF 挂载位表达降级。
        if "traffic_observation" in normalized_path or "traffic_status" in normalized_path:
            if leaf == "availability":
                metric = "ebpf_available"
                value = _availability_bool(value)
            elif leaf in {"valid", "libbpf_available", "bpf_loaded"}:
                metric = "ebpf_available"
                value = bool(value)
            elif leaf in {"capture_complete", "map_read_complete"}:
                metric = "ebpf_available"
                value = bool(value)
            elif leaf == "baseline_only":
                metric = "ebpf_available"
                value = not bool(value)
        if metric == "interface_state" and isinstance(value, (int, float)):
            value = {1: "up", 2: "down"}.get(int(value), "unspecified")
        if path.startswith("active_interface.") and metric and not _active_metric_available(active or {}, leaf):
            # proto3 数值 0 与 unavailable 必须区分；无效数值不进 observed，也不触发零流量。
            continue
        if traffic_partial and metric in {"traffic", "active_flows"}:
            continue
        if value is None:
            continue
        if metric:
            values.setdefault(metric, []).append(value)
        parts.append("observed.%s=%s" % (path, value))
        if metric == "rtt" and isinstance(value, (int, float)):
            parts.append("RTT 往返时延 高延迟" if value > 50 else "RTT 往返时延 正常")
        elif metric == "tcp_retransmission_rate" and isinstance(value, (int, float)):
            parts.append("TCP 重传 丢包 链路拥塞" if value >= 1 else "TCP 重传正常")
        elif metric == "rssi" and isinstance(value, (int, float)):
            parts.append("WiFi RSSI 信号弱 无线干扰" if value < -70 else "WiFi RSSI 信号正常")
        elif metric == "traffic" and isinstance(value, (int, float)) and value == 0:
            parts.append("流量为零 网络中断 监控异常")
        elif metric == "interface_state" and str(value).lower() in {"down", "inactive", "0", "false"}:
            parts.append("网络接口 down 不可用 中断")
        elif metric == "ebpf_available" and not _availability_bool(value):
            parts.append("eBPF BPF 流量采集器 unavailable load attach 失败 证据缺失")
        elif metric == "default_route_changed" and _availability_bool(value):
            parts.append("多网卡 默认路由 default route 上行接口切换 ifindex 重绑")
    return "\n".join(parts), values


def _threshold_matches(threshold: Dict[str, Any], observed: Any) -> bool:
    """按知识条目的结构化操作符比较单个观测值，不可转换时返回 ``False``。"""
    operator = threshold.get("operator")
    if operator == "none":
        return True
    expected = threshold.get("value")
    try:
        if operator == "gt":
            return float(observed) > float(expected)
        if operator == "ge":
            return float(observed) >= float(expected)
        if operator == "lt":
            return float(observed) < float(expected)
        if operator == "le":
            return float(observed) <= float(expected)
        if operator == "between":
            return float(expected) <= float(observed) <= float(threshold["max_value"])
        if operator == "eq":
            return str(observed).strip().lower() == str(expected).strip().lower()
    except (TypeError, ValueError):
        return False
    return False


def _observation_is_degraded(snapshot: Dict[str, Any]) -> bool:
    """判断采样证据是否不完整，与“网络本身是否异常”分开。"""
    has_active = _pick_mapping(snapshot, "hasActiveInterface", "has_active_interface")
    if has_active is False:
        return True
    active = _active_interface(snapshot)
    if active is not None:
        for keys in (
            ("rttAvailability", "rtt_availability"),
            ("rssiAvailability", "rssi_availability"),
            ("tcpRetransmissionAvailability", "tcp_retransmission_availability"),
            ("trafficAvailability", "traffic_availability"),
        ):
            availability = _pick_mapping(active, *keys)
            if availability is not None and not _availability_bool(availability):
                return True
    for path, value in _flatten_snapshot(snapshot):
        normalized_path = _snake_case(path)
        leaf = _snake_case(re.sub(r"\[\d+\]$", "", path.split(".")[-1]))
        if (
            ("traffic_observation" in normalized_path or "traffic_status" in normalized_path)
            and (
                leaf in {"capture_complete", "map_read_complete"} and not bool(value)
                or leaf == "baseline_only" and bool(value)
            )
        ):
            return True
        if (normalized_path.endswith("quality_degraded") or normalized_path == "degraded") and bool(value):
            return True
        if "missing_metrics" in normalized_path and str(value).strip():
            return True
        if "traffic_observation" in normalized_path or "traffic_status" in normalized_path:
            if leaf == "valid" and not bool(value):
                return True
            if leaf == "availability" and not _availability_bool(value):
                return True
        if leaf in {"ebpf_available", "bpf_available"} and not _availability_bool(value):
            return True
    return False


def _diagnose_snapshot_with_store(snapshot: Dict[str, Any], store: Any, *, top_k: int,
                                  min_score: float) -> Dict[str, Any]:
    """对给定 store 执行真实 typed-snapshot 诊断，供黄金集和线上入口共同调用。"""
    provider = "versioned-local-rag/%s" % EMBEDDING_MODEL
    artifact_version = str(getattr(store, "artifact_version", "") or "unavailable")
    observation_degraded = isinstance(snapshot, dict) and _observation_is_degraded(snapshot)
    if not isinstance(snapshot, dict) or not snapshot:
        return {
            "status": "insufficient_evidence",
            "evidence": [],
            "knowledge_entry_ids": [],
            "confidence": 0.0,
            "actions": [],
            "degraded": True,
            "retrieval_degraded": True,
            "observation_degraded": True,
            "provider": provider,
            "artifact_version": artifact_version,
            "top_k": top_k,
            "similarity_threshold": min_score,
            "error": "snapshot must be a non-empty object",
        }
    if _pick_mapping(snapshot, "hasActiveInterface", "has_active_interface") is False:
        return {
            "status": "insufficient_evidence",
            "evidence": [],
            "knowledge_entry_ids": [],
            "confidence": 0.0,
            "actions": [],
            "degraded": True,
            "retrieval_degraded": False,
            "observation_degraded": True,
            "provider": provider,
            "artifact_version": artifact_version,
            "top_k": top_k,
            "similarity_threshold": min_score,
            "error": "snapshot explicitly reports no active interface",
        }
    query, observed = _snapshot_query(snapshot)
    if not observed:
        return {
            "status": "insufficient_evidence",
            "evidence": [],
            "knowledge_entry_ids": [],
            "confidence": 0.0,
            "actions": [],
            "degraded": True,
            "retrieval_degraded": False,
            "observation_degraded": True,
            "provider": provider,
            "artifact_version": artifact_version,
            "top_k": top_k,
            "similarity_threshold": min_score,
            "error": "snapshot contains no supported network metrics",
        }
    if top_k <= 0:
        raise ValueError("top_k must be positive")

    # 先对全部 chunk 做结构化阈值匹配，再用相似度做证据置信门禁；否则低分异常会被误判健康。
    broad = store.retrieve(
        query,
        top_k=max(len(getattr(store, "chunks", [])), top_k),
        similarity_threshold=-1.0,
    )
    threshold_matches: List[Evidence] = []
    for item in broad.evidence:
        metric = item.metadata.get("metric")
        threshold = item.metadata.get("threshold", {})
        matched = metric in observed and any(
            _threshold_matches(threshold, value) for value in observed[metric]
        )
        if matched and metric == "traffic" and threshold.get("operator") == "eq":
            try:
                is_zero_trigger = float(threshold.get("value")) == 0.0
            except (TypeError, ValueError):
                is_zero_trigger = False
            if is_zero_trigger:
                expected_activity = any(
                    _availability_bool(value)
                    for value in observed.get("expected_network_activity", [])
                )
                active_flows = any(
                    isinstance(value, (int, float)) and value > 0
                    for value in observed.get("active_flows", [])
                )
                matched = expected_activity or active_flows
        if matched:
            threshold_matches.append(item)
        elif threshold.get("operator") == "none":
            threshold_matches.append(item)

    if not threshold_matches:
        insufficient = observation_degraded
        return {
            "status": "insufficient_evidence" if insufficient else "healthy",
            "evidence": [],
            "knowledge_entry_ids": [],
            "confidence": 0.0 if insufficient else 1.0,
            "actions": [],
            "degraded": insufficient,
            "retrieval_degraded": False,
            "observation_degraded": observation_degraded,
            "provider": provider,
            "artifact_version": artifact_version,
            "top_k": top_k,
            "similarity_threshold": min_score,
            "error": "observation is incomplete" if insufficient else None,
        }

    applicable = [item for item in threshold_matches if item.score >= min_score][:top_k]
    if not applicable:
        return {
            "status": "insufficient_evidence",
            "evidence": [],
            "knowledge_entry_ids": [],
            "confidence": 0.0,
            "actions": [],
            "degraded": True,
            "retrieval_degraded": True,
            "observation_degraded": observation_degraded,
            "provider": provider,
            "artifact_version": artifact_version,
            "top_k": top_k,
            "similarity_threshold": min_score,
            "error": "structured anomaly matched, but no source evidence passed similarity threshold",
        }

    actions: List[str] = []
    for item in applicable:
        for action in item.metadata.get("actions", []):
            if action not in actions:
                actions.append(action)
    degradation_only = all(
        item.metadata.get("metric") in {"ebpf_available", "default_route_changed"}
        for item in applicable
    )
    return {
        "status": "degraded" if degradation_only else "unhealthy",
        "evidence": [asdict(item) for item in applicable],
        "knowledge_entry_ids": [item.entry_id for item in applicable],
        "confidence": round(max(item.score for item in applicable), 6),
        "actions": actions,
        "degraded": observation_degraded or degradation_only,
        "retrieval_degraded": False,
        "observation_degraded": observation_degraded,
        "provider": provider,
        "artifact_version": artifact_version,
        "top_k": top_k,
        "similarity_threshold": min_score,
        "error": None,
    }


def diagnose_snapshot(snapshot: Dict[str, Any], *, top_k: Optional[int] = None,
                      min_score: Optional[float] = None) -> Dict[str, Any]:
    """纯结构化运行时入口：不依赖日志正则，不打印 stdout，返回固定 JSON 形状。"""
    requested_top_k = top_k if top_k is not None else int(os.getenv("RAG_TOP_K", str(DEFAULT_TOP_K)))
    threshold = min_score if min_score is not None else float(
        os.getenv("RAG_SIMILARITY_THRESHOLD", str(DEFAULT_MIN_SCORE))
    )
    try:
        # 空/错误快照不应触发 artifact 构建；用哨兵 store 走统一输入校验。
        if not isinstance(snapshot, dict) or not snapshot:
            return _diagnose_snapshot_with_store(
                snapshot, None, top_k=requested_top_k, min_score=threshold
            )
        store = open_default_store(
            auto_rebuild=True,
            artifact_root=Path(os.getenv("RAG_ARTIFACT_ROOT", str(DEFAULT_ARTIFACT_ROOT))),
            raw_path=Path(os.getenv("RAG_RAW_PATH", str(DEFAULT_RAW_PATH))),
            schema_path=Path(os.getenv("RAG_SCHEMA_PATH", str(DEFAULT_SCHEMA_PATH))),
            golden_path=Path(os.getenv("RAG_GOLDEN_PATH", str(DEFAULT_GOLDEN_PATH))),
        )
        return _diagnose_snapshot_with_store(
            snapshot, store, top_k=requested_top_k, min_score=threshold
        )
    except Exception as error:
        observation_degraded = isinstance(snapshot, dict) and _observation_is_degraded(snapshot)
        return {
            "status": "unavailable",
            "evidence": [],
            "knowledge_entry_ids": [],
            "confidence": 0.0,
            "actions": [],
            "degraded": True,
            "retrieval_degraded": True,
            "observation_degraded": observation_degraded,
            "provider": "versioned-local-rag/%s" % EMBEDDING_MODEL,
            "artifact_version": "unavailable",
            "top_k": requested_top_k,
            "similarity_threshold": threshold,
            "error": "%s: %s" % (type(error).__name__, error),
        }


__all__ = [
    "ArtifactIntegrityError",
    "DEFAULT_ARTIFACT_ROOT",
    "DEFAULT_GOLDEN_PATH",
    "DEFAULT_RAW_PATH",
    "DEFAULT_SCHEMA_PATH",
    "EvaluationGateError",
    "Evidence",
    "IncompatibleArtifactError",
    "KnowledgeConflictError",
    "KnowledgeLifecycle",
    "KnowledgeValidationError",
    "RetrievalResult",
    "StableHashEmbeddings",
    "StableTokenizer",
    "StaleSourceError",
    "VersionedKnowledgeStore",
    "diagnose_snapshot",
    "open_default_store",
    "promote_candidates",
    "migrate_artifact_only",
    "validate_knowledge_document",
]
