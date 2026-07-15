#!/usr/bin/env python3
"""
文件职责：为知识库校验、候选提升、构建、发布、迁移、状态查询和回滚提供稳定 CLI。
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from knowledge_pipeline import (
    DEFAULT_ARTIFACT_ROOT,
    DEFAULT_GOLDEN_PATH,
    DEFAULT_RAW_PATH,
    DEFAULT_SCHEMA_PATH,
    KnowledgeLifecycle,
    KnowledgeValidationError,
    VersionedKnowledgeStore,
    migrate_artifact_only,
    promote_candidates,
    read_json,
    validate_knowledge_document,
)


def _path(value: str) -> Path:
    """把 CLI 路径展开为绝对路径，避免子命令切换工作目录后解析漂移。"""

    return Path(value).expanduser().resolve()


def _lifecycle(args: argparse.Namespace) -> KnowledgeLifecycle:
    """按公共 CLI 参数构造一次知识库生命周期控制器。"""

    return KnowledgeLifecycle(
        raw_path=args.raw,
        schema_path=args.schema,
        golden_path=args.golden,
        artifact_root=args.artifacts,
    )


def _emit(value: Dict[str, Any]) -> None:
    """向 stdout 输出稳定排序的 JSON，供人和自动化脚本共同消费。"""

    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def command_validate(args: argparse.Namespace) -> Dict[str, Any]:
    """校验正式知识库及候选文件，并返回版本、条目数和候选摘要。"""

    raw = read_json(args.raw)
    validate_knowledge_document(raw, args.schema, require_approved=True)
    candidates = []
    for candidate_path in args.candidate:
        candidate = read_json(candidate_path)
        validate_knowledge_document(candidate, args.schema, require_approved=args.require_approved_candidates)
        candidates.append({"path": str(candidate_path), "entry_count": len(candidate["entries"])})
    return {
        "status": "valid",
        "raw": str(args.raw),
        "kb_version": raw["kb_version"],
        "entry_count": len(raw["entries"]),
        "candidates": candidates,
    }


def command_build(args: argparse.Namespace) -> Dict[str, Any]:
    """构建并评测隔离 staging 制品，但不切换线上 current 指针。"""

    result = _lifecycle(args).build_staging(enforce_evaluation=True)
    return {
        "status": "staged",
        "staging_dir": str(result.staging_dir),
        "artifact_version": result.manifest["artifact_version"],
        "evaluation": result.evaluation,
    }


def command_release(args: argparse.Namespace) -> Dict[str, Any]:
    """完成构建、评测与原子发布，返回新的版本指针。"""

    lifecycle = _lifecycle(args)
    pointer = lifecycle.release()
    return {"status": "published", **pointer}


def command_migrate(args: argparse.Namespace) -> Dict[str, Any]:
    """仅使用自包含 current artifact 迁移到新的制品根目录。"""

    # 不依赖源码树或外部 raw/schema/golden，只消费 source current artifact 的自包含输入。
    return migrate_artifact_only(args.from_artifacts, args.target_artifacts)


def command_status(args: argparse.Namespace) -> Dict[str, Any]:
    """验证当前制品、源码绑定和兼容性，并返回可审计状态。"""

    store = VersionedKnowledgeStore(
        artifact_root=args.artifacts,
        raw_path=args.raw,
        schema_path=args.schema,
    ).load_current(validate_source=True)
    previous_path = args.artifacts / "previous.json"
    return {
        "status": "ready",
        "artifact_version": store.artifact_version,
        "kb_version": store.manifest["kb_version"],
        "entry_count": len(store.chunks),
        "source_sha256": store.manifest["source"]["aggregate_sha256"],
        "artifact_checksum": store.manifest["artifact_checksum"],
        "evaluation": store.manifest["evaluation"],
        "previous": read_json(previous_path) if previous_path.exists() else None,
    }


def command_rollback(args: argparse.Namespace) -> Dict[str, Any]:
    """把 current 原子切换到 previous 或用户指定的保留版本。"""

    pointer = _lifecycle(args).rollback(args.version)
    return {"status": "rolled-back", **pointer}


def command_promote(args: argparse.Namespace) -> Dict[str, Any]:
    """将已审批候选合并、评测并作为一个可恢复事务发布。"""

    release = promote_candidates(
        candidate_path=args.candidate,
        raw_path=args.raw,
        schema_path=args.schema,
        golden_path=args.golden,
        artifact_root=args.artifacts,
        kb_version=args.kb_version,
    )
    return {
        "status": "candidate-evaluated-and-published",
        **release,
    }


def _common(parser: argparse.ArgumentParser) -> None:
    """给需要源码与制品路径的子命令注册统一参数。"""

    parser.add_argument("--raw", type=_path, default=DEFAULT_RAW_PATH)
    parser.add_argument("--schema", type=_path, default=DEFAULT_SCHEMA_PATH)
    parser.add_argument("--golden", type=_path, default=DEFAULT_GOLDEN_PATH)
    parser.add_argument("--artifacts", type=_path, default=DEFAULT_ARTIFACT_ROOT)


def build_parser() -> argparse.ArgumentParser:
    """构造知识库生命周期 CLI 及各子命令到 handler 的映射。"""

    parser = argparse.ArgumentParser(description="WeakNet versioned RAG knowledge lifecycle")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate raw/candidate schema and conflicts")
    _common(validate)
    validate.add_argument("--candidate", type=_path, action="append", default=[])
    validate.add_argument(
        "--require-approved-candidates",
        action="store_true",
        help="apply the release review gate; draft candidate templates fail by design",
    )
    validate.set_defaults(handler=command_validate)

    build = subparsers.add_parser("build", help="build and evaluate an isolated staging artifact")
    _common(build)
    build.set_defaults(handler=command_build)

    release = subparsers.add_parser("release", help="build, evaluate and atomically switch current")
    _common(release)
    release.set_defaults(handler=command_release)

    migrate = subparsers.add_parser(
        "migrate",
        help="rebuild into a new root using only a copied current artifact",
    )
    migrate.add_argument("--from-artifacts", type=_path, default=DEFAULT_ARTIFACT_ROOT)
    migrate.add_argument("--target-artifacts", type=_path, required=True)
    migrate.set_defaults(handler=command_migrate)

    status = subparsers.add_parser("status", help="verify current pointer, checksums, source and compatibility")
    _common(status)
    status.set_defaults(handler=command_status)

    rollback = subparsers.add_parser("rollback", help="atomically switch to previous or an explicit retained version")
    _common(rollback)
    rollback.add_argument("--version", help="retained artifact version; omit to use previous.json")
    rollback.set_defaults(handler=command_rollback)

    promote = subparsers.add_parser(
        "promote",
        help="review-gate, stage, evaluate and transactionally publish an approved candidate set",
    )
    _common(promote)
    promote.add_argument("--candidate", type=_path, required=True)
    promote.add_argument("--kb-version", required=True)
    promote.set_defaults(handler=command_promote)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """执行选定子命令；成功返回 0，异常转成结构化 JSON 并返回 1。"""

    args = build_parser().parse_args(argv)
    try:
        _emit(args.handler(args))
        return 0
    except Exception as error:
        _emit({"status": "error", "error_type": type(error).__name__, "error": str(error)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
