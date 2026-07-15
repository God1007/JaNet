#!/usr/bin/env python3
"""把标准输入写入有大小上限的日志文件，并保留编号归档。

轮转时由真正持有文件描述符的进程主动关闭、重命名并重新打开文件，避免只改文件名
后服务仍持续写入旧 inode，最终磁盘空间没有得到释放的问题。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import BinaryIO


READ_SIZE = 64 * 1024


def positive_integer(value: str) -> int:
    """解析严格为正数的十进制命令行参数。"""

    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a decimal integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


class RotatingStreamWriter:
    """持续追加字节，同时限制当前文件和 N 份编号归档的大小。"""

    def __init__(self, path: Path, max_bytes: int, backups: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be greater than zero")
        if backups <= 0:
            raise ValueError("backups must be greater than zero")
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self._stream: BinaryIO | None = None
        self._size = 0

    def _backup_path(self, index: int) -> Path:
        return Path(f"{self.path}.{index}")

    def _remove_stale_backups(self) -> None:
        """删除超出新保留数量或新大小上限的旧编号归档。"""

        prefix = f"{self.path.name}."
        for candidate in self.path.parent.glob(f"{self.path.name}.*"):
            suffix = candidate.name[len(prefix) :]
            if not suffix.isdigit():
                continue
            if (
                int(suffix, 10) > self.backups
                or candidate.stat().st_size > self.max_bytes
            ):
                candidate.unlink(missing_ok=True)

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644,
        )
        os.chmod(self.path, 0o644)
        self._stream = os.fdopen(descriptor, "ab", buffering=0)
        self._size = self.path.stat().st_size

    def __enter__(self) -> "RotatingStreamWriter":
        self._remove_stale_backups()
        # run-mac.sh 正常启动前会清空当前日志；这里仍防御独立使用时遗留的超大文件，
        # 确保调整为更小上限后不会继续保留一个违反新配置的当前文件。
        if self.path.exists() and self.path.stat().st_size > self.max_bytes:
            self.path.unlink()
        self._open()
        if self._size >= self.max_bytes:
            self._rotate()
        return self

    def __exit__(self, *_args: object) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _rotate(self) -> None:
        """关闭自有 fd，原子移动编号归档，再重新打开当前文件。"""

        if self._stream is not None:
            self._stream.close()
            self._stream = None

        self._backup_path(self.backups).unlink(missing_ok=True)
        for index in range(self.backups - 1, 0, -1):
            source = self._backup_path(index)
            if source.exists():
                os.replace(source, self._backup_path(index + 1))
        if self.path.exists():
            os.replace(self.path, self._backup_path(1))
        self._open()

    def write(self, data: bytes) -> None:
        """完整写入字节；输入超过剩余容量时跨多个有界文件切分。"""

        if self._stream is None:
            raise RuntimeError("writer is not open")
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if self._size >= self.max_bytes:
                self._rotate()
            capacity = self.max_bytes - self._size
            piece = view[offset : offset + capacity]
            piece_offset = 0
            while piece_offset < len(piece):
                written = self._stream.write(piece[piece_offset:])
                if written is None or written <= 0:
                    raise OSError("log write made no progress")
                piece_offset += written
                self._size += written
                offset += written


def copy_stream(source: BinaryIO, writer: RotatingStreamWriter) -> None:
    """持续排空二进制输入；无缓冲落盘使 ``tail -F`` 能及时看到新日志。"""

    # BufferedReader.read(size) 可能等待攒满 size；read1() 只取管道当前已有数据，
    # 低流量日志也能立即写入，而不是积到 64 KiB 后才突然出现。
    read_available = getattr(source, "read1", source.read)
    while chunk := read_available(READ_SIZE):
        writer.write(chunk)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--max-bytes", required=True, type=positive_integer)
    parser.add_argument("--backups", required=True, type=positive_integer)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        with RotatingStreamWriter(args.path, args.max_bytes, args.backups) as writer:
            copy_stream(sys.stdin.buffer, writer)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"stream log rotator failed: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
