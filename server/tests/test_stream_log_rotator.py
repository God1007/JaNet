#!/usr/bin/env python3
"""Server 零依赖流式日志轮转器的契约测试。"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROTATOR = Path(__file__).parents[1] / "tools" / "stream_log_rotator.py"


class StreamLogRotatorTest(unittest.TestCase):
    def run_rotator(
        self,
        path: Path,
        payload: bytes,
        *,
        max_bytes: int,
        backups: int,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(ROTATOR),
                "--path",
                str(path),
                "--max-bytes",
                str(max_bytes),
                "--backups",
                str(backups),
            ],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_limits_each_file_and_retains_only_newest_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            payload = bytes(range(100))

            result = self.run_rotator(path, payload, max_bytes=32, backups=2)

            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertLessEqual(path.stat().st_size, 32)
            self.assertLessEqual(Path(f"{path}.1").stat().st_size, 32)
            self.assertLessEqual(Path(f"{path}.2").stat().st_size, 32)
            self.assertFalse(Path(f"{path}.3").exists())
            retained = (
                Path(f"{path}.2").read_bytes()
                + Path(f"{path}.1").read_bytes()
                + path.read_bytes()
            )
            self.assertEqual(retained, payload[-len(retained) :])

    def test_prunes_backups_above_new_retention_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            Path(f"{path}.1").write_bytes(b"kept")
            Path(f"{path}.2").write_bytes(b"stale")
            Path(f"{path}.janet-follow.pid").write_bytes(b"manifest")

            result = self.run_rotator(path, b"new", max_bytes=16, backups=1)

            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(Path(f"{path}.1").exists())
            self.assertFalse(Path(f"{path}.2").exists())
            self.assertTrue(Path(f"{path}.janet-follow.pid").exists())

    def test_smaller_configuration_drops_oversized_old_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            path.write_bytes(b"oversized-current")
            Path(f"{path}.1").write_bytes(b"oversized-backup")

            result = self.run_rotator(path, b"new", max_bytes=4, backups=1)

            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(path.read_bytes(), b"new")
            self.assertFalse(Path(f"{path}.1").exists())

    def test_rejects_non_positive_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            result = self.run_rotator(path, b"data", max_bytes=0, backups=1)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"greater than zero", result.stderr)

    def test_small_live_write_is_visible_before_stdin_closes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.log"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(ROTATOR),
                    "--path",
                    str(path),
                    "--max-bytes",
                    "1024",
                    "--backups",
                    "1",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                self.assertIsNotNone(process.stdin)
                process.stdin.write(b"live-now\n")
                process.stdin.flush()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if path.exists() and path.read_bytes() == b"live-now\n":
                        break
                    time.sleep(0.02)
                self.assertEqual(path.read_bytes(), b"live-now\n")
                self.assertIsNone(process.poll(), "rotator exited before input closed")
                process.stdin.close()
                self.assertEqual(process.wait(timeout=2), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
