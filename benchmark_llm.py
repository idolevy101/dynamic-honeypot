#!/usr/bin/env python3
"""End-to-end shell dispatcher latency benchmark. Not collected by pytest."""

from __future__ import annotations

import argparse
import asyncio
import os
import shlex
import sys
import time
from dataclasses import dataclass

from dotenv import load_dotenv

from llm import GROQ_MODEL, GroqProvider
from shell import Shell, lookup_static_output
from vfs import VirtualFileSystem

_WARMUP_COMMAND = "whoami"
_DEFAULT_COMMANDS = (
    "whoami",
    "uname -a",
    "id",
    "ps aux",
    "ps -ef",
    "df -h",
    "free -m",
    "uptime",
)
_PREVIEW_CHARS = 60


@dataclass
class Sample:
    command: str
    path: str
    latency_ms: float
    output_len: int
    preview: str
    error: str | None = None


def _path_for(command: str) -> str:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return "llm"
    return "static" if lookup_static_output(tokens) is not None else "llm"


def _preview(text: str, limit: int = _PREVIEW_CHARS) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


async def _timed_execute(shell: Shell, command: str) -> Sample:
    path = _path_for(command)
    started = time.perf_counter()
    try:
        result = await shell.execute(command)
        output = result.output
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return Sample(
            command=command,
            path=path,
            latency_ms=elapsed_ms,
            output_len=0,
            preview="",
            error=type(exc).__name__,
        )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return Sample(
        command=command,
        path=path,
        latency_ms=elapsed_ms,
        output_len=len(output),
        preview=_preview(output),
    )


def _print_table(samples: list[Sample]) -> None:
    cmd_w = max(len("Command"), max(len(s.command) for s in samples))
    path_w = max(len("Path"), max(len(s.path) for s in samples))
    prev_w = max(len("Preview"), max(len(s.preview or s.error or "") for s in samples))
    header = (
        f"{'Command':<{cmd_w}}  {'Path':<{path_w}}  {'Time (ms)':>9}  "
        f"{'Len':>5}  {'Preview':<{prev_w}}"
    )
    print(header)
    print("-" * len(header))
    for sample in samples:
        note = sample.error if sample.error else sample.preview
        print(
            f"{sample.command:<{cmd_w}}  {sample.path:<{path_w}}  "
            f"{sample.latency_ms:>9.1f}  {sample.output_len:>5}  {note:<{prev_w}}"
        )


def _print_stats(samples: list[Sample]) -> None:
    print()
    for label, group in (
        ("static", [s for s in samples if s.path == "static"]),
        ("llm", [s for s in samples if s.path == "llm"]),
        ("all", samples),
    ):
        if not group:
            continue
        latencies = [s.latency_ms for s in group]
        print(
            f"Summary {label:<6}  n={len(latencies)}  "
            f"min={min(latencies):.1f} ms  "
            f"max={max(latencies):.1f} ms  "
            f"avg={sum(latencies) / len(latencies):.1f} ms"
        )
    failed = [s for s in samples if s.error]
    if failed:
        print(f"Errors   {len(failed)}/{len(samples)} calls raised after provider fallback")


async def _run(commands: tuple[str, ...]) -> int:
    load_dotenv()
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        print("GROQ_API_KEY is not set. Add it to .env and retry.", file=sys.stderr)
        return 1

    shell = Shell(VirtualFileSystem(), llm_provider=GroqProvider(api_key))
    print(f"Model: {GROQ_MODEL}")
    print("Router: Shell.execute (static templates before Groq)")
    print(f"Warm-up: {_WARMUP_COMMAND}")
    warmup = await _timed_execute(shell, _WARMUP_COMMAND)
    if warmup.error:
        print(f"Warm-up failed ({warmup.error}) after {warmup.latency_ms:.1f} ms")
    else:
        print(f"Warm-up completed in {warmup.latency_ms:.1f} ms")
    print()

    samples = [await _timed_execute(shell, command) for command in commands]
    _print_table(samples)
    _print_stats(samples)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark Shell dispatcher latency (static templates vs Groq)"
    )
    parser.add_argument(
        "commands",
        nargs="*",
        default=list(_DEFAULT_COMMANDS),
        help="Commands to time after warm-up (default: recon mix of static and LLM)",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(tuple(args.commands))))


if __name__ == "__main__":
    main()
