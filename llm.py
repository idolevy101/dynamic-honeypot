"""LLM provider abstraction for unrecognized-command fallback.

The shell never imports a concrete vendor SDK; all backends implement
:class:`LLMProvider`. Host OS execution is never used.
"""

from __future__ import annotations

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Final

import groq

_LOGGER = logging.getLogger(__name__)

GROQ_MODEL: Final[str] = "llama-3.1-8b-instant"
GROQ_TEMPERATURE: Final[float] = 0.1
GROQ_TIMEOUT_SECONDS: Final[float] = 3.0

_SYSTEM_PROMPT: Final[str] = """\
You are an authentic Ubuntu 22.04 LTS bash shell (GNU/Linux 5.15.0-generic x86_64).
Output raw stdout and/or stderr only. No markdown, no backticks, no conversational filler, no explanations.
This is a read-only simulation. Typical commands include whoami, uname -a, id, ps, ifconfig, and netstat.
If a command would modify the system, emit a realistic bash error instead of performing it.
Never break character.

Session:
user=root
hostname={hostname}
cwd={cwd}
directory listing={listing}
"""


def _command_not_found(command: str) -> str:
    tokens = command.split()
    name = tokens[0] if tokens else command
    return f"bash: {name}: command not found"


class LLMProvider(ABC):
    @abstractmethod
    async def generate_response(
        self,
        command: str,
        cwd: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Return simulated shell output for an unrecognized command."""


class NullLLMProvider(LLMProvider):
    """Deterministic offline fallback used when no API key is configured."""

    async def generate_response(
        self,
        command: str,
        cwd: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        _ = cwd, context
        return _command_not_found(command)


class GroqProvider(LLMProvider):
    """Async Groq backend with a hard per-request timeout and Null fallback."""

    def __init__(self, api_key: str, *, client: groq.AsyncGroq | None = None) -> None:
        self._client = client or groq.AsyncGroq(
            api_key=api_key,
            timeout=GROQ_TIMEOUT_SECONDS,
            max_retries=0,
        )
        self._null = NullLLMProvider()

    async def generate_response(
        self,
        command: str,
        cwd: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        ctx = context or {}
        hostname = str(ctx.get("hostname", "ubuntu-srv"))
        listing = ctx.get("listing", [])
        if not isinstance(listing, list):
            listing = []
        listing_text = " ".join(str(name) for name in listing)
        system_prompt = _SYSTEM_PROMPT.format(
            hostname=hostname,
            cwd=cwd,
            listing=listing_text,
        )
        try:
            completion = await asyncio.wait_for(
                self._client.chat.completions.create(
                    model=GROQ_MODEL,
                    temperature=GROQ_TEMPERATURE,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": command},
                    ],
                ),
                timeout=GROQ_TIMEOUT_SECONDS,
            )
        except (
            asyncio.TimeoutError,
            TimeoutError,
            OSError,
            groq.GroqError,
        ) as exc:
            _LOGGER.warning("Groq generate_response failed; using Null fallback: %s", exc)
            return await self._null.generate_response(command, cwd, context)

        content = completion.choices[0].message.content
        if content is None:
            return ""
        return content


def create_llm_provider() -> LLMProvider:
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return NullLLMProvider()
    return GroqProvider(api_key=api_key)
