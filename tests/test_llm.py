from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import groq
import pytest

from llm import GroqProvider, NullLLMProvider, create_llm_provider
from vfs import HOSTNAME


async def test_null_provider_command_not_found() -> None:
    provider = NullLLMProvider()
    assert await provider.generate_response("whoami", "/root") == (
        "bash: whoami: command not found"
    )
    assert await provider.generate_response("uname -a", "/root") == (
        "bash: uname: command not found"
    )
    assert await provider.generate_response("", "/root") == "bash: : command not found"


def test_create_llm_provider_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert isinstance(create_llm_provider(), NullLLMProvider)


def test_create_llm_provider_empty_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "   ")
    assert isinstance(create_llm_provider(), NullLLMProvider)


def test_create_llm_provider_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    provider = create_llm_provider()
    assert isinstance(provider, GroqProvider)


async def test_groq_provider_returns_model_content() -> None:
    client = MagicMock()
    completion = MagicMock()
    completion.choices = [MagicMock()]
    completion.choices[0].message.content = "root\n"
    client.chat.completions.create = AsyncMock(return_value=completion)
    provider = GroqProvider("gsk_test", client=client)

    output = await provider.generate_response(
        "whoami",
        "/root",
        {"hostname": HOSTNAME, "user": "root", "listing": [".bash_history"]},
    )
    assert output == "root\n"
    client.chat.completions.create.assert_awaited_once()
    kwargs = client.chat.completions.create.await_args.kwargs
    assert kwargs["model"] == "llama-3.1-8b-instant"
    assert kwargs["temperature"] == 0.1


async def test_groq_provider_falls_back_on_api_error() -> None:
    client = MagicMock()
    client.chat.completions.create = AsyncMock(side_effect=groq.GroqError("boom"))
    provider = GroqProvider("gsk_test", client=client)
    output = await provider.generate_response("id", "/root")
    assert output == "bash: id: command not found"


async def test_groq_provider_falls_back_on_timeout() -> None:
    client = MagicMock()
    client.chat.completions.create = AsyncMock(side_effect=TimeoutError())
    provider = GroqProvider("gsk_test", client=client)
    output = await provider.generate_response("ps", "/tmp")
    assert output == "bash: ps: command not found"
