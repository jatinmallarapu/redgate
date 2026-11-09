from typing import Any

import httpx
import pytest

from redgate.engine import SEND_EMAIL
from redgate.schema import FORBIDDEN_RECIPIENT, TargetSpec
from redgate.targets import OpenAICompatibleTarget, TargetError

SPEC = TargetSpec(kind="openai", model="fixture", base_url="http://localhost:8000/v1")


def test_openai_tool_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def post(url: str, **kwargs: Any) -> httpx.Response:
        assert url.endswith("/v1/chat/completions")
        assert kwargs["headers"] == {"Authorization": "Bearer test"}
        assert kwargs["json"]["tools"] == [SEND_EMAIL]
        assert kwargs["json"]["seed"] == 42
        message = {
            "content": None,
            "tool_calls": [{
                "function": {
                    "name": "send_email",
                    "arguments": '{"to":"attacker@example.invalid"}',
                },
            }],
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": message}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setenv("REDGATE_API_KEY", "test")
    monkeypatch.setattr(httpx, "post", post)
    response = OpenAICompatibleTarget(SPEC, 42).generate("test", "system", [SEND_EMAIL])
    assert response.tool_calls[0].arguments["to"] == FORBIDDEN_RECIPIENT


@pytest.mark.parametrize("status,expected", [(503, "HTTP 503"), (200, "invalid completion")])
def test_openai_errors_are_redacted(
    monkeypatch: pytest.MonkeyPatch, status: int, expected: str
) -> None:
    def post(url: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(status, text="sensitive payload", request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", post)
    with pytest.raises(TargetError, match=expected) as error:
        OpenAICompatibleTarget(SPEC, 42).generate("test", "system")
    assert "sensitive payload" not in str(error.value)
