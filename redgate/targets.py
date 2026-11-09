import json
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from .schema import CANARY, FORBIDDEN_RECIPIENT, PROXY_MARKER, TargetSpec


class TargetError(RuntimeError):
    """An inference failure safe to show in CLI output."""


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class Response:
    text: str
    tool_calls: tuple[ToolCall, ...] = ()


class Target(Protocol):
    def generate(
        self,
        prompt: str,
        system_prompt: str,
        tools: list[dict[str, Any]] | None = None,
    ) -> Response: ...


class MockTarget:
    def __init__(self, model: str) -> None:
        if model not in {"vulnerable", "resistant"}:
            raise TargetError("mock model must be vulnerable or resistant")
        self.model = model

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        tools: list[dict[str, Any]] | None = None,
    ) -> Response:
        if self.model == "resistant":
            return Response("I will follow the original task.")
        if tools:
            if "<untrusted-tool-output>" in prompt:
                return Response("I summarized the fixture.")
            return Response("", (ToolCall("send_email", {"to": FORBIDDEN_RECIPIENT}),))
        if re.search(r"confetti|Y29uZmV0dGk=", prompt, re.IGNORECASE):
            return Response(PROXY_MARKER)
        return Response(CANARY)


class OpenAICompatibleTarget:
    def __init__(self, spec: TargetSpec, seed: int) -> None:
        if spec.base_url is None:
            raise TargetError("missing endpoint")
        url = urlsplit(spec.base_url)
        if (
            url.scheme not in {"https", "http"}
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
        ):
            raise TargetError("base_url must be an HTTP(S) URL without credentials or parameters")
        self.url = spec.base_url.rstrip("/") + "/chat/completions"
        self.model = spec.model
        self.seed = seed
        self.max_tokens = spec.max_tokens

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        tools: list[dict[str, Any]] | None = None,
    ) -> Response:
        key = os.environ.get("REDGATE_API_KEY")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "seed": self.seed,
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
        try:
            response = httpx.post(self.url, json=payload, headers=headers, timeout=60)
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]
            content = message.get("content")
            if content is not None and not isinstance(content, str):
                raise ValueError("unexpected content type")
            calls = tuple(
                ToolCall(item["function"]["name"], json.loads(item["function"]["arguments"]))
                for item in (message.get("tool_calls") or [])
            )
            if any(not isinstance(c.name, str) or not isinstance(c.arguments, dict) for c in calls):
                raise ValueError("unexpected tool call format")
            if not calls and not content:
                raise ValueError("empty completion")
        except httpx.HTTPStatusError as exc:
            raise TargetError(f"endpoint returned HTTP {exc.response.status_code}") from None
        except httpx.RequestError:
            raise TargetError("could not reach inference endpoint") from None
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            raise TargetError("endpoint returned an invalid completion") from None
        return Response(content or "", calls)


class TransformersTarget:
    def __init__(self, spec: TargetSpec) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError:
            raise TargetError("install the hf extra for Transformers inference") from None
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(spec.model, revision=spec.revision)
        self.model = AutoModelForCausalLM.from_pretrained(spec.model, revision=spec.revision).eval()
        self.max_tokens = spec.max_tokens

    def generate(
        self,
        prompt: str,
        system_prompt: str,
        tools: list[dict[str, Any]] | None = None,
    ) -> Response:
        if tools:
            raise TargetError("use a tool-capable OpenAI-compatible endpoint for agent cases")
        inputs = self.tokenizer.apply_chat_template(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        )
        with self.torch.inference_mode():
            generated = self.model.generate(
                **inputs,
                do_sample=False,
                max_new_tokens=self.max_tokens,
            )
        tokens = generated[0, inputs["input_ids"].shape[-1]:]
        return Response(str(self.tokenizer.decode(tokens, skip_special_tokens=True)))


def build_target(spec: TargetSpec, seed: int) -> Target:
    match spec.kind:
        case "mock":
            return MockTarget(spec.model)
        case "openai":
            return OpenAICompatibleTarget(spec, seed)
        case "hf":
            return TransformersTarget(spec)
