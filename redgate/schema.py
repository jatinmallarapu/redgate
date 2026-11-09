from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Slug = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]*$")]
Milliseconds = Annotated[float, Field(ge=0, allow_inf_nan=False)]
CANARY = "REDGATE_SYNTHETIC_CANARY_74F9"
PROXY_MARKER = "REDGATE_PROXY_CONFETTI"
FORBIDDEN_RECIPIENT = "attacker@example.invalid"


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Category(StrEnum):
    INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    INDIRECT = "agent_indirect"


class Case(Record):
    id: Slug
    prompt: Annotated[str, Field(min_length=1)]
    tool: Literal["read_email", "search_docs"] | None = None
    tool_output: Annotated[str, Field(min_length=1)] | None = None


class Suite(Record):
    name: Slug
    category: Category
    cases: Annotated[list[Case], Field(min_length=1)]

    @model_validator(mode="after")
    def check_cases(self) -> Self:
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("case IDs must be unique within a suite")
        for case in self.cases:
            if self.category == Category.INDIRECT:
                if case.tool is None or case.tool_output is None:
                    raise ValueError("indirect cases require a tool and its synthetic output")
            elif case.tool is not None or case.tool_output is not None:
                raise ValueError("tool fixtures belong in an indirect suite")
        return self


class TargetSpec(Record):
    kind: Literal["mock", "openai", "hf"]
    model: Annotated[str, Field(min_length=1)]
    base_url: str | None = None
    revision: str | None = None
    max_tokens: Annotated[int, Field(gt=0, le=4096)] = 128

    @model_validator(mode="after")
    def check_connection(self) -> Self:
        if self.kind == "openai" and not self.base_url:
            raise ValueError("OpenAI-compatible targets require base_url")
        return self


class Metric(StrEnum):
    PROMPT_INJECTION_ASR = "prompt_injection_asr"
    JAILBREAK_ASR = "jailbreak_asr"
    AGENT_INDIRECT_ASR = "agent_indirect_asr"
    CANARY_LEAK = "canary_leak"
    P95_LATENCY_MS = "p95_latency_ms"


class Limit(Record):
    max: Annotated[float, Field(ge=0, allow_inf_nan=False, strict=True)]


class Policy(Record):
    customer: Slug
    gates: Annotated[dict[Metric, Limit], Field(min_length=1)]
    required_suites: Annotated[set[Slug], Field(min_length=1)]

    @model_validator(mode="after")
    def check_rates(self) -> Self:
        for metric, limit in self.gates.items():
            if metric != Metric.P95_LATENCY_MS and limit.max > 1:
                raise ValueError(f"{metric} max must be between 0 and 1")
        return self


class Outcome(Record):
    suite: Slug
    case_id: Slug
    category: Category
    latency_ms: Milliseconds
    attack_success: bool
    canary_leak: bool
    response_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Manifest(Record):
    protocol: Literal[1] = 1
    suites: Annotated[list[Suite], Field(min_length=1)]
    target: TargetSpec
    seed: int
    spotlight: bool
    system_prompt: str
    # Suites contain synthetic fixtures. Credentials are resolved from the environment.
