import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Self
from uuid import UUID, uuid4

from pydantic import model_validator

from .engine import fingerprint, summarize
from .schema import Manifest, Metric, Outcome, Policy, Record


class Run(Record):
    id: UUID
    config_hash: str
    dataset_fingerprint: str
    manifest: Manifest
    outcomes: list[Outcome]

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        expected = [
            (suite.name, suite.category, case.id)
            for suite in self.manifest.suites
            for case in suite.cases
        ]
        actual = [(row.suite, row.category, row.case_id) for row in self.outcomes]
        if actual != expected or len(expected) != len(set(expected)):
            raise ValueError("outcomes must match every manifest case exactly once")
        if self.config_hash != fingerprint(self.manifest.model_dump(mode="json")):
            raise ValueError("manifest hash mismatch")
        if self.dataset_fingerprint != fingerprint(
            [suite.model_dump(mode="json") for suite in self.manifest.suites]
        ):
            raise ValueError("dataset fingerprint mismatch")
        return self

    @property
    def metrics(self) -> dict[Metric, float]:
        return summarize(self.outcomes)


def save_run(directory: Path, manifest: Manifest, outcomes: list[Outcome]) -> Run:
    run = Run(
        id=uuid4(),
        config_hash=fingerprint(manifest.model_dump(mode="json")),
        dataset_fingerprint=fingerprint(
            [suite.model_dump(mode="json") for suite in manifest.suites]
        ),
        manifest=manifest,
        outcomes=outcomes,
    )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run.id}.json"
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(run.model_dump_json(indent=2))
            stream.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return run


def load_run(directory: Path, run_id: UUID) -> Run:
    run = Run.model_validate_json((directory / f"{run_id}.json").read_bytes())
    if run.id != run_id:
        raise ValueError("stored run ID does not match the requested run")
    return run


def gate(run: Run, policy: Policy) -> list[str]:
    complete = {suite.name for suite in run.manifest.suites}
    reasons = [
        f"required suite missing: {name}" for name in sorted(policy.required_suites - complete)
    ]
    metrics = run.metrics
    for metric, limit in sorted(policy.gates.items()):
        if metric not in metrics:
            reasons.append(f"metric unavailable: {metric}")
        elif metrics[metric] > limit.max:
            reasons.append(f"{metric} = {metrics[metric]:.6g} exceeds {limit.max:.6g}")
    return reasons
