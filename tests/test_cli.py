import json
from pathlib import Path
from uuid import UUID

from typer.testing import CliRunner

from redgate.cli import app
from redgate.runs import load_run
from redgate.schema import CANARY, Metric

runner = CliRunner()


def invoke_run(path: Path, model: str, *options: str) -> tuple[int, str, UUID]:
    result = runner.invoke(
        app,
        [
            "run", "--suite", "injection-basic", "--target", model,
            "--run-dir", str(path), *options,
        ],
    )
    id_line = next(line for line in result.output.splitlines() if line.startswith("run_id: "))
    return result.exit_code, result.output, UUID(id_line.removeprefix("run_id: "))


def test_gate_and_redacted_artifact(tmp_path: Path) -> None:
    code, output, run_id = invoke_run(tmp_path, "mock-vulnerable", "--policy", "default")
    assert code == 2
    assert "BLOCK (default)" in output
    assert "prompt_injection_asr = 1" in output
    data = json.loads((tmp_path / f"{run_id}.json").read_text())
    assert "text" not in data["outcomes"][0]
    assert CANARY not in json.dumps(data["outcomes"])

    result = runner.invoke(
        app, ["gate", "--run", str(run_id), "--policy", "acme-bank", "--run-dir", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "required suite missing: agent-indirect" in result.output
    assert "metric unavailable: jailbreak_asr" in result.output


def test_full_suite_pass_and_reproduce(tmp_path: Path) -> None:
    code, output, run_id = invoke_run(
        tmp_path, "mock-resistant", "--suite", "agent-indirect", "--suite", "jailbreak-proxy",
        "--policy", "acme-bank",
    )
    assert code == 0
    assert "PASS (acme-bank)" in output
    original = load_run(tmp_path, run_id)
    assert len(original.outcomes) == 8
    result = runner.invoke(app, ["reproduce", str(run_id), "--run-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "verdicts_match: true" in result.output
    assert original.config_hash in result.output
    assert original.dataset_fingerprint in result.output
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_spotlighting_in_synthetic_agent(tmp_path: Path) -> None:
    _, _, unprotected = invoke_run(tmp_path, "mock-vulnerable", "--suite", "agent-indirect")
    _, _, protected = invoke_run(
        tmp_path, "mock-vulnerable", "--suite", "agent-indirect", "--spotlight"
    )
    assert load_run(tmp_path, unprotected).metrics[Metric.AGENT_INDIRECT_ASR] == 1
    assert load_run(tmp_path, protected).metrics[Metric.AGENT_INDIRECT_ASR] == 0


def test_invalid_config_saves_nothing(tmp_path: Path) -> None:
    suite = tmp_path / "invalid.yaml"
    suite.write_text("name: bad\ncategory: prompt_injection\ncases: []\n")
    result = runner.invoke(
        app,
        ["run", "--suite", str(suite), "--target", "mock-resistant", "--run-dir", str(tmp_path)],
    )
    assert result.exit_code == 1
    assert "Error:" in result.output
    assert not list(tmp_path.glob("*.json"))


def test_incomplete_evidence_is_rejected(tmp_path: Path) -> None:
    _, _, run_id = invoke_run(tmp_path, "mock-resistant")
    path = tmp_path / f"{run_id}.json"
    data = json.loads(path.read_text())
    data["outcomes"].pop()
    path.write_text(json.dumps(data))
    result = runner.invoke(
        app, ["gate", "--run", str(run_id), "--policy", "default", "--run-dir", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "outcomes must match" in result.output
