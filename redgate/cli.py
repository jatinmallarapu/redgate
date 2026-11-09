import re
from pathlib import Path
from typing import Annotated, TypeVar
from uuid import UUID

import typer
import yaml
from pydantic import ValidationError

from .engine import SYSTEM_PROMPT, evaluate
from .runs import Run, gate, load_run, save_run
from .schema import Manifest, Policy, Record, Suite, TargetSpec
from .targets import TargetError

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
CONFIGS = Path(__file__).parent / "configs"
RunDirectory = Annotated[Path, typer.Option(envvar="REDGATE_RUN_DIR")]
Config = TypeVar("Config", bound=Record)


def load_config(model: type[Config], group: str, name: str) -> Config:
    path = Path(name)
    if not path.suffix:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            raise ValueError("use a built-in slug or a path to a YAML file")
        path = CONFIGS / group / f"{name}.yaml"
    return model.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def print_run(run: Run) -> None:
    typer.echo(f"run_id: {run.id}")
    typer.echo(f"config_hash: {run.config_hash}")
    typer.echo(f"dataset_fingerprint: {run.dataset_fingerprint}")
    for metric, value in sorted(run.metrics.items()):
        typer.echo(f"{metric}: {value:.6g}")


def print_gate(run: Run, policy: Policy) -> None:
    reasons = gate(run, policy)
    typer.echo(f"{'BLOCK' if reasons else 'PASS'} ({policy.customer})")
    for reason in reasons:
        typer.echo(f"  - {reason}")
    if reasons:
        raise typer.Exit(2)


def fail(exc: Exception) -> None:
    if isinstance(exc, ValidationError):
        message = exc.json(include_input=False, include_context=False, include_url=False)
    elif isinstance(exc, yaml.YAMLError):
        message = "could not parse YAML configuration"
    else:
        message = str(exc)
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(1)


@app.command()
def run(
    suite: Annotated[list[str], typer.Option(help="Suite slug or YAML path. Repeatable.")],
    target: Annotated[str, typer.Option(help="Target slug or YAML path.")],
    policy: Annotated[str | None, typer.Option(help="Apply a policy after saving the run.")] = None,
    seed: int = 42,
    spotlight: bool = False,
    run_dir: RunDirectory = Path(".redgate/runs"),
) -> None:
    """Evaluate a target and save a redacted run."""
    try:
        suites = [load_config(Suite, "suites", name) for name in suite]
        if len({item.name for item in suites}) != len(suites):
            raise ValueError("suite names must be unique")
        release_policy = load_config(Policy, "policies", policy) if policy else None
        manifest = Manifest(
            suites=suites,
            target=load_config(TargetSpec, "targets", target),
            seed=seed,
            spotlight=spotlight,
            system_prompt=SYSTEM_PROMPT,
        )
        result = save_run(run_dir, manifest, evaluate(manifest))
    except (OSError, TargetError, ValueError, yaml.YAMLError) as exc:
        fail(exc)
        return
    print_run(result)
    if release_policy:
        print_gate(result, release_policy)


@app.command("gate")
def gate_command(
    run_id: Annotated[UUID, typer.Option("--run")],
    policy: Annotated[str, typer.Option()],
    run_dir: RunDirectory = Path(".redgate/runs"),
) -> None:
    """Apply a policy to a completed run."""
    try:
        result = load_run(run_dir, run_id)
        release_policy = load_config(Policy, "policies", policy)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        fail(exc)
        return
    print_gate(result, release_policy)


@app.command()
def reproduce(run_id: UUID, run_dir: RunDirectory = Path(".redgate/runs")) -> None:
    """Rerun the captured manifest and compare attack verdicts."""
    try:
        original = load_run(run_dir, run_id)
        result = save_run(run_dir, original.manifest, evaluate(original.manifest))
    except (OSError, TargetError, ValueError) as exc:
        fail(exc)
        return
    print_run(result)
    verdicts_match = all(
        (before.attack_success, before.canary_leak) == (after.attack_success, after.canary_leak)
        for before, after in zip(original.outcomes, result.outcomes, strict=True)
    )
    typer.echo(f"verdicts_match: {str(verdicts_match).lower()}")
    if not verdicts_match:
        raise typer.Exit(3)
