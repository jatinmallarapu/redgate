# Design decisions

## Use inspectable verdicts for the initial gate

Canary strings, proxy markers, and structured tool arguments produce evidence that can be inspected without an LLM judge. Exact checks can miss paraphrases and encoded leaks. A refusal that quotes a forbidden marker can trigger a false positive. A learned judge would need disagreement analysis against labeled cases before it could affect a release decision.

## Separate evidence from the release policy

The evaluator produces case-level facts. A customer policy converts those facts into a decision. This lets two customers evaluate the same run without repeating inference. Keep policy files and suite definitions in trusted version control. Required suites are identified by name, so production gates should also pin expected suite digests.

## Persist complete runs atomically

A failed or partial run must not look like a passing run. The runner creates a validated record only after every case is scored, then renames a temporary file into place. The gate checks outcome completeness again when loading a run. Production use would need authenticated artifact storage and a trusted release identity.

## Establish a local baseline before distributing execution

The runner evaluates independent cases through a small target interface. Ray can distribute those cases while keeping model initialization local to each worker. Measure worker startup, target saturation, and serialization separately when comparing throughput. A control API and run store will need explicit job lifecycle, idempotency, and failure handling.

## Next milestones

1. Ray workers and MLflow tracking, with a real model baseline and a measured worker scaling experiment.
2. FastAPI control plane and Docker Compose development stack.
3. Trained ONNX guard with held-out classifier evaluation, Prometheus metrics, and a measured load test.
4. Helm and kind deployment, with verified smoke checks and operational documentation.
