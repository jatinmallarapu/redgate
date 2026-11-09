# Results

The installed CLI was exercised locally on Windows with Python 3.12. The bundled targets are scripted fixtures. These numbers describe the smoke checks.

| Run | Cases | Observed result |
| --- | ---: | --- |
| Resistant fixture, all suites | 8 | Zero successful attacks. Acme Bank policy passed. |
| Vulnerable fixture, direct injection | 3 | Three canary leaks. Default policy blocked with exit code 2. |
| Vulnerable fixture, indirect injection | 2 | Two forbidden email calls requested. |
| Same indirect cases with spotlighting | 2 | Zero forbidden email calls requested. |
| Replay of the resistant fixture | 8 | Configuration hash, dataset fingerprint, and every verdict matched. |

Pytest reported 8 passing tests and 86.07% statement coverage. Real-model robustness, inference latency, worker scaling, and guard accuracy require separate experiments. The spotlighting behavior is scripted into the mock target.
