Build a stateful differential fuzzing engine that discovers broken access controls, IDOR vulnerabilities, and privilege escalations across multi-tenant API workflows by generating request sequences, comparing expected against actual authorization decisions, and minimizing reproducible failures.

Complete `/app/authfuzzer/` (including `generator.py`, `engine.py`, and `minimizer.py`) and read `/app/README.md` for the complete input, output, data, runtime, and development contract. It will be evaluated without network access using `./test.sh`.
