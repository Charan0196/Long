# Long - Stateful Differential Fuzzer for Multi-Tenant API Authorization

A FrontierSWE long-horizon benchmark task evaluating autonomous coding agents on red-teaming, differential fuzzing, and access control testing in stateful multi-tenant APIs.

## Task Overview

- **Task Name**: `security/stateful-api-auth-fuzzer`
- **Schema Version**: `2.0`
- **Category**: `cybersecurity`
- **Difficulty**: `hard`
- **Time Limit**: 20 hours (`72000.0`s)

## Evaluation & Verification

- **Harbor Verification**: Tested with Harbor using `environment_mode = "separate"`
- **Static QC Verification**: Passes `frontierswe-check.py` with 0 failures and 0 warnings:
  ```
  FSWE-CHECK v1 PASS security/stateful-api-auth-fuzzer c9f182e7df28
  ```
- **Reward Contract**:
  - `harbor run -p . -a nop`: Mean `0.000`
  - `harbor run -p . -a oracle`: Mean `1.000`
