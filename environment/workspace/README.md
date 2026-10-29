# Stateful API Authorization Fuzzer

## Mission

You are tasked with building a stateful differential fuzzing engine in `authfuzzer/` to discover authorization vulnerabilities in multi-tenant REST APIs.

In stateful systems, authorization depends on dynamic resource lifecycles:
- Creating documents
- Sharing documents (viewer vs. editor)
- Revoking permissions
- Transferring ownership
- Deleting and recreating resources
- Enforcing strict tenant boundaries

Stateless scanners miss bugs caused by operation order and permission state transitions. Your testing engine must generate valid, multi-step scenarios, evaluate API responses against the ground-truth authorization policy in `api/policy.py`, identify violations, minimize reproduction sequences, and export structured JSON reports.

---

## Directory Layout

```
/app/
├── README.md                 # This specification document
├── pyproject.toml            # Python package setup
├── requirements.txt          # Python dependencies
├── api/                      # Synthetic API under test
│   ├── models.py             # Domain models (Tenant, User, Document, APIRequest, APIResponse)
│   ├── policy.py             # Formal authorization policy (Ground Truth)
│   ├── client.py             # Target interface & factory (`get_target`)
│   ├── reference.py          # Clean reference implementation
│   └── faulty/               # Deliberately faulty implementations
│       ├── idor.py
│       ├── cross_tenant.py
│       ├── guest_escalation.py
│       ├── stale_share.py
│       └── transfer_retention.py
└── authfuzzer/               # The package you must complete
    ├── cli.py                # Command-line interface
    ├── engine.py             # Differential execution engine
    ├── generator.py          # Stateful scenario generator
    ├── minimizer.py          # Failure sequence minimizer (Delta Debugging)
    ├── models.py             # Fuzzing data models
    ├── reporter.py           # JSON report serializer/deserializer
    └── state.py              # Simulated state tracker
```

---

## Technical Specifications

### 1. The Synthetic API Contract

The API represents a document workspace:
- **Tenants**: Independent organizations (`org_alpha`, `org_beta`). Strict tenant isolation applies: no cross-tenant reading, writing, sharing, or deleting.
- **Roles**:
  - `admin`: Full administrative access to all documents in their tenant.
  - `member`: Can create documents, manage owned documents, and access shared documents.
  - `guest`: Cannot create documents. Can only access documents explicitly shared with them.
- **Endpoints**:
  - `POST /api/v1/documents` (`{"id": str, "title": str, "content": str}`) -> `201 Created`
  - `GET /api/v1/documents/{doc_id}` -> `200 OK`
  - `PUT /api/v1/documents/{doc_id}` (`{"content": str}`) -> `200 OK`
  - `DELETE /api/v1/documents/{doc_id}` -> `200 OK`
  - `POST /api/v1/documents/{doc_id}/share` (`{"target_user_id": str, "access_level": "viewer"|"editor"}`) -> `200 OK`
  - `POST /api/v1/documents/{doc_id}/revoke` (`{"target_user_id": str}`) -> `200 OK`
  - `POST /api/v1/documents/{doc_id}/transfer` (`{"new_owner_id": str}`) -> `200 OK`

All requests must provide:
- `X-Tenant-Id`: Active tenant ID
- `X-User-Id`: Calling user ID

### 2. Scenario Generation (`authfuzzer/generator.py`)
- Given tenants, users, and an integer `seed`, produce deterministic multi-step request sequences.
- Track resource lifecycles: create documents before reading/updating/sharing them.
- Inject probes targeting common vulnerability classes:
  - Cross-tenant reads and updates
  - Same-tenant unauthorized member accesses
  - Guest creation and unauthorized editing
  - Deleting documents and testing if shares persist upon re-creation
  - Transferring ownership and verifying old owner loses privileges

### 3. Differential Engine (`authfuzzer/engine.py`)
- Execute scenarios against the target (`BaseTarget.dispatch(request)`).
- For each step, compute expected decision via `AuthorizationPolicy.evaluate(request, users, documents)`.
- Classify discrepancies:
  - `CROSS_TENANT_ACCESS`: Target returned 200 on cross-tenant operation.
  - `IDOR_HORIZONTAL`: Target returned 200 to unauthorized member in same tenant.
  - `GUEST_PRIVILEGE_ESCALATION`: Target permitted guest creation or unauthorized guest modification.
  - `STALE_ACL_ACCESS`: Target granted access to resurrected/deleted document via stale shares.
  - `TRANSFERRED_OWNER_RETENTION`: Target permitted former owner to delete after transfer.
- When an anomaly is discovered, record the step, expected decision, actual decision, and original sequence.

### 4. Failure Minimization (`authfuzzer/minimizer.py`)
- Given a failing scenario of length $N$, find the minimal subsequence $M \subseteq N$ that still reproduces the exact violation at the final action.
- Use Delta Debugging (ddmin):
  - Retain the terminal failing action.
  - Test omitting earlier non-essential actions (e.g. unrelated reads, updates to other documents).
  - Verify that replaying the minimized sequence against a reset target reproduces the exact failure status code.

### 5. CLI Interface (`python -m authfuzzer.cli`)
```bash
# Run fuzzing
python -m authfuzzer.cli fuzz \
  --target <target_name> \
  --seed <int> \
  --scenarios <int> \
  --max-steps <int> \
  --output <report_path.json> \
  [--minimize]

# Replay reproduction
python -m authfuzzer.cli replay \
  --target <target_name> \
  --repro <report_path.json>
```

---

## Verifier Targets

Your fuzzer will be evaluated against:
1. `reference`: Perfectly compliant target. Your fuzzer must report **0 violations**.
2. `idor`: Deliberate horizontal IDOR.
3. `cross_tenant`: Deliberate cross-tenant leak.
4. `guest_escalation`: Deliberate guest role escalation.
5. `stale_share`: Deliberate stale ACL reuse after deletion.
6. `transfer_retention`: Deliberate delete privilege retention after ownership transfer.
