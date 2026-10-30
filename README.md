# Sovereign AI Data Enclave (build guide)

Private research repo. A sovereign AI data enclave: Keycloak identity, OPA and OpenTDF policy, HSM-backed keys, label-filtered pgvector retrieval, and audit logs. Retrieval-augmented AI over labelled data, where **authorisation happens before retrieval**.

Full write-up and phase plan: [`docs/project-page.md`](docs/project-page.md)

## What's here

| File | Phase | Purpose |
|---|---|---|
| `enclave/labels.py` | 2 | Canadian levels (U, Protected A/B/C, C, S, TS), compartments, release caveats, **portion markings** `(PB)` and `(S//REL TO CAN, USA)`, dominance check |
| `policy/enclave.rego` | 2 | The same rule as OPA policy |
| `enclave/keys.py` | 4 | **Envelope encryption**: a data key per label bucket wrapped by a KEK (HSM placeholder), label bound as AES-GCM associated data, crypto-shredding |
| `enclave/store.py` | 3, 5 | Ingest (per-paragraph labels, encrypted chunks) and search that **filters by label, then ranks, then decrypts**, with the query hashed in the audit log |
| `enclave/guard.py` | 1 | OWASP LLM01 indirect-injection screening, output inherits the highest source label, prompt that treats documents as data |
| `enclave/leakage.py` | 6 | **Canary tokens** plus a subject × query sweep: zero leaks while authorised recall still works |
| `enclave/audit.py` | 5 | Hash-chained audit log |
| `deploy/compose.yaml` | 7 | Keycloak, OPA, pgvector, SoftHSM on an internal-only network |

## Quickstart

```bash
pip install -r requirements.txt
python demo.py && python -m unittest -v
```

## Next steps
- [ ] Replace `LocalKEK` with PKCS#11 (SoftHSM2, then YubiHSM2): `C_WrapKey`/`C_UnwrapKey`
- [ ] pgvector table with `level`, `compartments[]`, `releasable_to[]` columns and **Postgres row-level security** driven by the Keycloak token claims, so the database enforces the filter too
- [ ] A local LLM inside the enclave (llama.cpp or Ollama, no egress), with `build_prompt` and an output-label banner on every answer
- [ ] Red-team set: 50 injection strings in documents, measuring detection rate and whether the model obeyed any
- [ ] Phase 8: map controls to the CPCSC/ITSG-33 control families in the write-up
