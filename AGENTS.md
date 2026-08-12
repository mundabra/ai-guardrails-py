# Working in ai-guardrails-py

Zero-dependency Python guardrails for LLM/agentic apps. Python sibling of
[`mundabra/ai-guardrails`](https://github.com/mundabra/ai-guardrails) (TypeScript).

## Invariants

1. **No runtime dependencies.** Ever. The library must import and run on a bare Python 3.11+.
   Consumers embed it in frozen binaries and offline environments.
2. **Guards never raise.** A malformed input, a pathological regex case, an unreadable corpus —
   all degrade to "allow" plus a log, never an exception. Callers run these on every model call;
   a crash here breaks their product.
3. **Reports never carry full sensitive content.** `Finding.value_preview` is masked
   (`types.mask` / `types.mask_url`), not merely truncated — an SSN is shorter than any preview
   limit. Reasons reach logs too, so they follow the same rule.
4. **Sync and fast.** Consumers call these from hot loops. No I/O, no async, patterns compiled
   once at import.
5. **Parity with the TS sibling is a test, not a promise.** `tests/test_parity_*.py` holds
   vectors ported from the TypeScript suite. If a change makes those diverge, it is a decision
   to be made deliberately — update both libraries or document the divergence.

## Layout

- `normalize.py` — the 14-step deobfuscation pipeline. Step names match the TS implementation.
- `corpus.py` + `data/*.json` — patterns/weights/categories as data, compiled and cached.
- `guards/` — one module per guard, each returning a `Verdict` with span-based `Finding`s.
- `scanner.py` — the stage-oriented API (`scan_input` / `scan_tool_result` / `scan_output`),
  `CachedScanner`, and report serialization.
- `datamark.py` — spotlighting. Not in the TS sibling.

## Adding a pattern

Add it to `data/<corpus>.json` with a category and weight — not to Python source. Then add a
vector to the tests. Weights: 0.1 (weak signal) to 1.0 (strong); the block threshold is 0.7,
so a single pattern at >= 0.7 blocks alone.

## Testing discipline

A test that has never failed proves nothing. Before trusting a new test, break the code it
covers and watch it fail.

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check src tests
```

## Known trade-offs

- Pattern heuristics have **low recall against adaptive attackers**. This is documented in the
  README and must stay documented — the library's honest value is spotlighting + visibility,
  not a claim of injection-proofing.
- `normalize()` is lossy (it collapses repeated characters), which is why the injection guard
  scans **both** raw and normalized text. Any new guard matching structural/delimiter patterns
  needs the same treatment.
