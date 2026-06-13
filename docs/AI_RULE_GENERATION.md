# AI-assisted rule generation (human in the loop)

`sentinel genrule` turns a free-text threat report into a **draft** Sigma rule
and a matching pair of TP/FP sample logs. It is the most constrained part of the
platform on purpose.

## Why a human stays in the loop

A detection rule is security-critical code. A model can draft plausible logic,
but it can also hallucinate field names, mis-map ATT&CK techniques, or write a
rule that is too broad (alert fatigue) or too narrow (missed attacks). So the AI
is allowed to *propose*, never to *merge or deploy*:

1. Output goes to `drafts/` — a directory excluded from the pipeline. It is
   `.gitignore`d (except `.gitkeep`) and never imported by `convert`/`deploy`.
2. The draft is validated with the **same** validator as hand-written rules, so
   a human starts from something well-formed, not raw model text.
3. Promotion is a deliberate manual step: review, fix, and move the files into
   `detections/` and `tests/logs/`, then run `make validate && make test`.

This mirrors a pull-request review: the model is a fast junior drafter; the
engineer is accountable for what ships.

## How it works

```bash
make genrule REPORT=threat-report.txt
# or: sentinel genrule --report threat-report.txt [--provider gemini|template]
```

The provider is pluggable behind the `AIProvider` interface
(`src/sentinelcode/genrule.py`):

* **`gemini`** — Google Gemini over its REST API. Needs `GEMINI_API_KEY`
  (optionally `GEMINI_MODEL`, default `gemini-2.5-flash`). The system prompt
  instructs the model to emit valid Linux `process_creation` Sigma mapped to
  ECS, with a proper ATT&CK mapping and a self-consistent TP/FP pair.
* **`template`** — a deterministic, offline fallback (no key, no network). It
  extracts command tokens from the report and emits a valid, self-consistent
  draft. This keeps the command usable in CI and demos.

Resolution order: `--provider` flag → `AI_PROVIDER` env → `gemini` if
`GEMINI_API_KEY` is set, otherwise `template`.

## Output

```
drafts/<report-name>/
├── rule.yml              # the draft Sigma rule
├── true_positive.jsonl   # event that should fire it
└── false_positive.jsonl  # benign event that should not
```

The command prints any validation issues for the human to resolve before review.
Add real `references`, sharpen the `detection`, confirm the ATT&CK tags, and only
then promote the rule.
