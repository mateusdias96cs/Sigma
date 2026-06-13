# Adding a detection rule

A new detection is never "done" until it ships with tests. The loop:

## 1. Write the Sigma rule

Create a `.yml` file under the matching tactic folder, e.g.
`detections/credential_access/my_rule.yml`. Every rule **must** define all
required metadata (validation fails otherwise):

`title`, `id` (a fresh UUIDv4), `status`, `description`, `references`,
`author`, `date`, `tags` (≥1 `attack.<tactic>` **and** ≥1 `attack.tXXXX[.YYY]`
technique), `logsource`, `detection`, `falsepositives`, `level`.

Generate a UUID with `python -c "import uuid;print(uuid.uuid4())"`. Author the
`detection` against ECS field names (`process.command_line`, `process.executable`,
`user.name`, …) — see [LOG_SCHEMA.md](LOG_SCHEMA.md).

## 2. Add the TP/FP sample logs

Create `tests/logs/<id>/` (the directory name is the rule's `id`) with:

* `true_positive.jsonl` — an event that **must** fire the rule;
* `false_positive.jsonl` — a benign look-alike that **must not** fire.

## 3. Validate and test, offline

```bash
make validate   # metadata + ATT&CK tags + pySigma validators
make test       # applies each rule to its TP/FP logs via the offline engine
```

Iterate until both are green. No Elasticsearch needed.

## 4. Refresh coverage

```bash
make coverage   # regenerates coverage/navigator_layer.json + coverage_summary.md
```

## 5. Commit

Small, conventional commit, e.g. `feat(rules): detect /etc/shadow reads`.
`pre-commit` re-runs ruff, yamllint and `sentinel validate` before the commit
lands. CI then repeats validate + test + coverage on the PR.

> The rule is the **single source of truth**. Never hand-edit the generated
> Elastic NDJSON — change the Sigma rule and re-run `make convert`.

## Generating a starting draft with AI (optional)

```bash
make genrule REPORT=path/to/threat-report.txt
```

This writes a **draft** (rule + TP/FP logs) into `drafts/` and validates it, but
never publishes it. Review it, fix what the model got wrong, then move it into
`detections/` and `tests/logs/` and follow the steps above. See
[AI_RULE_GENERATION.md](AI_RULE_GENERATION.md).
