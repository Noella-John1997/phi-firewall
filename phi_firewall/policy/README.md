# `policy/` - what to do with each entity

`default_policy.yaml` sets an action per entity type (`tokenize`, `mask`, `block`, `allow`) plus a
`default` for anything not listed. `policy.py` loads it into a `Policy` object.

Use your own file:

```bash
export POLICY_PATH=/path/to/my_policy.yaml
```

Example - a research team that must never send any date:

```yaml
default: tokenize
entities:
  DATE: mask
  DOB: mask
  CREDIT_CARD: block
```
