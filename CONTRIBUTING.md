# Contributing to SentinelShield

## Local verification

Before sharing changes, run:

```powershell
python -m unittest discover -s tests -v
python -m sentinelshield.evaluation
```

## Design principles

- Keep detection rules explainable and assign a rule ID, category, severity, and
  short message to every new rule.
- Add safe, offline unit tests for normal and attack-shaped inputs.
- Do not claim production-grade protection or real-world accuracy from the
  controlled evaluation dataset.
- Keep attack samples inert: never send them to external targets or execute them.
- Document configuration changes and any new limitations in `README.md`.

## Pull-request checklist

- [ ] The test suite passes locally.
- [ ] New detection behavior has both a positive and, where appropriate, a normal
      input test.
- [ ] Documentation reflects the change.
- [ ] No generated database, report, or credential file is included.
