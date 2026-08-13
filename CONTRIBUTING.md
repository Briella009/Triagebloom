# Contributing to TriageBloom

Thank you for helping improve the project.

## Good contribution areas

- New input-field aliases
- Sanitised sample schemas
- Detection rules with clear threat reasoning
- Tests for true-positive and false-positive cases
- Documentation and accessibility improvements
- Performance measurements on large synthetic datasets

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Detection-rule requirements

Every new rule should include:

1. A stable rule ID.
2. A concise problem statement.
3. A MITRE ATT&CK mapping where appropriate.
4. At least one true-positive test.
5. At least one benign or false-positive test.
6. Explainable trigger details.
7. Safe investigation guidance.
8. No automatic destructive or containment action.

## Pull requests

Keep pull requests focused. Explain the problem, the approach, test results, and any known limitations. Never include employer, client, or personal log data. Synthetic or explicitly authorised sanitised fixtures only.

By contributing, you agree that your contribution may be distributed under the MIT licence.
