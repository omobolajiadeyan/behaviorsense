# Contributing

Thanks for taking a look at BehaviorSense.

## Development

BehaviorSense intentionally uses the Python standard library only.

```bash
python -m unittest discover -s tests -v
python detector.py sample_data/ --verbose
```

The CLI exits with code `2` when a `CRITICAL` entity is found. That is expected
and allows CI or shell scripts to treat high-risk results as actionable.

## Detection Changes

When changing scoring, parsers, or technique hints:

- Add or update tests in `tests/`.
- Keep examples synthetic. Do not commit real logs.
- Document any new signal in the README.
- Be explicit about limitations and false-positive risk.

## Pull Requests

Good pull requests are small and explain the security behavior being changed.
Include sample input and expected output when possible.
