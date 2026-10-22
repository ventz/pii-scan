# Contributing

Thanks for helping improve pii-scan. Issues and pull requests are welcome.

## Development setup

Requires [uv](https://docs.astral.sh/uv/) and git.

```bash
git clone https://github.com/ventz/pii-scan
cd pii-scan
uv sync --extra re2
uv run --extra re2 pytest
uv run ruff check src tests
```

The `re2` extra installs google-re2, which the `--restricted-config` tests need (they skip
without it). Plain `uv run` or `uv sync` removes extras that aren't requested. google-re2 has no
wheels for free-threaded Python (3.14t), so those tests skip there. CI runs the suite on Linux and
macOS with Python 3.11 to 3.14 and 3.14t.

Run the CLI from the checkout with `uv run pii-scan ...` (or the `./pii_scan` shim).

## Ground rules

- **Synthetic data only.** Never commit, paste, or attach real personal data or real secrets:
  not in tests, fixtures, issues, or pull requests. Use documented example values such as
  `AKIAIOSFODNN7EXAMPLE`, `123-45-6789`, and `4111 1111 1111 1111`.
- **No values in output.** New outputs must use `Finding.preview` and `Finding.fingerprint`,
  never raw text.
- **Fail closed.** Detectors raise `DetectorError` on any failure; they never return an empty
  result to mean "something went wrong".
- **Linear-time regex.** Built-in patterns must avoid nested or overlapping quantifiers and use
  bounded repetition. Add a prefilter trigger when a rule has a literal anchor.
- **Tests with changes.** AWS layers are tested with botocore's `Stubber`; no test may call AWS.

## Project layout

See [docs/architecture.md](docs/architecture.md) for how sources, detectors, the pipeline, and
sinks fit together.

## Pull requests

- Keep changes focused, and describe the user-visible effect.
- Add an entry under the unreleased section of [CHANGELOG.md](CHANGELOG.md).
- Update the relevant page in `docs/` when behavior or configuration changes.
