# Contributing

Thanks for considering a contribution!

## Setup

```bash
uv sync --all-extras
```

Optional (recommended):

```bash
uv run pre-commit install
```

## Quality checks

```bash
uv run ruff check .
uv run ruff format .
uv run mdformat README.md
uv run pytest -q
```

## Guidelines

- Keep changes focused and small where possible.
- Add or update tests when behavior changes.
- Update README and docs for user-facing changes.
