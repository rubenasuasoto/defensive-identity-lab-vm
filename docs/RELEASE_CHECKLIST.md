# Release checklist

Use this checklist before creating `v0.1.0`.

## Local validation

```powershell
uv sync --extra dev --locked
uv run ruff check .
uv run pytest --cov=identitylab --cov-report=term-missing
uv run identitylab all
uv run detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
uv run pip-audit --skip-editable
```

## Public validation

- GitHub Pages source is set to GitHub Actions.
- `Validate hub` is green.
- `Publish hub site` is green.
- Public hub returns `200`: `https://rubenasuasoto.github.io/defensive-identity-lab-vm/`.
- Public GitBook returns `200`: `https://2dam-7.gitbook.io/defensive-lab/`.
- The hub links to the three public demos.
- The three GitBook URLs return `200`.
- The three lab release URLs return `200`.

## Release

```powershell
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Create a GitHub Release from the tag after Actions and Pages are green.
