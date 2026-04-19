# Releasing pipelock-verify

Use GitHub OIDC Trusted Publishing for releases. Do not rely on a long-lived
PyPI API token unless Trusted Publishing is unavailable.

## First public release

1. Rename the local branch to `main` if needed.
2. Create the public GitHub repo and push the current branch:

```bash
gh repo create luckyPipewrench/pipelock-verify-python \
  --public \
  --source . \
  --remote origin \
  --push \
  --description "Python verifier for Pipelock action receipts (Ed25519-signed, chain-linked)"
```

3. On PyPI, add a **pending trusted publisher** for:
   - Project name: `pipelock-verify`
   - Owner: `luckyPipewrench`
   - Repository: `pipelock-verify-python`
   - Workflow: `release.yml`
   - Environment: `pypi`
4. Confirm the version in `pyproject.toml` matches the release tag you plan to
   push. The GitHub Actions release workflow enforces this.
5. Create the first **signed, annotated** tag and push it. The release-tags
   ruleset rejects unsigned tags, so use `-a -s` (or rely on `tag.gpgsign = true`
   in your git config):

```bash
git tag -a -s v0.1.0 -m "pipelock-verify 0.1.0"
git push origin main --tags
```

GitHub Actions builds the distributions, checks them with `twine`, and publishes
to PyPI through OIDC.

## Subsequent releases

1. Bump `project.version` in `pyproject.toml`.
2. Install local maintainer tooling if needed:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,release]"
```

3. Run the verification gates:

```bash
pytest
ruff check pipelock_verify tests
ruff format --check pipelock_verify tests
mypy pipelock_verify
python -m build
twine check dist/*
```

4. Commit the version bump, then create a **signed, annotated** tag for the
   same version:

```bash
git tag -a -s vX.Y.Z -m "pipelock-verify X.Y.Z"
git push origin main --tags
```

If the tag version and `pyproject.toml` version diverge, the release workflow
fails before publish.
