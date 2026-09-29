# Contributing

Use Python 3.11 or later. Install development dependencies:

```sh
python -m pip install -e ".[dev,lab,desktop]"
python -m pytest
python -m ruff check src tests tools
```

Keep changes focused and add a regression check for behavior changes. Describe the
problem, resulting behavior and actual validation in the pull request. Use mocks
or the local lab for tests; do not require real provider credentials or external targets.

Never commit `.env`, API keys, session cookies, personal reports or generated builds.
Use `.env.example` for configuration documentation. Installer binaries belong in
GitHub Releases, not Git history. The lab's demo credentials are deliberately fake.

Report application vulnerabilities according to [SECURITY.md](SECURITY.md).
