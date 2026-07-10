# Contributing to Terminus

Terminus is built in the open because a security control you cannot read is a security
control you cannot trust. Contributions are welcome, and a few kinds are especially
valuable:

- **Threat models and bypass attempts.** If you can get a query past the enforcement,
  that is the most useful contribution there is. For anything exploitable, disclose it
  privately first (see below), not as a public issue.
- **Policy examples** for real agent-to-database patterns.
- **New database dialects** and parser coverage.
- **Docs** that make the security model clearer.

## Ground rules

- Default-deny and fail-closed are not up for negotiation. A change that can loosen a deny
  or add a fail-open path on the decision core will not be merged.
- Keep changes tested. Run the full gate before opening a PR:
  ```bash
  make check
  ```
- Match the existing style (Python 3.11+, full type hints, `mypy --strict`, Black + isort
  + ruff). See `PROJECT.md` for the architecture and the invariants to preserve.

## Security disclosure

Do not open a public issue for a vulnerability. Email
[security@interceptai.tech](mailto:security@interceptai.tech). See `SECURITY.md`.

## Contributor terms (why this matters)

Terminus is dual-licensed: AGPL-3.0 for the open-source core, plus a commercial license.
For that to work, contributions must be made under terms that let the project offer them
under both licenses. By opening a pull request you agree that your contribution is licensed
under AGPL-3.0 and that you grant InterceptAI the right to also distribute it under a
commercial license. We use a lightweight Developer Certificate of Origin (DCO): sign off
your commits with `git commit -s`.
