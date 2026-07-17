# Contributing

Thanks for helping improve the APIPact agent. Because this agent runs inside
customer networks and holds credentials, contributions are held to a high bar for
clarity and security.

## Ground rules

- **Keep the agent small and readable.** Its trust story depends on being
  auditable in an afternoon (see [TRUST.md](TRUST.md)). New runtime dependencies
  need a strong justification.
- **No new capabilities without discussion.** The agent receives a spec, makes a
  call, returns a result. Anything that broadens that (running code, new outbound
  destinations, new local file access) is a design change, not a patch.
- **Security-relevant paths** — the envelope/crypto wiring (`internal/secure`),
  the egress guard (`internal/executor/egress.go`), and the updater
  (`internal/update`, `internal/supervisor`) — must keep or add tests.

## Before you open a PR

```bash
make verify     # gofmt clean + go vet + full test suite (incl. live self-update tests)
```

- Format with `gofmt`; keep comments to constraints and intent, matching the
  surrounding style.
- Update [api/CONTRACT.md](api/CONTRACT.md) in the same PR if you change any wire
  type in `internal/protocol` — the cloud mirrors that contract and must not drift.
- Add tests that assert behavior against real HTTP servers / real crypto, in the
  style of the existing suites.

## Reporting security issues

Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
