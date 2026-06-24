# Contributing

Thanks for your interest in improving `go-rack-attack`.

## Development

```bash
go test -race ./...   # tests must pass with the race detector
go vet ./...
gofmt -l .            # must print nothing
```

Tests use [miniredis](https://github.com/alicebob/miniredis), so no real Redis
server is needed to run the suite.

## Guidelines

- **Security first.** This is a request-filtering library; bugs are security
  bugs. New IP-handling or rule-matching code must come with tests that cover
  the spoofing / bypass angle, not just the happy path.
- **Keep the store interface small.** Backend-specific behavior belongs in a
  `Store` implementation, not in the core filter.
- **Concurrency.** The filter is used from many goroutines. Anything touching
  shared state must keep `go test -race` clean.
- Add a test for every behavior change and update the README/godoc when the
  public API changes.

## Pull requests

1. Fork and branch from `main`.
2. Make your change with tests.
3. Ensure CI (test + vet + gofmt + staticcheck) passes.
4. Open the PR with a clear description of the problem and approach.

## Maintainers: branch protection

Dependency PRs from [Renovate](./renovate.json) are set to automerge once CI is
green. For that to be safe, `main` must require the CI checks to pass. Configure
this once under **Settings → Branches → Add branch ruleset** (or classic branch
protection) for `main`:

- **Require a pull request before merging** — and require approval from a code
  owner (see [.github/CODEOWNERS](./.github/CODEOWNERS)).
- **Require status checks to pass before merging**, selecting the `test` and
  `lint` jobs from the CI workflow. Enable *Require branches to be up to date*.
- **Do not allow bypassing the above settings** (so even maintainers go through
  CI), and keep *Allow auto-merge* enabled at the repo level so Renovate's
  automerge works.

With these in place, only green, code-owner-reviewed changes reach `main`, and
Renovate's minor/patch updates merge themselves after passing the same gate.
