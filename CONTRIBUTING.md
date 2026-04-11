# Contributing

## Branches And Pull Requests

- Do not push directly to `main`.
- Create a branch for every feature, fix, or refactor.
- Open a pull request even for owner-authored changes when the change is non-trivial.
- Keep pull requests focused. Large cross-cutting changes should be split when possible.

Suggested branch names:

- `feature/<short-topic>`
- `fix/<short-topic>`
- `refactor/<short-topic>`
- `docs/<short-topic>`

## Review Expectations

Review is expected to focus on:

- behavioral regressions
- security and auth implications
- networking, discovery, and scan side effects
- Docker and deployment impact
- missing tests or missing validation

Style-only comments should not block important fixes unless they affect maintainability.

## Required Validation

Before requesting review, contributors should run:

```powershell
go test ./...
```

```powershell
cd web
npm ci
npm run build
```

For changes touching runtime behavior, also run a local smoke test with Docker when practical:

```powershell
docker compose build
docker compose up -d
```

## Merge Policy

- Prefer squash merge for normal pull requests.
- Avoid direct merges to `main`.
- Rebase or update the branch if `main` moved and the PR is out of date.
- High-risk areas should not be merged without explicit review:
  - authentication and session handling
  - proxy, CORS, WebSocket, and SSE behavior
  - scanning, discovery, Wake-on-LAN, and SSH execution
  - Docker and deployment changes

## CI

GitHub Actions runs the repository checks used for branch protection:

- backend tests with `go test ./...`
- frontend production build with `npm run build`

If CI fails, fix the branch before merge instead of merging around the failure.
