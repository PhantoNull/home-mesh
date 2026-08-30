# Home Mesh

![Home Mesh preview](assets/readme-preview.png)

Home Mesh is a local-first network inventory and control panel for home labs and small networks.

It is designed to discover, map, and manage:

- endpoint devices
- network infrastructure such as routers, switches, and access points
- logical network segments such as LANs and VLANs
- operational actions such as Wake-on-LAN and SSH access

The goal is to provide a lightweight control surface that can manage heterogeneous devices and infrastructure, while being able to run on a thin client, Raspberry Pi, mini PC, or another always-on node near the network edge.

It is built for the awkward middle ground between "just SSH into it" and "deploy a full enterprise stack": a small, opinionated dashboard that can inventory your network, run a few useful actions, and stay close to the edge where the network actually lives.

The deployment model is intentionally portable. Docker is the easiest path, but the backend and frontend can also be run natively without assuming a Windows-only or PowerShell-only environment.

## What It Does

Current MVP capabilities include:

- support for heterogeneous managed targets, not just one class of device
- inventory CRUD for devices, network nodes, and network segments
- topology relations and a visual topology graph
- backend-driven live refresh for devices and network nodes
- SSE-based progressive UI updates pushed from the backend
- batch `nmap`-powered background scanning when available, with fallback probing logic
- DNS-to-IP refresh when a hostname is configured
- best-effort MAC address resolution
- manual MAC address entry for devices
- Wake-on-LAN for devices with a known MAC address
- encrypted per-device SSH credential storage
- interactive SSH terminal in the web UI
- action history for operational events
- application authentication with backend-protected APIs
- optimistic concurrency control for inventory and credential changes
- liveness/readiness probes and bounded SSH workloads
- Docker-based local deployment

## Architecture

The project is split into two main parts:

- Go backend
  - REST API
  - SQLite persistence
  - background refresh and probing logic
  - SSE event stream for live updates
  - Wake-on-LAN
  - encrypted secrets
  - SSH execution and terminal sessions
- React + TypeScript frontend
  - inventory dashboard
  - topology graph
  - CRUD popups
  - server-driven live state updates
  - SSH modal and terminal UI

## Repository Structure

- `cmd/server`
  - backend entrypoint
- `internal/actions`
  - operational actions such as Wake-on-LAN
- `internal/api`
  - HTTP routing and API handlers
- `internal/config`
  - environment-based configuration
- `internal/monitor`
  - live refresh and reachability checks
- `internal/networkscan`
  - process-wide coordination for discovery and scheduled scans
- `internal/secrets`
  - encryption/decryption for stored secrets
- `internal/sshclient`
  - SSH command and terminal session logic
- `internal/store`
  - SQLite schema and persistence layer
- `web`
  - React + TypeScript frontend

## Tech Stack

- Go
- React
- TypeScript
- Vite
- SQLite
- Server-Sent Events (SSE)
- Docker Compose
- Nginx for frontend container serving/proxying

## Local Development

### Prerequisites

- Go 1.25.13 (or Go 1.26.6 and newer)
- Node.js 24+
- npm 11+
- Docker Desktop or Docker Engine

### Environment

Create a local `.env` from `.env.example` for Docker Compose. Native execution
does not load dotenv files automatically: export the applicable application
variables in the process environment before running `go run`.
`HOME_MESH_API_PORT`, the `WEB_*` settings, and
`HOME_MESH_SSH_KNOWN_HOSTS_FILE` are Compose-only; a native backend uses
`HOME_MESH_HTTP_ADDR` for its listener and `HOME_MESH_SSH_KNOWN_HOSTS_PATH` for
its verified host-key file.

For an authenticated deployment with SSH credential storage, configure:

- `HOME_MESH_MASTER_KEY`
- `HOME_MESH_SESSION_SECRET` with at least 32 bytes
- `HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD` with at least 12 bytes on first start
- optionally `HOME_MESH_SCAN_INTERVAL`
- optionally `HOME_MESH_SESSION_DURATION` between 5 minutes and 24 hours
- optionally `HOME_MESH_SSH_HOST_KEY_MODE`
- optionally `HOME_MESH_TRUSTED_PROXY_CIDRS` when running behind an explicit reverse proxy
- optionally `HOME_MESH_ALLOWED_HOSTS` when the UI is served through DNS hostnames
- optionally `HOME_MESH_NMAP_PATH`
- optionally `HOME_MESH_DNS_SERVER` when the LAN DNS server should be used
  directly for forward and reverse lookups (for example, a Pi-hole address)
- optionally `HOME_MESH_DISCOVERY_ALLOW_PUBLIC` for an explicit, high-risk
  public-range scan opt-in
- optionally `HOME_MESH_SEED_DEMO_DATA=true` for a disposable, empty database
- optionally `HOME_MESH_API_PORT` to change the Compose API listener and Nginx
  upstream together
- optionally `HOME_MESH_API_BIND` to constrain the Compose API listener to a
  host address (the Linux product bundle binds it to its private proxy gateway)
- optionally `HOME_MESH_WEB_BIND` to publish the UI beyond loopback
- optionally `HOME_MESH_WEB_PORT`

Example:

```dotenv
HOME_MESH_MASTER_KEY=replace-with-a-base64-encoded-32-byte-key
HOME_MESH_MASTER_KEY_VERSION=2
HOME_MESH_PREVIOUS_MASTER_KEYS=
HOME_MESH_SEED_DEMO_DATA=false
HOME_MESH_SESSION_SECRET=replace-with-a-long-random-session-secret
HOME_MESH_SESSION_DURATION=1h
HOME_MESH_AUTH_DISABLED=false
HOME_MESH_TRUSTED_PROXY_CIDRS=172.16.0.0/12
HOME_MESH_ALLOWED_HOSTS=
HOME_MESH_BOOTSTRAP_ADMIN_USERNAME=root
HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-password-for-first-start-only
HOME_MESH_SSH_HOST_KEY_MODE=known_hosts
HOME_MESH_SSH_KNOWN_HOSTS_FILE=./config/known_hosts
HOME_MESH_NMAP_PATH=nmap
HOME_MESH_DISCOVERY_ALLOW_PUBLIC=false
HOME_MESH_SCAN_INTERVAL=30s
HOME_MESH_API_PORT=18080
HOME_MESH_API_BIND=
HOME_MESH_API_HEALTH_HOST=127.0.0.1
HOME_MESH_HTTP_ADDR=:18080
HOME_MESH_WEB_BIND=127.0.0.1
HOME_MESH_WEB_PORT=3000
```

To generate a local master key:

Unix-like shells:

```sh
openssl rand -base64 32
```

PowerShell:

```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { [byte](Get-Random -Maximum 256) }))
```

### Run Backend Natively

```sh
go run ./cmd/server
```

By default, the backend listens on:

- `http://localhost:18080`

### Run Frontend Natively

```sh
cd web
npm ci
npm run dev
```

The frontend dev server runs on:

- `http://localhost:5173`

The Vite dev server proxies `/api` to the backend, including SSE and SSH terminal websocket traffic.

### Build Checks

Backend:

```sh
go test ./...
go vet ./...
go build ./cmd/server
```

Frontend:

```sh
cd web
npm test
npm audit --audit-level=high
npm run build
npm run test:e2e
```

## Source Docker Compose

The repository Compose file builds the current checkout and is intended for
development and pre-release verification. The versioned Linux product bundle is
documented under [Deployment](#deployment).

Current Docker layout:

- `api`
  - Go backend
  - configured with `network_mode: host`
  - this is useful for LAN operations such as Wake-on-LAN, ARP, and reachability checks
  - includes `nmap` in the container image for discovery and background scans
- `web`
  - frontend served by Nginx
  - proxies `/api` to the backend via `host.docker.internal:18080` by default
  - maps `host.docker.internal` through Docker's `host-gateway` on Linux
  - preserves the canonical Host header and forwards controlled client/protocol
    metadata required by SSH WebSockets, rate limiting, and origin checks

Start the stack:

```sh
docker compose up -d --build
```

Open:

- frontend: `http://localhost:3000`

Compose defaults:

- the UI binds only to `127.0.0.1`; set `HOME_MESH_WEB_BIND` to a specific LAN
  address when other trusted devices must reach it
- `HOME_MESH_WEB_PORT` controls the published frontend port.
- `HOME_MESH_API_PORT` controls both the host-network API listener and the
  Nginx upstream; it defaults to `18080`.
- the API uses host networking for LAN discovery and Wake-on-LAN, while Nginx is
  the supported browser entry point
- host networking also makes the configured API port reachable wherever the
  host firewall permits it; restrict that port to the local host or trusted
  management network
- both containers run non-root with read-only root filesystems, bounded resources,
  health checks, restart policy, and dropped Linux capabilities

Stop the stack:

```sh
docker compose down
```

## Configuration Notes

### SSH Secret Storage

SSH passwords are not stored in plaintext.

They are encrypted server-side using XChaCha20-Poly1305 and authenticated against
the owning device ID. Without `HOME_MESH_MASTER_KEY`, encrypted SSH credential
storage and SSH execution will not work. Startup validates all stored credentials
before accepting traffic, so a missing or incorrect key fails immediately.

To rotate the key, increment `HOME_MESH_MASTER_KEY_VERSION`, put the new key in
`HOME_MESH_MASTER_KEY`, and retain older keys in
`HOME_MESH_PREVIOUS_MASTER_KEYS` as comma-separated `version:base64` entries.
Previous versions must be lower than the current version. Readable legacy rows
are re-encrypted with the current key during startup; remove an old key only
after one successful start has completed that migration.

### Application Authentication

Home Mesh protects backend APIs with a single application-level login. Startup
fails closed when `HOME_MESH_SESSION_SECRET` is missing or shorter than 32 bytes.
An intentionally unauthenticated development runtime requires the explicit
`HOME_MESH_AUTH_DISABLED=true` opt-out; never use that mode on a shared network.

First-start bootstrap:

- set `HOME_MESH_BOOTSTRAP_ADMIN_USERNAME`
- set `HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD`
- start the app once
- the backend stores only an `Argon2id` password hash in SQLite
- remove `HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD` from `.env` after bootstrap if you do not want it lingering on disk

Behavior:

- unauthenticated requests to protected API routes return `401`
- the frontend shows a login form before loading the dashboard
- successful login creates an `HttpOnly` session cookie
- session lifetime defaults to 1 hour and is bounded by `HOME_MESH_SESSION_DURATION`
- logout revokes the current session server-side; process restarts revoke all sessions
- failed login attempts are rate-limited per client IP
- concurrent Argon2 password checks are bounded to cap authentication memory use

This protection applies server-side, so direct requests to the backend API are also blocked without a valid session.

`HOME_MESH_TRUSTED_PROXY_CIDRS` is a comma-separated allowlist of reverse-proxy
networks whose `X-Forwarded-For` and `X-Forwarded-Proto` headers may be trusted.
No source address, including loopback, is trusted implicitly. Compose defaults
this value to the Docker bridge range `172.16.0.0/12`; native deployments should
leave it empty unless a known proxy is in front of the API, and should use the
narrowest CIDRs practical.

Host-header validation accepts IP literals and `localhost`. DNS names must be
listed explicitly, comma-separated, in `HOME_MESH_ALLOWED_HOSTS`; include the
public-facing hostname when putting Home Mesh behind a reverse proxy. Origin
checks remain same-origin and only honor forwarded protocol metadata from a
trusted proxy.

### SSH Host Key Mode

The secure default is `HOME_MESH_SSH_HOST_KEY_MODE=known_hosts`. Compose mounts
the host file selected by `HOME_MESH_SSH_KNOWN_HOSTS_FILE` (default
`./config/known_hosts`) read-only; populate it with keys verified through a trusted
channel before opening an SSH session. The file should be readable by the
container user and must not contain unverified keys.

The API entrypoint imports that read-only mount into the Docker-managed data
volume as `/data/known_hosts` with mode `0600`. The running API uses this
persistent, private copy for strict verification and can reload it after an
explicit host-key approval from the UI. This preserves permission validation on
Linux and avoids Docker Desktop's synthetic bind-mount permissions disabling
SSH on Windows. Recreating the data volume removes UI-enrolled keys; copy the
managed `/data/known_hosts` file into the configured source file before doing
so if you need to preserve those approvals.

Native execution can override the default user known-hosts file with:

- `HOME_MESH_SSH_KNOWN_HOSTS_PATH`

Unverified SSH host keys are rejected; there is no insecure host-key mode.

When a saved SSH credential reaches a new host, open the device's SSH panel and
choose **Check host key**. Home Mesh performs the SSH handshake without sending
the stored password and displays the algorithm, SHA-256 fingerprint, and
authorized-key line. Compare the fingerprint through a trusted channel, then
choose **Trust this host key**. The API probes again before writing, so a key
that changes between review and approval is rejected. A different key of the
same algorithm is treated as a rotation and must be investigated manually;
additional algorithms can be enrolled without replacing existing keys.

### Database

Compose stores SQLite state in the Docker-managed `home_mesh_data` volume so the
non-root API owns it consistently across Linux hosts. Native execution still
uses `data/home-mesh.db` by default. Treat both locations as private state, not
source code; backing up the database also requires backing up the active master
key.

Deployments upgrading from the previous `./data:/data` bind mount must copy the
stopped `home-mesh.db` into the `home_mesh_data` volume before first start. The
old `data/known_hosts` file also moves to the host path selected by
`HOME_MESH_SSH_KNOWN_HOSTS_FILE`; Compose does not migrate either file
automatically.

Schema migrations, integrity checks, foreign-key checks, and file-permission
hardening run automatically when the store opens. Fresh databases start empty;
demo inventory is inserted only with `HOME_MESH_SEED_DEMO_DATA=true` and only
when every application table is empty. Current schema version 5 includes resource
versions, enforces relation endpoints, and quarantines invalid legacy relations
or segment memberships instead of silently accepting them.

### API Consistency And Limits

- `GET /api/health` reports process liveness; `GET /api/ready` also verifies the
  SQLite store and is the endpoint used by container health checks.
- Individual inventory resources expose a strong numeric `ETag`. Updates carry
  the same version in their JSON body; deletes and SSH credential changes require
  a matching `If-Match` header. Stale writes fail instead of overwriting newer
  state.
- `PUT /api/inventory/order` applies a complete, versioned ordering atomically.
- JSON request bodies are limited to 1 MiB.
- Synchronous full refresh and discovery requests have a 2 minute 15 second
  operation budget and return `504` on timeout; their response write deadline is
  extended separately so valid long scans can still deliver JSON.
- SSH command and terminal workloads have independent global concurrency limits;
  saturation returns `429` with `Retry-After`.
- Shutdown rejects new SSH terminal upgrades, gives active streams an initial
  8-second drain window, then cancels and waits for terminal audit completion
  before closing SQLite.

### Discovery And Background Scanning

Home Mesh uses two closely related scan paths:

- manual discovery via:
  - `GET /api/discovery/capabilities`
  - `GET /api/discovery/scan/stream` for progressive SSE results
  - `POST /api/discovery/scan`
- backend-scheduled refresh loops that update known devices and network nodes and push changes to the UI over SSE

Current shape:

- Docker Compose API image includes `nmap`
- native non-Docker runs require `nmap` to be installed separately if you want discovery or faster batch scans
- the backend falls back to legacy probing when `nmap` is unavailable
- the background scan interval is controlled by `HOME_MESH_SCAN_INTERVAL`
- discovery uses an unprivileged-compatible host probe profile; it omits raw
  UDP probes and does not require added container capabilities
- manual discovery and scheduled refresh share one coordinator, so overlapping
  `nmap` workloads are rejected or deferred rather than competing for the host
- tunnel, VPN, and point-to-point interfaces are excluded from inferred local
  scan ranges; public-range discovery requires the explicit high-risk opt-in

On Docker Desktop, automatic interface detection can expose only the internal
Linux VM subnet. Enter the physical LAN explicitly in the discovery dialog (for
example `192.168.1.0/24`), or deploy on a Linux host for native LAN visibility.

You can override the binary path with:

- `HOME_MESH_NMAP_PATH`

### Live Refresh

Live refresh is server-driven.

The backend runs a background scan loop, stores changes in SQLite, and publishes
changed snapshots over `/api/events`. The stream supports replay cursors and
keepalives; the frontend reconnects with bounded backoff and falls back to a full
inventory reload when replay is no longer possible. Refresh responses distinguish
complete, partial, and skipped results instead of reporting partial work as a
clean success.

## Deployment

Home Mesh has one supported product deployment and one native development mode.

### 1. Linux Product Bundle

The supported product deployment is Docker Engine plus Compose v2 on a physical
Linux host connected to the managed LAN. Release images are published for
`linux/amd64` and `linux/arm64`; each release includes a versioned deployment
bundle with Compose, secure bootstrap, health validation, update, and consistent
backup commands.

Suitable hosts include:

- Linux thin client
- mini PC
- Raspberry Pi class edge node

Install from the matching `home-mesh-linux-<version>.tar.gz` GitHub release:

```sh
tar -xzf home-mesh-linux-<version>.tar.gz
cd home-mesh-linux-<version>
./home-mesh.sh init
```

Review the generated `.env`, then validate and start:

```sh
./home-mesh.sh doctor
./home-mesh.sh up
```

The product Compose model:

- pulls versioned GHCR images instead of compiling on the target
- uses real Linux host networking for WOL and LAN discovery
- exposes the API only on a deterministic private proxy bridge gateway
- publishes Nginx on loopback by default
- stores SQLite and enrolled SSH host keys in a named volume
- creates a consistent data-and-key backup before updates

See [`deploy/linux/README.md`](deploy/linux/README.md) for install, network, WOL,
backup, update, rollback, and restore procedures.

Docker Desktop, macOS, FreeBSD, and generic Unix systems are not product WOL
acceptance targets. Docker Desktop host networking does not provide the same
physical-interface contract as Docker Engine on Linux.

### 2. Native Backend + Static Frontend

This is a good future production shape for a very lightweight install.

Model:

- run the Go backend as a native service
- serve the built frontend with Nginx or directly from the backend later

This is especially attractive when:

- you want fewer moving parts
- you want better low-level LAN visibility
- you want a smaller operational footprint

## Contributing

Home Mesh is being prepared for a cleaner open-source workflow.

Working expectations for contributions:

- changes should land through pull requests
- `main` should stay mergeable and deployable
- backend and frontend changes should be validated before merge
- changes touching auth, proxying, SSH, discovery, or Docker should get especially careful review

## Known Current Limitations

- topology discovery is still mostly manual
- MAC address resolution is best-effort and depends on network visibility
- Wake-on-LAN reliability depends on deployment/network environment
- background scanning currently focuses on known devices and nodes, not full autonomous topology discovery
- floorplans and physical placement are not implemented yet
- router/switch-specific discovery integrations are not implemented yet
- SSH credentials currently support password authentication, not managed key pairs
- management of devices outside the local network still requires an explicit
  remote-agent or private-overlay design; the current API should not be exposed
  directly to the public Internet

## Project Status

This repository is beyond bootstrap and already in early working-MVP territory.

Core foundations already in place:

- persistent inventory
- visual dashboard
- backend-driven live refresh
- progressive per-item live updates
- topology graph
- Wake-on-LAN
- SSH credentials and SSH terminal
- application authentication
- Docker deployment path
- basic open-source contribution guardrails

Next large product areas are likely to be:

- better topology/discovery
- remote agents or private-overlay connectivity
- managed SSH key authentication and role-based access control
- router/switch-specific integrations and observed-host promotion workflows
