# Home Mesh For Linux

This bundle is the supported Home Mesh product deployment for a physical Linux
host connected to the managed LAN. It supports Docker Engine on `linux/amd64`
and `linux/arm64`. Docker Desktop, macOS, FreeBSD, and generic Unix hosts are not
WOL acceptance targets because they do not provide the same physical host
network contract.

## Requirements

- a maintained Linux distribution
- Docker Engine and Docker Compose v2
- a stable LAN connection and address
- outbound access to GHCR, unless images are mirrored locally
- a LAN DNS resolver when private hostnames are required

The GHCR packages must be public for anonymous pulls. For a private package or
registry mirror, run `docker login` before `./home-mesh.sh up` and override
`HOME_MESH_API_IMAGE` and `HOME_MESH_WEB_IMAGE` when required.

The API uses Linux host networking for discovery, SSH, and WOL. Its HTTP
listener binds only to the dedicated `home-mesh-proxy` bridge gateway. Nginx is
the browser entry point and is published on loopback by default.

## Install

Extract a `home-mesh-linux-*.tar.gz` release bundle, then run:

```sh
./home-mesh.sh init
```

The command creates a secret `.env` with mode `0600`, creates the non-secret
SSH host-key source with mode `0644` so the non-root container can import it,
generates unique encryption/session secrets, and prints the one-time bootstrap
password.
Before startup, edit `.env`:

- keep `HOME_MESH_WEB_BIND=127.0.0.1` when using a local TLS reverse proxy;
- otherwise set it to the Linux host's LAN address for trusted LAN access;
- set `HOME_MESH_ALLOWED_HOSTS` for every browser-visible DNS hostname;
- set `HOME_MESH_DNS_SERVER` to the host or LAN resolver;
- change the proxy subnet and gateway together if `172.30.0.0/24` overlaps an
  existing LAN, VPN, or Docker network.

Validate and start:

```sh
./home-mesh.sh doctor
./home-mesh.sh up
```

After the first successful login, clear
`HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD` in `.env` and run `./home-mesh.sh up` again
so the bootstrap secret is no longer present in the API container environment.

## Operations

```sh
./home-mesh.sh status
./home-mesh.sh logs
./home-mesh.sh backup
./home-mesh.sh update
./home-mesh.sh down
```

`backup` briefly stops the API to capture a consistent SQLite database, then
restarts it and creates a mode-0600 archive under `backups/`. The archive also
contains `.env`, including the keys required to decrypt stored SSH credentials;
treat it as a secret and copy it off the host.

`update` creates a backup before pulling and recreating the configured image
tag. Pin `HOME_MESH_IMAGE_TAG` to a release version for reproducible upgrades
and rollback. Never delete the `home-mesh-data` volume during a normal update.

## WOL Acceptance

Identify the Linux LAN interface:

```sh
ip -br -4 address
ip -4 route show default
```

Before relying on WOL, capture one UI-triggered packet on an online target or a
second LAN host:

```sh
sudo tcpdump -ni <lan-interface> udp port 9
```

Then place the target in its intended sleep/off state, wait until the transition
is complete, and trigger Wake from Home Mesh. A successful UDP send only proves
local socket delivery; packet capture and target wake prove the deployment path.

## Network And TLS

The UI ships as HTTP. Publishing it on a LAN address is appropriate only for a
trusted network. For remote or untrusted access, keep the UI on loopback and put
an authenticated TLS reverse proxy or private VPN in front of it.

The API port is not intended as a public entry point. The product Compose file
binds it to the private proxy bridge gateway and trusts only that bridge CIDR for
forwarded request metadata.

## Restore

Restore is intentionally manual and offline:

1. stop the stack with `./home-mesh.sh down`;
2. preserve the existing `.env`, `config`, and `home-mesh-data` volume;
3. extract the selected backup into a protected temporary directory;
4. restore `.env` and `config/known_hosts`;
5. copy the backed-up `data/` contents into the empty `home-mesh-data` volume;
6. run `./home-mesh.sh doctor` and `./home-mesh.sh up`.

Do not start a database with keys from a different backup. Test restore on a
non-production host before depending on the backup procedure.
