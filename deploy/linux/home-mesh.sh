#!/bin/sh
set -eu

umask 077

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file="$root_dir/.env"
compose_file="$root_dir/compose.yml"

usage() {
  cat <<'EOF'
Usage: ./home-mesh.sh <command>

Commands:
  init              Generate a private .env and local configuration
  doctor            Validate the Linux host and rendered Compose model
  up                Pull the configured images and start Home Mesh
  update            Back up state, pull images, and recreate the stack
  backup [DIR]      Create a consistent encrypted-state backup
  status            Show service status
  logs              Follow API and web logs
  down              Stop the stack without deleting persistent data
EOF
}

fail() {
  printf 'home-mesh: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

compose() {
  docker compose --project-directory "$root_dir" --env-file "$env_file" -f "$compose_file" "$@"
}

random_base64() {
  byte_count=$1
  head -c "$byte_count" /dev/urandom | base64 | tr -d '\n'
}

release_version() {
  if [ -s "$root_dir/VERSION" ]; then
    sed -n '1p' "$root_dir/VERSION"
  else
    printf 'latest\n'
  fi
}

host_dns_server() {
  server=$(awk '/^nameserver[[:space:]]+/ { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)
  if [ -n "$server" ]; then
    printf '%s\n' "$server"
  else
    printf '127.0.0.53\n'
  fi
}

init_config() {
  [ ! -e "$env_file" ] || fail "$env_file already exists"
  require_command base64
  require_command head

  master_key=$(random_base64 32)
  session_secret=$(random_base64 48)
  bootstrap_password=$(random_base64 24)
  image_tag=$(release_version)
  dns_server=$(host_dns_server)

  mkdir -p "$root_dir/config"
  if [ ! -e "$root_dir/config/known_hosts" ]; then
    : > "$root_dir/config/known_hosts"
  fi
  chmod 0644 "$root_dir/config/known_hosts"

  cat > "$env_file" <<EOF
HOME_MESH_IMAGE_TAG=$image_tag
HOME_MESH_API_IMAGE=ghcr.io/phantonull/home-mesh-api
HOME_MESH_WEB_IMAGE=ghcr.io/phantonull/home-mesh-web

HOME_MESH_WEB_BIND=127.0.0.1
HOME_MESH_WEB_PORT=3000
HOME_MESH_ALLOWED_HOSTS=

HOME_MESH_PROXY_SUBNET=172.30.0.0/24
HOME_MESH_PROXY_GATEWAY=172.30.0.1
HOME_MESH_API_PORT=18080
HOME_MESH_DNS_SERVER=$dns_server

HOME_MESH_MASTER_KEY=$master_key
HOME_MESH_MASTER_KEY_VERSION=2
HOME_MESH_PREVIOUS_MASTER_KEYS=
HOME_MESH_SESSION_SECRET=$session_secret
HOME_MESH_SESSION_DURATION=1h
HOME_MESH_BOOTSTRAP_ADMIN_USERNAME=root
HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD=$bootstrap_password

HOME_MESH_SEED_DEMO_DATA=false
HOME_MESH_DISCOVERY_ALLOW_PUBLIC=false
HOME_MESH_SCAN_INTERVAL=30s
EOF
  chmod 0600 "$env_file"

  printf 'Created %s with mode 0600.\n' "$env_file"
  printf 'Initial username: root\n'
  printf 'Initial password: %s\n' "$bootstrap_password"
  printf 'Review HOME_MESH_WEB_BIND, HOME_MESH_ALLOWED_HOSTS, and HOME_MESH_DNS_SERVER before starting.\n'
}

doctor() {
  [ "$(uname -s)" = "Linux" ] || fail "the product Compose deployment requires a Linux host"
  [ -f "$env_file" ] || fail "run ./home-mesh.sh init first"
  require_command docker
  require_command ip

  docker info >/dev/null 2>&1 || fail "Docker Engine is unavailable to the current user"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

  mode=$(stat -c '%a' "$env_file" 2>/dev/null || true)
  [ "$mode" = "600" ] || fail "$env_file must have mode 0600 (current: ${mode:-unknown})"

  known_hosts_mode=$(stat -c '%a' "$root_dir/config/known_hosts" 2>/dev/null || true)
  [ "$known_hosts_mode" = "644" ] || fail "config/known_hosts must have mode 0644 so the non-root API can import it"

  compose config --quiet
  printf 'Compose configuration: valid\n'
  printf 'Default route:\n'
  ip -4 route show default || true
  printf 'LAN addresses:\n'
  ip -br -4 address show scope global || true
}

start_stack() {
  doctor
  compose pull
  compose up -d --wait --wait-timeout 120
  compose ps
}

backup_stack() {
  [ -f "$env_file" ] || fail "run ./home-mesh.sh init first"
  require_command docker
  require_command tar

  backup_root=${1:-"$root_dir/backups"}
  mkdir -p "$backup_root"
  backup_root=$(CDPATH='' cd -- "$backup_root" && pwd)
  timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
  archive="$backup_root/home-mesh-backup-$timestamp.tar.gz"
  stage=$(mktemp -d "$backup_root/.home-mesh-backup.XXXXXX")
  api_stopped=false

  cleanup() {
    if [ "$api_stopped" = true ]; then
      compose start api >/dev/null 2>&1 || true
    fi
    rm -rf -- "$stage"
  }
  trap cleanup EXIT HUP INT TERM

  api_id=$(compose ps -aq api)
  [ -n "$api_id" ] || fail "the API container does not exist; start Home Mesh before backing it up"

  mkdir -p "$stage/data" "$stage/config"
  compose stop api
  api_stopped=true
  docker cp "$api_id:/data/." "$stage/data/"
  cp "$env_file" "$stage/.env"
  cp "$compose_file" "$stage/compose.yml"
  cp "$root_dir/config/known_hosts" "$stage/config/known_hosts"
  if [ -f "$root_dir/VERSION" ]; then
    cp "$root_dir/VERSION" "$stage/VERSION"
  fi

  compose start api
  api_stopped=false
  compose up -d --wait --wait-timeout 120 >/dev/null

  tar -C "$stage" -czf "$archive" .
  chmod 0600 "$archive"
  rm -rf -- "$stage"
  trap - EXIT HUP INT TERM

  printf 'Backup created: %s\n' "$archive"
  printf 'The archive contains encryption keys and must be stored as a secret.\n'
}

command=${1:-}
case "$command" in
  init)
    init_config
    ;;
  doctor)
    doctor
    ;;
  up)
    start_stack
    ;;
  update)
    backup_stack "${2:-$root_dir/backups}"
    start_stack
    ;;
  backup)
    backup_stack "${2:-$root_dir/backups}"
    ;;
  status)
    [ -f "$env_file" ] || fail "run ./home-mesh.sh init first"
    compose ps
    ;;
  logs)
    [ -f "$env_file" ] || fail "run ./home-mesh.sh init first"
    compose logs --follow --tail=200 api web
    ;;
  down)
    [ -f "$env_file" ] || fail "run ./home-mesh.sh init first"
    compose down
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
