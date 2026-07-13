#!/bin/sh
set -eu

api_port="${HOME_MESH_API_PORT:-18080}"

case "$api_port" in
  ''|*[!0-9]*)
    echo "HOME_MESH_API_PORT must be an integer between 1 and 65535" >&2
    exit 1
    ;;
esac

if [ "$api_port" -lt 1 ] || [ "$api_port" -gt 65535 ]; then
  echo "HOME_MESH_API_PORT must be an integer between 1 and 65535" >&2
  exit 1
fi

export HOME_MESH_API_PORT="$api_port"
export HOME_MESH_HTTP_ADDR=":$api_port"

known_hosts_source="${HOME_MESH_SSH_KNOWN_HOSTS_SOURCE:-}"
known_hosts_path="${HOME_MESH_SSH_KNOWN_HOSTS_PERSIST_PATH:-/data/known_hosts}"
if [ -n "$known_hosts_source" ]; then
  umask 077
  if [ ! -e "$known_hosts_path" ]; then
    cp "$known_hosts_source" "$known_hosts_path"
  else
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        ""|\#*) continue ;;
      esac
      if ! grep -Fqx -- "$line" "$known_hosts_path"; then
        printf '%s\n' "$line" >> "$known_hosts_path"
      fi
    done < "$known_hosts_source"
  fi
  chmod 0600 "$known_hosts_path"
fi

if [ ! -e "$known_hosts_path" ]; then
  umask 077
  : > "$known_hosts_path"
  chmod 0600 "$known_hosts_path"
fi
export HOME_MESH_SSH_KNOWN_HOSTS_PATH="$known_hosts_path"

exec /usr/local/bin/home-mesh-api "$@"
