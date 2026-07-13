#!/bin/sh
set -eu

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
