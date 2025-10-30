#!/bin/bash

# ABOUTME: Mounts the EC2 /mnt/local directory to macOS at /mnt/local via SSHFS.
# ABOUTME: Reads state/key info and provides friendly checks and instructions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/.aws-terminal-state"
ENV_FILE="$SCRIPT_DIR/.env"
MOUNT_POINT="~/mnt/local"

err() { echo "[ERROR] $*" >&2; }
info(){ echo "[INFO] $*"; }

require() { command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1"; exit 2; }; }

main(){
  # Dependencies: macFUSE + sshfs
  if ! command -v sshfs >/dev/null 2>&1; then
    err "sshfs not found. Install macFUSE and sshfs first:"
    echo "  brew install --cask macfuse"
    echo "  brew install gromgit/fuse/sshfs-mac"
    exit 2
  fi
  require ssh

  [ -f "$STATE_FILE" ] || { err "State file not found: $STATE_FILE"; exit 1; }
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  [ -n "${PUBLIC_IP:-}" ] || { err "PUBLIC_IP not present in state file"; exit 1; }
  if [ -f "$ENV_FILE" ]; then . "$ENV_FILE"; fi
  [ -n "${KEY_NAME:-}" ] || { err "KEY_NAME not set; run aws-terminal-run.sh first"; exit 1; }

  PEM="$SCRIPT_DIR/${KEY_NAME}.pem"
  [ -f "$PEM" ] || { err "PEM file not found: $PEM"; exit 1; }

  # Prepare mount point
  if [ ! -d "$MOUNT_POINT" ]; then
    sudo mkdir -p "$MOUNT_POINT"
    sudo chown "$USER" "$MOUNT_POINT"
  fi

  # Mount via SSHFS
  info "Mounting ubuntu@$PUBLIC_IP:/mnt/local to $MOUNT_POINT ..."
  sshfs -o IdentityFile="$PEM" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3 \
        "ubuntu@$PUBLIC_IP:/mnt/local" "$MOUNT_POINT"

  info "Mounted. To unmount: ./aws-terminal-umount-local.sh"
}

main "$@"

