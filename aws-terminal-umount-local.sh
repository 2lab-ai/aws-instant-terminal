#!/bin/bash

# ABOUTME: Unmounts the SSHFS mount at /mnt/local on macOS.
# ABOUTME: Provides safe fallbacks using umount and diskutil.

set -euo pipefail

MOUNT_POINT="/mnt/local"

echo "[INFO] Unmounting $MOUNT_POINT ..."
if mount | grep -q " on $MOUNT_POINT "; then
  if umount "$MOUNT_POINT" 2>/dev/null; then
    echo "[INFO] Unmounted with umount"
    exit 0
  fi
  if diskutil unmount force "$MOUNT_POINT" 2>/dev/null; then
    echo "[INFO] Unmounted with diskutil"
    exit 0
  fi
  echo "[WARN] Could not unmount $MOUNT_POINT automatically. Try: sudo umount -f $MOUNT_POINT"
else
  echo "[INFO] $MOUNT_POINT is not mounted"
fi

