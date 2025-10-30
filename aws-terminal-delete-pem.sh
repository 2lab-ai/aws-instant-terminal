#!/bin/bash

# ABOUTME: Finds encrypted EBS volumes derived from local .pem keys and deletes them.
# ABOUTME: Optionally deletes the matching .pem files after confirming.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEARCH_DIR="${SEARCH_DIR:-$SCRIPT_DIR}"

yes_all=0
dry_run=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--search-dir DIR] [--yes] [--dry-run]
  --search-dir DIR  Directory to scan for .pem files (default: repo root)
  --yes             Delete without prompting per pem (dangerous)
  --dry-run         Show what would be deleted without actions

This script computes SHA-256 over each .pem file, derives a volume tag Name
(temp-terminal-enc-<12hex>), scans all available AWS regions for EBS volumes
with that Name, and optionally deletes found volume(s) and the .pem file.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --search-dir) SEARCH_DIR="$2"; shift;;
    --yes) yes_all=1 ;;
    --dry-run) dry_run=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
  shift || true
done

require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 2; }; }
require aws; require jq; require shasum; require find

echo "Scanning regions..."
mapfile -t REGIONS < <(aws ec2 describe-regions --all-regions \
  --query "Regions[?OptInStatus=='opt-in-not-required' || OptInStatus=='opted-in'].RegionName" \
  --output text | tr '\t' '\n')

if [ ${#REGIONS[@]} -eq 0 ]; then
  echo "No regions available or not authorized" >&2; exit 2
fi

echo "Searching .pem files in: $SEARCH_DIR"
mapfile -t PEMS < <(find "$SEARCH_DIR" -type f -name "*.pem" 2>/dev/null | sort)

if [ ${#PEMS[@]} -eq 0 ]; then
  echo "No .pem files found under $SEARCH_DIR"; exit 0
fi

for pem in "${PEMS[@]}"; do
  hash=$(shasum -a 256 "$pem" | awk '{print $1}')
  short=${hash:0:12}
  volname="temp-terminal-enc-$short"
  echo
  echo "PEM: $pem"
  echo " -> Volume tag Name: $volname"

  found=()
  for region in "${REGIONS[@]}"; do
    vid=$(aws ec2 describe-volumes --region "$region" \
      --filters Name=tag:Name,Values="$volname" \
      --query 'Volumes[0].VolumeId' --output text 2>/dev/null || echo None)
    if [ -n "$vid" ] && [ "$vid" != "None" ] && [ "$vid" != "null" ]; then
      state=$(aws ec2 describe-volumes --region "$region" --volume-ids "$vid" --query 'Volumes[0].State' --output text)
      attach=$(aws ec2 describe-volumes --region "$region" --volume-ids "$vid" --query 'Volumes[0].Attachments[0].InstanceId' --output text 2>/dev/null || echo None)
      echo "   - $region: $vid (state=$state, attached_to=$attach)"
      found+=("$region|$vid|$attach")
    fi
  done

  if [ ${#found[@]} -eq 0 ]; then
    echo "   No matching volumes found."
    continue
  fi

  if [ $dry_run -eq 1 ]; then
    echo "   DRY-RUN: would delete volumes above and PEM: $pem"
    continue
  fi

  approve=$yes_all
  if [ $approve -eq 0 ]; then
    read -p "Delete listed volume(s) AND the PEM file? (y/N): " yn; [[ "$yn" =~ ^[Yy]$ ]] && approve=1 || approve=0
  fi

  if [ $approve -eq 1 ]; then
    for item in "${found[@]}"; do
      region=${item%%|*}; rest=${item#*|}; vid=${rest%%|*}; inst=${rest##*|}
      if [ "$inst" != "None" ] && [ "$inst" != "null" ]; then
        echo "   Detaching $vid from $inst in $region..."
        aws ec2 detach-volume --volume-id "$vid" --region "$region" >/dev/null 2>&1 || true
        aws ec2 wait volume-available --volume-ids "$vid" --region "$region" 2>/dev/null || true
      fi
      echo "   Deleting $vid in $region..."
      aws ec2 delete-volume --volume-id "$vid" --region "$region" >/dev/null 2>&1 || true
    done
    echo "   Removing PEM: $pem"
    rm -f "$pem"
  else
    echo "   Skipped deletion for $pem"
  fi
done

echo
echo "Done."

