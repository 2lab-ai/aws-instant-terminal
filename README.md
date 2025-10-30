ABOUTME: Documents how to run the temporary EC2 terminal and encrypted volumes.
ABOUTME: Explains key-bound EBS encryption and cleanup workflows.

# AWS Temporary Terminal + Key-Bound Encrypted Volume

This repo provides a one-file macOS script to launch a temporary Ubuntu EC2 VM
with XFCE + VNC + NoVNC and an optional encrypted EBS data volume that is bound
to your local SSH key (.pem). Press Ctrl+C to tear everything down.

## Scripts

- `aws-terminal-run.sh`
  - Launches EC2 (Ubuntu 22.04), installs XFCE desktop, starts TightVNC `:1` and
    serves NoVNC on port `6080` (configurable). Prints SSH and NoVNC instructions
    and keeps the session alive until Ctrl+C.
  - Creates a temporary SSH key pair and stores the private key locally as
    `temp-terminal-key-<timestamp>.pem`.
  - Optional Encrypted EBS (`/mnt/local`): If enabled, the data volume name and
    the LUKS passphrase are derived from the SHA‑256 of the local `.pem` file
    that `aws-terminal-run.sh` creates. The key name is also stored in `.env`
    as `KEY_NAME` for convenience. Deleting the `.pem` file makes the volume
    permanently inaccessible by design (one‑way lock).

- `aws-terminal-delete-pem.sh`
  - Scans local `.pem` files, derives the corresponding EBS volume name
    `temp-terminal-enc-<12hex>` from each key's SHA‑256, searches all AWS regions
    for a matching volume, and optionally deletes both the volume(s) and the PEM.

## Quick Start

1) Dependencies on macOS
   - AWS CLI (`brew install awscli`), `jq`, `curl`
   - AWS credentials configured (`aws configure`)

2) Launch
   - `chmod +x ./aws-terminal-run.sh`
   - `./aws-terminal-run.sh`
   - First run will ask for region, instance type, resolution, and NoVNC port; values are saved to `.env`.
   - Choose whether to enable encrypted EBS and set capacity (32/64/128/256 GB).

3) Connect
   - SSH: command shown in output
   - NoVNC: `http://<PublicIP>:<port>/vnc.html` with the printed temporary password

4) Exit
   - Press Ctrl+C in the macOS terminal to terminate the EC2 instance and delete
     related resources. If encrypted EBS is used, the volume is detached but left
     intact so data persists between sessions. The SSH key pair and `.pem` are
     preserved (not deleted) so you can remount the volume later; remove them
     manually (e.g., with `aws-terminal-delete-pem.sh`) if desired.

## Key‑Bound Encrypted EBS Details

- When encryption is enabled, the script derives
  - `VOL_NAME = temp-terminal-enc-<first 12 hex>` from `sha256(.pem)`
  - `LUKS passphrase = full sha256(.pem)`
- The `.pem` file is never uploaded; only the derived passphrase is piped to
  `cryptsetup` on the remote host during mounting.
- If a volume with tag `Name=VOL_NAME` exists, it will be reused; otherwise you
  can create a new one with the chosen size.
- The instance is placed in the volume's Availability Zone when reusing a volume.
- Deleting the `.pem` file removes your ability to derive the passphrase; you
  cannot mount the volume again. This is intentional for one‑way lock.

## Delete PEM + Matching Volumes

Use `aws-terminal-delete-pem.sh` to find and optionally delete volumes derived
from local `.pem` files:

```
chmod +x ./aws-terminal-delete-pem.sh
./aws-terminal-delete-pem.sh --dry-run
./aws-terminal-delete-pem.sh            # interactive delete
./aws-terminal-delete-pem.sh --yes      # non-interactive (dangerous)
```

The script scans all available regions. If a matching volume is attached, it
will attempt to detach before deletion.

## Notes

- Security group opens SSH(22) and NoVNC port only to your current public IP (/32).
- Costs accrue while the instance is running. Press Ctrl+C when finished.
- The script prints a temporary VNC password; it is unrelated to the EBS key‑bound passphrase.
  - Example: `./aws-terminal-delete-pem.sh --dry-run` then run without `--dry-run`.

- `aws-terminal-mount-local.sh`
  - On macOS, mounts the remote `/mnt/local` from the EC2 to local `/mnt/local`
    using SSHFS so files are visible on both sides in real time.
  - Requirements: macFUSE + sshfs
    - `brew install --cask macfuse`
    - `brew install gromgit/fuse/sshfs-mac`

- `aws-terminal-umount-local.sh`
  - Unmounts `/mnt/local` on macOS.
