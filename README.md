ABOUTME: Documents how to run the temporary EC2 terminal and encrypted volumes.
ABOUTME: Explains key-bound EBS encryption and cleanup workflows.

# AWS Temporary Terminal + Key-Bound Encrypted Volume

This repo provides a one-file macOS script to launch a temporary Ubuntu EC2 VM
with XFCE + VNC + NoVNC and an encrypted EBS data volume bound to your local
SSH key (.pem). Press Ctrl+C to tear everything down.

## Scripts

- `aws-instant-terminal.sh`
  - Launches EC2 (Ubuntu 22.04), installs or reuses a preset AMI with desktop,
    starts TightVNC `:1` and serves NoVNC on port `6080` (configurable). Prints
    SSH and NoVNC instructions and keeps the session alive until Ctrl+C.
  - Creates a temporary SSH key pair and stores the private key locally as
    `temp-terminal-key-<timestamp>.pem`.
  - Encrypted EBS (`/mnt/local`): Always enabled. The volume name and the LUKS
    passphrase are derived from the SHA‑256 of the local `.pem` file. The key
    name is also stored in `.env` as `KEY_NAME`. Deleting the `.pem` file makes
    the volume permanently inaccessible by design (one‑way lock).

- `aws-terminal-delete-pem.sh`
  - Scans local `.pem` files, derives the corresponding EBS volume name
    `temp-terminal-enc-<12hex>` from each key's SHA‑256, searches all AWS regions
    for a matching volume, and optionally deletes both the volume(s) and the PEM.

- `aws-terminal-mount-local.sh`
  - On macOS, mounts the remote `/mnt/local` from the EC2 to a local directory
    using SSHFS so files are visible on both sides in real time.
  - Requirements: macFUSE + sshfs
    - `brew install --cask macfuse`
    - `brew install gromgit/fuse/sshfs-mac`

- `aws-terminal-umount-local.sh`
  - Unmounts the SSHFS mount on macOS.

## Quick Start

1) Dependencies on macOS
   - AWS CLI (`brew install awscli`), `jq`, `curl`
   - AWS credentials configured (`aws configure`)

2) Launch
   - `chmod +x ./aws-instant-terminal.sh`
   - `./aws-instant-terminal.sh`
   - First run asks region, instance type, resolution, and NoVNC port; values are saved to `.env`.
   - Encrypted EBS is always enabled; you will be asked once for volume size
     (32/64/128/256 GB) and the choice is saved as `VOL_SIZE_GB` in `.env`.

3) Connect
   - SSH: command shown in output
   - NoVNC: `http://<PublicIP>:<port>/vnc.html` with the printed temporary password

4) Exit
   - Press Ctrl+C in the macOS terminal to terminate the EC2 instance and delete
     related resources. If encrypted EBS is used, the volume is detached but left
     intact so data persists between sessions. The SSH key pair and `.pem` are
     preserved (not deleted) so you can remount the volume later; remove them
     manually (e.g., with `aws-terminal-delete-pem.sh`) if desired.

## Dry Run

Check resolved configuration without creating resources:

```
./aws-instant-terminal.sh --dry-run
```

## Key‑Bound Encrypted EBS Details

- Always on. The script derives:
  - `VOL_NAME = temp-terminal-enc-<first 12 hex>` from `sha256(.pem)`
  - `LUKS passphrase = full sha256(.pem)`
- The `.pem` file is never uploaded; only the derived passphrase is piped to
  `cryptsetup` on the remote host during mounting.
- If a volume with tag `Name=VOL_NAME` exists, it is reused; otherwise it is
  created automatically in the instance AZ (size from `VOL_SIZE_GB`).
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

### .env Keys (common)

- `AWS_REGION`, `INSTANCE_TYPE`, `DISPLAY_GEOMETRY`, `NO_VNC_PORT`
- `USE_PRESET` (default `1`), `CUSTOM_AMI_ID`, `CUSTOM_AMI_NAME`, `PRESET_FORCE_REBUILD`
- `KEY_NAME` (created and stored automatically)
- `VOL_SIZE_GB` (required for encrypted data volume)

Tip: prevent accidental commit of sensitive files. Consider adding `*.pem` to
your `.gitignore`.

## Flow Stages (Runtime)

- 0-Init: Check dependencies
  - aws, jq, curl, base64, and AWS credentials
- 1-Config: Load .env and prompt options
  - Region, instance type, geometry, NoVNC port; USE_PRESET, CUSTOM_AMI_ID respected
  - Encrypted EBS: always enabled; choose size once and persist (`VOL_SIZE_GB`)
- 2-KeyPair: Resolve or create SSH key pair
  - Reuse if AWS key exists and local PEM is valid; otherwise create a new unique key
  - Persist `KEY_NAME` to `.env`
- 3-SG: Create security group
  - Opens 22 and 6080 to current public IP (/32)
- 4-Preset AMI: Ensure AMI (reuse/build)
  - If `CUSTOM_AMI_ID` available → reuse
  - Else search by `CUSTOM_AMI_NAME`
  - Else build once (install desktop/VNC/novnc/browsers/clipboard/etc.), create AMI, store `CUSTOM_AMI_ID`
- 5-State: Check existing instance reuse/delete
  - Offer delete or reuse (start if stopped)
- 6-EncVolume: Derive from PEM and locate volume
  - Name and LUKS passphrase derived from `sha256(.pem)`
  - Reuse existing volume; else auto-create with chosen size in instance AZ
- 7-Launch: Start instance
  - Uses preset AMI if present (fast path); lightweight user-data
- 8-Volume: Attach and mount (if enabled)
  - Attach EBS, LUKS open, ext4 mount at `/mnt/local`
- 9-Ready: Wait for readiness
  - Check `/tmp/terminal-ready` via SSH and NoVNC HTTP reachability
- 10-Output: Show SSH and NoVNC instructions
- Ctrl+C: Cleanup
  - Unmount and close LUKS, detach volume, terminate instance, delete SG
  - Preserve AWS key pair and local PEM (user deletes later)

Each stage is logged with a `[STAGE]` prefix in the terminal for clarity.

## Flow Stages (Preset Build)

- Preset/Check: Resolve custom AMI
- Preset/Reuse: Use custom AMI ID if available
- Preset/FoundByName: Found by name
- Preset/BuildStart: Launch builder on base Ubuntu
- Preset/CreateImage: Create AMI without reboot
- Preset/Available: AMI available; terminate builder

You should see these `[STAGE]` logs on first run that builds a preset.

- Security group opens SSH(22) and NoVNC port only to your current public IP (/32).
- Costs accrue while the instance is running. Press Ctrl+C when finished.
- The script prints a temporary VNC password; it is unrelated to the EBS key‑bound passphrase.

For macOS mounting use:

```
./aws-terminal-mount-local.sh
./aws-terminal-umount-local.sh
```
