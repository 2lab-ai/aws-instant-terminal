Context
- Script `aws-terminal-run.sh` provisions a temporary Ubuntu EC2 desktop with SSH/NoVNC. It optionally attached a LUKS-on-EBS data volume via prompts.

Problem
- Interactive prompts ask whether to use an encrypted EBS volume, whether to create a volume if missing, and which size to use. This breaks non-interactive usage and adds friction.

Goal
- Always use an encrypted data EBS volume automatically.
- On first run only, ask for size and persist to `.env` as `VOL_SIZE_GB`; reuse thereafter.
- Auto-create the volume without prompts when missing; auto-create in instance AZ if an existing same-name volume is in another AZ.
- Keep a safety prompt only when the volume is attached to a different instance.

Non-Goals
- Changing instance root volume encryption or size.
- Modifying other scripts (`*-mount-local.sh`, `*-umount-local.sh`, `*-delete-pem.sh`).
- Implementing automated tests.

Constraints
- Minimal, focused changes; maintain existing behavior where not specified.
- Persist config to `.env` and prefer idempotent behavior.
- Avoid destructive actions without user confirmation (detach-from-other-instance remains prompted).

