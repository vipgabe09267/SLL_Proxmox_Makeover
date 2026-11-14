# Proxmox Makeover v0.1-beta

First public beta for Proxmox VE 9.

- Native appearance editor with login/dashboard previews, a draggable color wheel,
  local PNG artwork, separate login/dashboard fonts and configurable branding.
- Update protection enabled by default, with a manual off switch.
- Optional passwordless passkey login for local PVE/PAM accounts.
- Per-user passkey role: login alternative or native two-factor verification.
- Key removal, guarded installation, local uninstall and retained rollback history.
- Shell bootstrap verifies the release checksum and installs missing prerequisites.

Checked on pve-manager 9.2.25 and 9.2.26. Primary credentials are node-local;
install and enroll on each node separately. Password access and required native
MFA remain available. Password changes invalidate existing login passkeys.

Project code and artwork: AGPL-3.0-only. Font and dependency notices are retained.

See the README for install/uninstall commands and docs/RELEASE-AUDIT.md for
verification scope. Download proxmox-makeover-0.1-beta.tar.gz and SHA256SUMS;
verify with `sha256sum -c SHA256SUMS` before a manual installation.
