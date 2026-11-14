# v0.1-beta verification

First public beta of Proxmox Makeover by Southland Labs.

## Scope

Validated on Proxmox VE 9 with pve-manager 9.2.25 and 9.2.26, widget toolkit
5.2.12, access control 9.2.0 and HTTP server 6.0.7. Native Proxmox files are
supplied by the installed system and are not redistributed.

The release retains the deployed appearance editor, previews, color wheel,
primary passkeys, per-user role enforcement and key-removal implementation.
Publication adds separate login/dashboard font choices, the shell bootstrap,
AGPL-3.0-only licensing and the GitHub release workflow. It does not change production accounts or authentication policy.

## Automated checks

Final local results: 95 Python tests, 225 appearance API checks, 211 key-management
API checks, 103 native HTTP checks, and seven native Chromium suites passed.

- Python helper, installer, bootstrap and passkey proof/state tests.
- Appearance API validation and fault tests.
- Key-management API tests under Perl taint mode.
- Native PVE HTTP integration with isolated accounts/stores and real signatures.
- Native Chromium suites for editor/legacy compatibility, key management,
  primary login, per-user roles, local font rendering, toolbar geometry and
  touch color selection.
- Source archive install, Apply, update protection on/off, uninstall and rollback
  against isolated copies of current vendor files.
- Repeat builds, archive/source equality and private-state/credential scanning.

The cryptographic core was checked with Debian python-fido2 1.2.0 and upstream
2.2.1, including user verification, exact origin/RP, replay, expiry, handles,
counters and account-generation binding. Native password changes invalidate
old primary records. Already accepted native sessions retain native lifetimes.

Role tests cover fresh password proof including root, selected-key enable/all-key
disable, other-factor/user preservation, mandatory policy, revision/generation
races, cached native configuration isolation and uncertain write outcomes.
Two-factor mode rejects primary passkey-only login before issuing a ticket.

The bootstrap validates the tagged archive before any package action, installs
only missing prerequisites without upgrading installed packages, checks active
tasks/consoles before activation, and retains a local source copy for recovery.
Checksum, extraction, network and package failures stop before activation.
The documented uninstall runs the installed local command with no download.

## Deployment and device testing

The complete beta runtime was activated through the guarded installer. The November 14
live qualification passed 29 API checks and 71 browser checks, including local
font loading and previews. It preserved
authentication/appearance configuration and guest operation. No production key
was enrolled or removed by those automated live checks.

On November 14, 2026, the maintainer reported successful real-device testing.
This is maintainer acceptance, distinct from the automated virtual-device tests.

Fresh installation and removal are tested against an isolated vendor filesystem;
activation was tested on the existing customized PVE host. A separate clean
PVE VM lifecycle and real multi-node execution are not claimed. Primary records
remain node-local; every participating node needs a matching mode-gate version.

## GitHub and distribution

GitHub Actions runs the isolated Python/Perl checks and builds/checks the source
release. Native PVE HTTP tests run only where the vendor libraries exist;
ordinary Ubuntu runners explicitly skip them. Native browser tests are separate
local qualification. See [Actions](https://github.com/vipgabe09267/SLL_Proxmox_Makeover/actions)
for actual hosted results. A tag publishes only after its checks succeed.

The source release uses the shared public-file allowlist, deterministic archive
metadata and SHA-256 checksums. Host state, credentials, development tools and
native vendor bundles are excluded. Public tags are not rewritten. Project
code/artwork are AGPL-3.0-only; font and dependency notices are preserved.

Update protection rejects unknown vendor contracts. This evidence does not
certify every future PVE build, nonlocal primary realms, PVE 8/10 or the separate
native mobile app. No zero-vulnerability or universal-compatibility claim is made.
