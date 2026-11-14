# Security model

Makeover is a root-level local Proxmox extension. Install only a release/source
you trust. There is no telemetry, remote artwork dependency, generic plugin
installer, arbitrary CSS/JavaScript editor, SVG upload, shell-command field,
filesystem browser or general token collection. Font identifiers come from a
fixed allowlist; the bundled fonts are served from the same Proxmox origin.
Font URLs, uploads and CSS snippets are not accepted. Primary passkey enrollment
temporarily submits a fresh account password to native Proxmox verification;
it is never stored, logged, or passed to the Python cryptographic helper.
The separate native TFA enrollment dialog retains its vendor credential handler.
Optional extra-verification enrollment requires explicit confirmation before
opening that dialog. Native key management retains the platform's password and
permission policy and CSRF-protected endpoints. Disabling an optional entry
retains its credential. The installer does not
disable existing account or realm MFA, and primary login never bypasses it.

Both key lists remain visible and expose per-key removal with confirmation.
Removal binds the selected entry to its
current account, cookie, CSRF token and dialog lifetime; closing or hiding the
view invalidates pending confirmation. Primary revocation uses the existing
own-user credential endpoint. Native two-factor removal uses a protected,
token-disabled POST bridge that derives the owner from the full interactive
session, accepts only that user's WebAuthn/U2F entries, and delegates deletion
and reauthentication to the native handler. A nonroot password is sent in the
request body rather than the URL; it is never passed to the Python verifier or
included in the bridge's error response. Existing native root password policy
is preserved. The frontend requires the advertised removal capability before
enabling this action.

## Per-user passkey role

The mode switch changes authentication policy for the signed-in account.
Enabled native WebAuthn/U2F entries are the authoritative two-factor role;
without them the account uses login-alternative mode. The primary handler
checks those native flags before and after native MFA handling and issues no
primary passkey ticket in two-factor mode. Native password/MFA authentication
remains authoritative. Other factor types and required realm policies are not
disabled.

Mode writes require a full interactive session, native CSRF, fresh password
proof for every account including root, an expected revision and a stable
account generation. Enabling requires an explicitly selected owned native key.
Alternative mode disables only the account's WebAuthn/U2F flags. A single native
TFA lock protects validation and one atomic write of a separately cloned native
configuration object, preserving other users, factors and cached originals.
Failures are followed by an authoritative reread; an old whole configuration is
never restored over concurrent changes. Realm-enforced or unsupported legacy
policies cannot be changed through this control.

Native flags persist across the cluster; no separate node-local role database
is introduced. Primary credential readiness remains node-local. Every node
offering Makeover primary login must run this gate implementation. Previously
accepted native sessions and MFA continuations retain their native lifetimes.

## Primary passkey trust boundary

This extension deliberately adds a new primary authentication path for opted-in
local `pve`/`pam` accounts. It does not turn native TFA records into primary keys,
modify PAM, rewrite realm policy, or change native WebAuthn configuration.
Registration requires an existing full native interactive session, native CSRF
validation, fresh native password verification, and a discoverable WebAuthn
credential with user verification required. A successfully verified primary
assertion replaces the password step; native account-enabled/expiry checks and
configured additional MFA remain in force before a full Proxmox session.

Credentials are bound to a server-derived account generation, not just a
reusable username. Native Perl derives a domain-separated SHA-256 fingerprint
from the current local password state (and PAM UID/GID where applicable).
Plaintext passwords and raw native password hashes never enter the Python
helper, credential database or logs. Registration binds the pending ceremony
and credential to that fingerprint; login checks it freshly in constant time
before native MFA/ticket issuance. Password changes/resets and native automatic
password-record upgrades invalidate old login passkeys. Fresh password-verified
enrollment rotates the user handle and removes obsolete-generation credentials.
A password change during enrollment is rejected.
Native PVE password authentication can transparently strengthen a legacy hash.
If this changes the record during enrollment verification, one additional native
verification must prove the same supplied password against the current stable
record. A different-password reset or another record race is rejected; PAM
retains its single-verification rule.
This does not revoke native tickets or signed MFA continuations whose primary
proof was already accepted. Native continuation/session lifetime is preserved;
this is not a global native-ticket revocation mechanism.

Only fixed status/login paths are anonymously reachable. Their native dispatch
exception is narrow; unrelated Proxmox routes keep their original authentication
and CSRF checks. The Python helper is a fixed local executable with bounded JSON
stdin/stdout and no shell, network access or caller-selected state path. It uses
python-fido2 1.2–2.x for signature, challenge, RP hash, origin and presence/user-
verification checks. Exact HTTPS origins are enforced; cross-origin/framed
ceremonies, wrong user handles, replay, expired challenges and invalid counters
are rejected. Discoverable login does not accept a caller-selected username.
Short-lived ceremonies, global/per-client budgets and credential limits bound
anonymous state growth. Passkey responses contain no native ticket until proof
and native account/MFA policy checks succeed.

Public credential data, account bindings and counters are privileged authentication
state even though private authenticator keys never leave the authenticator.
They live in `/var/lib/proxmox-makeover/passkeys/`, with root-owned 0700 directories
and 0600 files, descriptor ownership/type checks, locking, atomic rename and fsync.
This node-local database is independent of appearance backups. Installer upgrades,
uninstall and rollback retain it. Back up stable credential records under its
lock; never restore pending ceremonies, rate budgets or native login tickets.
Native password access is the recovery path. Revoking a credential does not
invalidate already-issued native tickets or previously accepted native MFA
continuations. See [recovery](docs/PASSKEY-RECOVERY.md).

The origin `/SLL-Customs` route requires a verified interactive `PVEAuthCookie`.
Configuration reads require `Sys.Audit` on `/`; mutations require `Sys.Modify`
and Proxmox's native CSRF token. API-token identities are rejected. A reverse
proxy/Cloudflare Access is optional and is never the sole authentication gate.
Public presentation values are published as a generated static JavaScript file
so the anonymous login can render them. Do not put secrets in brand text.

The bounded schema accepts HTTPS links, fixed text fields, eight six-digit hex
colors and boolean preferences. PNGs have bounded bytes/dimensions, structural
and CRC validation, and full Pillow decoding in a fixed helper subprocess.
The editor stages 192 KiB decoded chunks below the native 512 KiB JSON-request
limit. Private random upload IDs are bound to the user, asset kind, configuration
revision and declared size; chunks must arrive in order. Staging is capped at
eight sessions and 32 MiB. IDs expire after one hour; expired files are reclaimed
on the next upload/apply cleanup, and successful applies consume their files.
No artwork becomes canonical until final revision-checked Apply.
All filenames are selected server-side; uploads cannot select a path. The Security
tab reads only the current account’s key metadata and opens the shipped native
AddWebauthn component with the account fixed. Its instance-local adapter supplies
the omitted fixed-user value and adds cancellation and session-lifetime checks
around the native form, WebAuthn operation and native enrollment endpoints.
It transiently handles the form password and credential response in browser
memory, clears password references on completion/cancellation, and aborts the
browser ceremony when the dialog closes or the session changes. Native server
permission checks, password policy and TFA protocol remain authoritative; a
request already accepted by the native server cannot be undone by closing a
dialog. The UI escapes dynamic values and revokes local artwork-preview URLs.

Mutations require the revision from the last read. An exclusive lock serializes
API writes and event-based overlay repairs. The API saves a complete prior
config/artwork set, then uses same-directory atomic renames and fsync. File,
helper, result-validation and audit failures trigger rollback. Failed rollback
is reported with its recovery location rather than being hidden. Installer
recovery failures retain the maintenance sentinel instead of reopening mixed
code/state to API writes; rollback itself first saves a compensating snapshot.
The shared control lock and maintenance marker are private root-owned files at
`/var/lib/proxmox-makeover/control.lock` and `maintenance.json`; the overlay lock
is `/var/lib/sls-proxmox-branding/overlay.lock`. Their parent directories are
0700. Legacy adoption retains the old API lock only during compatibility work,
always after the private lock; the installer never removes/chowns those old
shared-directory filenames. Healthy beta activation clears the active bridge
flag while preserving rollback history. Maintenance makes an overlapping legacy
helper call fail quickly instead of waiting on its own parent's API lock.
Before source swaps, lifecycle operations pause existing timer/path producers
without changing their enablement and wait for a running repair to finish
naturally. They reject concurrent canonical helper processes and drain the
legacy overlay lock before replacing old code. Desired trigger states are
recorded before pausing and in prepared recovery transactions. No service is
killed to obtain that lock, and no new timer is created.
Live-root checks normalize repeated leading slashes and use filesystem identity;
an alias of `/` cannot select fixture mode to bypass activation checks.
Removal/native recovery uses only the native host prerequisites, so a broken
optional Python dependency cannot prevent unloading the extension. Restoring a
beta target still validates that target and its loaded API; failed restoration
remains blocked or returns to the complete pre-rollback payload.
The last 20 complete new
API backup sets and three 1 MiB audit archives are retained. Overlay originals
needed for removal are kept with a bounded extra history.

A multi-file change is **not a crash-atomic database transaction**. A power loss
or forced process termination between file renames can leave a mixed set. Use
the complete backup set, hashes and helper check for operator recovery. Incomplete pre-commit backup directories and pre-beta history are
retained for operator review rather than deleted automatically. There is no
automatic UI restore workflow in this beta. Do not restore entire old
host trees over later legitimate edits.

Package compatibility checks fail closed; native daemon startup remains
available through nonfatal presentation repair and loader fallback. This is
best-effort compatibility, not a guarantee for every future Proxmox version.
The native ExtJS overrides still depend on the installed component architecture.
Loader fallback catches module-load failures; an unexpected error during a
future vendor proxy initialization may still need operator recovery.

Activation and unload require a coordinated daemon interruption. The installer
checks both native active tasks and actual console processes/sockets. An earlier
foundation deployment interrupted an in-use host console because only the task
API was checked. That incident is the reason for the independent process guard;
no force bypass is provided. A new session can still appear between inspection
and restart, so operators must coordinate access during the window.
After activation the installer checks the loaded public passkey API through
loopback HTTPS and protected native daemon forwarding, without creating or
printing a cookie, password or native ticket. Loader fallback alone does not
count as a successful extension activation.

Report vulnerabilities through [private security reporting](https://github.com/vipgabe09267/SLL_Proxmox_Makeover/security/advisories/new).
Include the Makeover version, Proxmox package versions, reproduction steps and
impact. Do not attach credentials, private keys, host backups or production
cookies. Use ordinary GitHub issues for non-security bugs.
