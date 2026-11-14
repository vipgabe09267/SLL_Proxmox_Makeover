# Primary passkey state and recovery

Passwordless sign-in and native two-factor keys are separate registrations.
Adding a login passkey verifies the account password once during setup; later
passkey sign-in uses the passkey instead of the username and password fields.
It does not enroll a native second factor. An existing second-factor-only key
must be registered separately as a login passkey before it can be used this way.
Optional native second factors may be disabled and retained for later use;
required realm policy and other users' settings must remain intact.

The account's passkey role is derived from enabled native WebAuthn/U2F flags.
Two-factor mode disables primary passkey-only sign-in; use the native password
flow and its additional verification. Changing **Use passkeys for 2FA** requires
the current password, even for root, and keeps registrations intact. A native
key and a resident login passkey are separate enrollments; switching role does
not convert one registration into the other. Update every node offering
Makeover primary login to enforce the same role gate. Existing accepted native
sessions and MFA continuations retain their native lifetimes.

Primary passkeys belong to an explicitly enrolled local `pve`/`pam` account on
one node and one RP ID/origin. The native password route remains available.
Existing native second-factor configuration is separate and still applies.
Losing every primary passkey does not remove your password or native recovery
methods. Use native account recovery if those are also unavailable.

From a full native session, revoke a lost primary credential from the passkey
manager. Revocation prevents new passkey assertions from issuing sessions; it
does not revoke Proxmox tickets already issued to that device or native MFA
continuations whose primary proof was accepted before the change. Password
changes have that same native lifetime limitation. Use native
account/session controls when a device or account is compromised.

Changing or resetting the account password invalidates its existing login
passkeys. An automatic Proxmox upgrade of the stored password protection also
changes the account generation and requires new passkeys. After recovery, sign in through native password/MFA and add a login
passkey again. Fresh enrollment removes obsolete records and assigns a new user
handle for the current account generation. Native TFA keys are separate and are
not removed. PAM identity changes such as a new UID/GID can also require new
enrollment.

The database is `/var/lib/proxmox-makeover/passkeys/state.json`, protected by
`/var/lib/proxmox-makeover/passkeys/lock`. The directory is root-owned 0700 and
files are 0600. It contains credential public keys, user handles, account/RP
bindings, one-way account-generation fingerprints and counters, plus short-lived challenges and rate limits. The
authenticator's private keys are never stored here. Protect database integrity
and access as authentication state.
No plaintext password or raw native password hash is stored in this database.

Back it up separately from branding configuration and retain root-only copies.
Take a consistent snapshot while holding the database's exclusive lock; copy
stable `schema`, `users` and `credentials` data into a versioned protected backup.
Do not export or restore live `ceremonies` or `rates`; an old pending challenge
must never become usable again. There is no automatic credential backup-history
or restore UI in this beta.

Restore only during a coordinated, reviewed interruption window, with native
password access confirmed first. Validate the source, schema, account bindings
and RP ID/origin, clear `ceremonies` and `rates`, and atomically replace the
database under its lock with root ownership and mode 0600. Preserve the current
database separately before replacement. Do not edit or blanket-restore native
Proxmox account/TFA files as part of this recovery. A database restore can undo
credential revocations made after that backup; review and reapply them.
Restoring credential data does not override a changed native password/account
generation. If its fingerprint no longer matches, sign in natively and enroll
again instead of restoring old password files to make a credential work.

Changing the RP ID or origin requires enrollment again at the new exact HTTPS
origin. Changing only the RP display name does not revoke existing keys.
Installer upgrades, uninstall and rollback never purge this credential directory.
Manual deletion is an explicit root recovery decision, not a normal uninstall
step. Re-enrollment after removal requires the native session, CSRF token and
fresh password check again.
