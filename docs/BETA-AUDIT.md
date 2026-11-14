# 0.1-beta implementation audit

Prepared 2026-11-08. This records a beta build, isolated tests and scoped live
frontend validation, not a claim of perfect security or compatibility with
every future Proxmox version.

## Changes from the foundation

The editor now uses native Proxmox ExtJS tabs, forms and buttons. Its color
picker uses a continuous draggable hue/saturation wheel and brightness slider;
exact hex entry remains available. Appearance contains brand/artwork/palette
controls; Login contains the welcome copy; Security keys provides native enrollment; Updates
contains repair preferences. Duplicate product/customizer fields and the custom
marketing-style editor were removed. Brand changes update default title/footer
text while preserving explicit custom overrides. Login/dashboard previews sit
beside the form on desktop, with their selector directly above the preview.
The Preview tab provides the same local controls on phones.

The launcher follows the native login lifecycle, appears after signing in
without a manual reload, and closes the editor on logout. Its button has a
visible native default-button appearance and pointer interaction. The latest
refinement gives it an explicit background/backdrop and replaces the finite
swatch selector with continuous wheel selection without external dependencies.
Browser checks passed for real mouse dragging, brightness adjustment,
preview-local switching, and the launcher's visible background, solid border
and pointer interaction.

Security keys lists only the current account’s public key metadata. The Add
passkey / security key button opens the shipped native AddWebauthn dialog.
A native display-only fixed-user selector omitted its value on submit. The
instance-local adapter supplies that fixed value and wraps the native form,
WebAuthn operation and enrollment endpoints with cancellation and session checks.
It handles password/credential values transiently in browser memory, clears
password references on exit and aborts browser enrollment when its dialog or
session ends. Native permission checks, password policy and TFA protocol remain
authoritative. Browser tests
exercise both native API phases against an isolated fake API with a simulated
hardware boundary. No production credential was created. This native TFA
workflow remains a second factor and is separate from primary passkeys.

The first public beta also adds explicitly enrolled primary passkeys for local
`pve`/`pam` accounts. Registration requires a full native session, native CSRF,
fresh native password verification and discoverable/user-verified WebAuthn
registration. Primary assertions replace only the password step; enabled/expiry
and additional native MFA checks still apply. The root-only Python verifier
uses python-fido2, while Perl owns native identity policy and ticket issuance.
Existing native TFA keys are never automatically promoted. See
[release gates](RELEASE-AUDIT.md) for the distinction between isolated proof
tests and an activated native backend.

The applied theme now derives its presentation colors, chart colors and native
control states from the saved palette. Host-specific storage labels were removed.
Logo/login/favicon/native icon slots use the two configurable local PNG masters.
The helper derives icon dimensions from uploaded artwork. Native component
shape checks fall back to native behavior if an override no longer fits.

Schema 2 adds Update protection, enabled by default. Schema 1 is normalized on
read without overwriting the operator's file; subsequent saves use schema 2.
Protection controls event-based reapplication, including any retained legacy
verification service. Turning it off does not prevent manual Apply. No recurring
maintenance schedule or new timer is installed.

## Security and reliability findings addressed

- File-write and audit failures formerly fell outside rollback. All mutation
  stages now have recovery, fsync, complete prior snapshots and explicit error
  reporting if recovery itself fails.
- Concurrent stale saves formerly overwrote newer settings. Mutations now require
  the last-read revision and return 409 on conflict; readers/repairs share locking.
- A maintenance sentinel rejects beta API requests with 503 during installer
  code swaps; filesystem mutation phases share the same private control lock.
  Both live under root-only `/var/lib/proxmox-makeover`, outside the shared
  temporary lock directory. The overlay lock also has a root-only parent.
  Adoption/recovery takes the old API lock only when needed, after the private
  lock; healthy beta commits retire that compatibility flag while rollback
  history and interrupted legacy restoration preserve it.
- PNG inspection now includes full pixel decoding, including rejection of
  CRC-valid but undecodable images. Size, dimensions, signature, structure and
  CRC checks remain mandatory.
- The native API server accepts only 512 KiB normal request bodies. Large
  artwork now stages through ordered, authenticated 192 KiB decoded chunks.
  Random IDs bind user, kind, revision and declared size. The final apply resolves
  validated completed uploads under lock. Staging has count/byte/expiry limits.
- Backup and audit growth are bounded for new complete histories. Symlink and
  ownership checks include locks, staging and recovery files; lock opens use
  O_NOFOLLOW and verify the opened descriptor.
- Uninstall/rollback after adopting the earlier foundation now converts saved
  settings back to its compatible schema, retaining the beta bytes separately.
  It preserves custom artwork and current text instead of restoring stale data.
- Installer recovery now retains its maintenance marker when restoration is
  incomplete; rollback captures its own compensating payload snapshot. A
  post-activation anonymous loopback status check exercises loaded proxy and
  protected daemon dispatch without generating a native cookie or ticket.
- Primary passkey credentials have a separate root-only node-local database.
  Upgrades/removal/rollback never delete it. Short-lived ceremonies are not
  credential backups and must not be restored into service.
- Username reuse is not treated as proof of the same account. Credentials and
  pending registrations carry a server-derived account-generation fingerprint;
  native Perl checks fresh password state before issuing a session. Password
  changes/resets and native password-record upgrades invalidate previous login passkeys, and fresh verified
  enrollment rotates the user handle and removes obsolete records. Raw passwords
  and native password hashes are never passed to Python, persisted or logged.
  Changes/revocation block future proofs; they do not globally revoke native
  tickets or signed MFA continuations whose primary proof was already accepted.

## Verification performed

The API suite exercises native permission declarations, token/anonymous denial,
protected-route 401/303 behavior, strict schemas,
revision conflicts, two-process concurrent writes, filesystem failures, rollback
failures, maintenance rejection, PNG decoding, bounded histories and private modes.
Chunk cases cover real supplied large artwork, wrong user/kind/revision/order,
incomplete/expired uploads, size/count/byte quotas, tampering and cleanup.

The account-bound primary passkey core passed 21 isolated tests against Debian
python-fido2 1.2.0 and upstream 2.2.1 with cryptography 43.0.0. The taint-mode
primary-passkey API suite passed 128 checks, and the isolated native PVE HTTP
suite passed 54 checks using actual proxy/root parsing, native authentication,
MFA and cryptography with fictional accounts, isolated stores and ephemeral
keys. No production account, key or service was changed by those tests. Final
snapshot/archive and hosted-workflow gates remain in RELEASE-AUDIT.md.

Installer fixtures exercise fresh installs, upgrades, default private staging,
unknown-template failures, current-vendor removal, preserved external edits,
legacy schema conversion and rollback, process guards and raced symlink attacks.
The latest full Python run passed 80 tests: 14 helper, 45 installer and 21
primary-passkey core tests. Installer cases also exercise interrupted legacy
daemon restoration and preparation failures without live service operations.
An actual paused historical helper could formerly overwrite a new bundle after
installation. The regression now rejects that overlap before source mutation;
after natural completion, the retry holds its old overlay lock through new
publication. Existing timer/path producers are paused and restored without
creating schedules or killing a writer. Desired states survive interruption
before/after snapshot preparation. Read-only root-identity regressions also
cover the `//` spelling, which must never select fixture mode on the live host.
The helper was also applied/checked/removed/re-enabled against an isolated copy
of the installed pve-manager 9.2.25 and 9.2.26 templates, native JavaScript and dark theme.
Native JavaScript stayed byte-identical.

The Chromium suite loads the installed native ExtJS/PVE runtime in a
loopback-only fixture with API stubs and fictional users/data. It passed
against both 0.1.0 and 0.1-beta backends, covering real mouse dragging on the color wheel,
brightness mouse/keyboard changes including Home/End at 0/100, and zero
appearance writes before Apply. It also verifies the selector within the
preview header, launcher background/border/pointer styling, 320/390px layouts,
escaping, contrast, PNG preview, unsaved-close/reset, revision+CSRF and
legacy-schema submissions, read-only behavior, login/logout, bypass and native
enrollment. Real supplied logo/favicon transport stays below the native
request limit and produces one canonical apply after staging. No external
browser requests or uncaught page errors occurred in those runs.

The separate mobile touch suite passed with real CDP touch dragging on the
180px wheel at device pixel ratio 2, without appearance writes or page errors.
Independent checks passed 4,352 HSV round trips plus busy/read-only, cancel
and disposal cases.

The presentation was published live as content version `3fc7b991c76d38ec` on
the existing foundation. The helper check was clean; daemon PIDs/start times
and configuration stayed unchanged. This was a frontend-only update, not a
live end-to-end beta backend deployment.

The API suite also passes under Perl taint mode (-T), including subprocess
argument checks and staging/backup cleanup. Python, JavaScript, Bash and both
real Perl/PVE integration modules pass syntax
checks. Source packaging uses an explicit allowlist and excludes host state,
credentials, development libraries and native vendor bundles. Local fixture
passes do not claim a GitHub-hosted workflow has run.

## Operational and compatibility limits

The corrected frontend can run against the existing 0.1.0 foundation without
a daemon lifecycle. Legacy requests use schema 1 and omit beta-only parameters.
Large legacy artwork is previewable but applying is blocked before exceeding the
native request limit; update-protection and primary passkey authentication need
the activated beta backend. Full beta
backend activation still requires a clear, approved daemon interruption window. The installer independently checks both API tasks and real console
processes/sockets. This preserves the lesson from the earlier foundation's
console-interruption incident. No guest/host reboot is part of activation.
Native security-key enrollment remains the user's own Proxmox operation.

Current native runtime validation is pve-manager 9.2.26 with widget toolkit
5.2.12; the earlier 9.2.25 runtime was checked as well. Future supported PVE 9
builds must pass structure and runtime checks; PVE 8/10 and alternate/mobile
applications are not validated. The overlay uses installed layout/theme files
and refuses unknown structures. Loader fallback covers module-load failures,
not every possible future vendor-initialization failure.

Cross-file updates remain recoverable rather than crash-atomic. Incomplete
backup directories/pre-beta histories are retained for operator review.
Installer release/transaction archives have no automatic retention policy;
inspect retained rollback requirements before manual pruning. Expired upload
bytes are reclaimed on the next cleanup event, not by a new scheduled job.
There is no UI restore-history workflow or cluster-shared configuration in this
beta; settings are node-local. Primary credential state also remains node-local,
has no automatic backup-history UI, and is recovered separately from appearance
data. See SECURITY.md for the complete trust boundary.
