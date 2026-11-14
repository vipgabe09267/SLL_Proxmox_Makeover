# Development and validation

This repository contains project code and artwork only. Browser tests load the
Proxmox vendor files from a locally installed PVE 9 tree; those vendor files and
any production state are not redistributed.

Install test prerequisites on a development machine:

```sh
apt install python3 python3-pil python3-fido2 python3-cryptography perl liburi-perl libwww-perl libio-compress-perl nodejs
```

Use Python 3 + Pillow,
python-fido2 **>=1.2,<3**, cryptography, Perl + URI/HTTP/Compress::Zlib, and Node.
Authentication-state and API ownership checks intentionally require root; run
the isolated suites in a disposable root-capable environment.
Every production path is redirected to a private temporary tree before the API
module is evaluated; no daemon is loaded by the suite.

```sh
sudo env MAKEOVER_TEST_REAL_HELPER=1 perl -T tests/test-api.pl
sudo perl -T tests/test-passkeys-api.pl
sudo python3 -m unittest discover -s tests -p 'test*.py' -v
bash -n install.sh
bash -n bootstrap.sh
node --check makeover.js
node --check native-security.js
node --check login-passkeys.js
node --check southland.js
python3 -m py_compile sls-proxmox-branding scripts/lifecycle.py scripts/release_inputs.py scripts/passkeys.py tools/build-release.py
```

On a PVE development host, also syntax-check the real integrations:

```sh
perl -T -I"$PWD" -c PVE/API2/SLLCustoms.pm
perl -T -I"$PWD" -c SLL/Makeover/Bootstrap.pm
perl -T -I"$PWD" -c PVE/API2/SLLPasskeys.pm
sudo perl -T tests/test-passkeys-http.pl
```

The browser fixture runs a loopback-only HTTP server, serves the current local
ExtJS/PVE resources read-only, and stubs the native and Makeover APIs. Its
credentials, nodes and metrics are fictional. It does not contact port 8006 or
use a production ticket. Install Playwright as a development dependency and its
Chromium browser, or set the fixture's environment overrides to existing tools:

```sh
node tests/browser-beta.cjs
node tests/browser-wheel-touch.cjs
node tests/test-native-security.cjs
node tests/browser-passkeys.cjs
node tests/browser-fonts.cjs
node tests/browser-toolbar.cjs
node tests/browser-passkey-mode.cjs
```

The browser suites check native tab/form interaction, editing without writes,
text escaping, contrast, PNG preview, reset/close handling, revision and CSRF
payloads, schema 1 compatibility, native key enrollment, bounded large-image
chunk transport, read-only permissions, 320/390px layout, native login and
temporary appearance bypass. Continuous picker checks passed against both
0.1.0 and 0.1-beta fixture backends using real mouse dragging, brightness
mouse/keyboard adjustment including Home/End at 0/100, and no appearance writes
before Apply. They verify **Preview login** and **Preview dashboard** within
the preview header, plus the launcher's background, solid border and pointer
styling. The separate touch suite passed real CDP mobile touch dragging on the
180px wheel at device pixel ratio 2, without appearance writes or page errors.
Keep these interaction checks when changing the picker or preview layout.
Evidence is written to `evidence/`; do not substitute live production
browsing for the offline fixture. CI runs isolated fault/installer tests; native
browser integration requires the installed vendor resources and is tested
separately.

Primary passkey tests must use real signature verification, discoverable user
handles, exact origins, required user verification, nonce/challenge single-use,
expiry, counters and account/MFA policy checks. Test both the supported Debian
1.2 API and 2.x; library method signatures changed during the upstream migration,
so the helper uses the response-object interface shared by these releases. See the
[upstream migration guide](https://developers.yubico.com/python-fido2/Migration_1-2.html).
Native protocol tests need the actual PVE HTTP authentication and protected
forwarding code, fictional native user/ACL configuration, and ephemeral signing
keys. Do not point them at production key/account files or treat permission
stubs as evidence of complete native authentication integration.

The configured hosted job uses explicit Ubuntu 26.04 because Ubuntu 24.04's
packaged fido2 is below this beta's minimum. It pins the checkout action to the
verified upstream v7.0.1 commit, uses read-only repository permissions and does
not persist Git credentials. Dependency packages come from signed OS package
repositories; the project does not run pip against the Proxmox system Python.
Current local/hosted validation status is in [the release audit](RELEASE-AUDIT.md).

To validate a package update, build an isolated root with the candidate vendor
template, runtime JavaScript and native dark theme, then run the real installer
with `--root DIR --no-activate`. It cannot invoke systemd, apt or native daemons
for an alternate root. The existing tests also simulate package replacements,
unknown templates, disk failures, concurrent saves, symlinks, malformed images,
configuration migration, uninstall and rollback.

Build the allowlisted source release and checksum:

```sh
python3 tools/build-release.py
cd dist
sha256sum -c SHA256SUMS
```

The build omits `.dev`, host state, credentials, native vendor bundles and Git
metadata. Repeat builds of the same inputs produce the same archive bytes.
GitHub workflow configuration is included, but a local pass is not a claim that
a hosted workflow or an untested Proxmox version has run successfully.

Pillow decoding deliberately uses both verification and a reopened `load()`;
opening alone does not decode the image. See the [Pillow Image API](https://pillow.readthedocs.io/en/stable/reference/Image.html).

The shell bootstrap tests substitute only the network/package boundary and a
fictional release. They verify checksum failure, unsafe extraction, download
and package failures, task guards, stage-only operation and retained-source
activation. They never install packages or activate production services.

Pushes and pull requests to `main` run the isolated checks. A `v*` tag reruns
those checks, verifies that the tag matches `VERSION`, builds the deterministic
archive and checksum, and publishes a beta prerelease. Only the publishing job
has repository write permission. No self-hosted production runner is used.
