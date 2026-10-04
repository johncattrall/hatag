# HAtag

Export your own Find My accessory keys from iCloud, convert existing exports, and
check nearby Bluetooth advertisements before importing devices into Home Assistant.
Supports compatible AirTag accessories, AirPods, iPhones, iPads, and Macs.
This is an independent command-line preparation tool, **not** a Home Assistant
integration, and is not affiliated with or endorsed by Apple or the Open Home Foundation.

Fork of [thisiscam/export-findmy](https://github.com/thisiscam/export-findmy), built
on [rustpush](https://github.com/OpenBubbles/rustpush) and
[FindMy.py](https://github.com/malmeloo/FindMy.py).

## Install with Homebrew

On **Apple Silicon macOS 14 (Sonoma) or newer**:

```bash
brew install johncattrall/tap/hatag
hatag --help
```

The formula installs the release binary and an isolated Python 3.14 environment
with checksummed, pinned diagnostic dependencies. Rust and a manual virtualenv
are not required. The installed command selects its bundled Python automatically;
`--python PATH` or `HATAG_PYTHON` can override it.

```bash
hatag --output json --output-dir ./ha-imports
hatag --diagnose --scan-seconds 30 ha-imports/*.findmy.json
brew upgrade johncattrall/tap/hatag
```

This is our [personal tap](https://github.com/johncattrall/homebrew-tap), not a
Homebrew/core package. The current binary is built for arm64; Intel and Linux users
must build from source. macOS may request Bluetooth permission for your terminal.
Upgrade/uninstall does not remove exported files, backups, or authentication state.
Versioned binaries and their corresponding source archives are published on the
repository's Releases page.

### Upgrading an existing installation

```bash
brew update
brew install johncattrall/tap/hatag
brew upgrade johncattrall/tap/hatag
```

Homebrew's rename metadata migrates the former `home-assistant-airtag-importer`
package. Use `hatag` afterward; no old command alias is installed. If you selected
a Python interpreter through the environment, rename `FINDMY_PYTHON` to
`HATAG_PYTHON`. Existing `.findmy.json` files, output folders, and backups require
no conversion or renaming.


## Build

On macOS, install the Rust toolchain, protobuf compiler, and OpenSSL CLI:

```bash
brew install rust protobuf openssl

git clone https://github.com/johncattrall/hatag.git
cd hatag
cargo build --release --locked
./target/release/hatag --help
```

The dependency and its related crates are pinned to
[`johncattrall/rustpush@48afd8a3`](https://github.com/johncattrall/rustpush/commit/48afd8a3a7319a2efd10e1f708e525deb2886013),
which retains the explicit RFC 3394 AES key-wrap IV and pins anisette header-error
propagation instead of panicking. No dependency source is vendored in this repository.

If Cargo cannot fetch an upstream submodule over SSH, use HTTPS for that build
without changing global Git configuration:

```bash
env CARGO_NET_GIT_FETCH_WITH_CLI=true \
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0=url.https://github.com/.insteadOf \
  GIT_CONFIG_VALUE_0=git@github.com: \
  cargo build --release --locked
```

## Export from iCloud

```bash
./target/release/hatag \
  --apple-id you@example.com \
  --output json \
  --output-dir ./ha-imports
```

JSON is the default. Choose `--output plist` or `--output both` when needed.
Repeated exports work in the same directory: byte-identical files are reused;
different content is written to a numbered sibling (`-1.findmy.json`, `-2.findmy.json`,
and so on). JSON/plist pairs keep matching basenames. Existing files are never
overwritten, including any saved Bluetooth alignment or custom metadata. Use the
path printed by the command for the new export; an older aligned file remains
available rather than having its alignment silently replaced with cloud data.
Names are joined using CloudKit record IDs, and filenames include a hash of the
full record ID so duplicate or sanitized names cannot overwrite other accessories.
You may rename files after export; identity and keys are inside the files.

The interactive exporter requests:

1. Your Apple Account password (hidden input).
2. The **SMS** two-factor code, not the code displayed on other Apple devices.
3. The unlock passcode or login password of the trusted device selected by serial
   number. This is not an AirTag passcode: AirTags have no passcode.

The default anisette v3 service is `https://ani.sidestore.io`; change it with
`--anisette-url URL`. Offline conversion and diagnostics do not contact this service,
sign in to Apple, or initialize iCloud Keychain state.

The anisette service is checked before requesting your Apple ID or password.
HTTP, transport, malformed-response, and service errors are reported rather than
replaced with an `explicit panic`. A failed ordinary header request does not erase
provisioning state. Service outages can be transient: keep the state directory and
retry later, or explicitly choose a service you trust with `--anisette-url`.
Do not repeatedly re-enter credentials or delete provisioning state to fix an
ordinary network/server error. HAtag does not automatically retry Apple login.


### Storage locations

`hatag` does not write authentication state into the directory you launched it from.
It uses the current user's application-data directory:

| Platform | Base directory |
|---|---|
| macOS | `~/Library/Application Support/hatag` |
| Linux | `$XDG_DATA_HOME/hatag`, or `~/.local/share/hatag` |
| Windows | `%LOCALAPPDATA%\hatag` |

Authentication files live in `state/` beneath that application-data directory.
**Exports and offline conversions default to the current working directory**,
unless `--output-dir PATH` is supplied. Paths are printed and output write access
is checked **before** asking for your Apple ID or password. If the output directory
isn't writable, change to a writable directory or specify `--output-dir`; HAtag
does not fall back to Application Support or change existing output permissions.
New directories use `0700` on Unix and exported files use `0600`.

Use `--state-dir PATH` (or `HATAG_STATE_DIR`) to choose a different authentication
directory, and `--output-dir PATH` for exports or offline conversions. A relative
override is intentionally relative to your current directory. Do not use `sudo`.

Versions before 0.1.3 wrote `keystore.plist` and `anisette_state/` into the working
directory. They are not moved or deleted automatically. To reuse them, pass
`--state-dir /path/to/that/old/directory`. Explicit diagnostic file arguments are
unaffected by these defaults.

Version 0.1.3 briefly defaulted exports to `hatag/exports` beneath application data.
Existing files there are left untouched; starting with 0.1.4, the default is the
working directory. To keep using that folder, select it with `--output-dir`.


## Convert existing exports offline

```bash
./target/release/hatag \
  --convert=home-assistant \
  --output-dir ./converted \
  /path/to/old-export.plist /path/to/another-export.json
```

This native conversion requires no Python or Apple login. It accepts legacy
exporter plists with raw key bytes, Apple-style nested-key plists, and FindMy.py
accessory JSON. Dates, key lengths, and observed alignment are validated. The old
standalone `convert_findmy_export.py` command has been replaced by this mode.
Original files are unchanged. Existing byte-identical outputs are reused; changed
outputs receive numbered sibling filenames, using the same rules as cloud export.

JSON output uses FindMy.py's `type: accessory` schema and preserves names,
identifiers, pairing dates, and available rolling-key alignment. Unknown alignment
stays unknown; no timestamp or index is invented. Plist output uses nested key
fields and whole-second UTC dates compatible with Python's plist parser. FindMy.py's
plist import API requires names/alignment to be supplied separately, so **use JSON
for Home Assistant** to retain those automatically.

## Diagnose Bluetooth matching

Python is required only for Bluetooth diagnostics. Install its pinned dependencies
in a virtual environment (Python 3.10–3.14):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-diagnostics.txt

./target/release/hatag \
  --diagnose --python .venv/bin/python \
  --scan-seconds 30 \
  ha-imports/*.findmy.json
```

Without explicit files, diagnostics reads JSON files from `--output-dir` (default
the current working directory). `HATAG_PYTHON` can select the interpreter instead of `--python`.
The diagnostic source is embedded in the compiled binary, so moving the binary
alone does not break its script lookup.

Keep devices physically near the scanning computer. Enable Bluetooth and approve
macOS Bluetooth access for your terminal when requested. Capture finishes before
key matching begins; matching an old, unaligned export can take several minutes.
Playing a sound can identify a physical device, but **does not establish alignment**.
Do not repeatedly play sounds or assume a successful sound proves exported keys.

Diagnostics is read-only by default. It reports device names and matching status,
not private keys, Bluetooth addresses, or locations. It never changes HA entries.
A completed scan with no matches exits successfully; input, permission, adapter,
and dependency failures exit nonzero.

To persist verified primary-key alignment:

```bash
./target/release/hatag \
  --diagnose --save-alignment --python .venv/bin/python \
  --scan-seconds 60 \
  ha-imports/*.findmy.json
```

Only primary-key observations with a non-regressing index/date can be saved.
Secondary-only matches are reported as conservative bounds and are **not** saved
as exact primary alignment. Unmatched files stay unchanged. Before changing files,
the tool creates and verifies an owner-only ZIP backup; changes use atomic file
replacement and preserve all fields except the observed alignment date and index.
Backups are private key material and are not encrypted.

A scanning Mac cannot be assumed to receive its own advertisements. AirPods
components, connected owner-nearby devices, and second-generation AirTag DULT
advertisements may not be visible to the supported Offline Finding scanner.
No match is not proof of a bad export. Do not reset accessories or iCloud Keychain
just to make a scan succeed.

## Import into Home Assistant

Install the separate [hass-FindMy integration](https://github.com/malmeloo/hass-FindMy).
Configure its Apple account, then add a **FindMy Device → Rolling, derived** and
upload the desired `.findmy.json` file. If a previous upload failed, choose the file
afresh instead of reusing the form's stale attachment.

The importer does not modify HA configuration or replace existing entities. Preserve
entity IDs when updating an existing device through your integration's supported
workflow. Format validation and Bluetooth matching do not prove that Apple will
return recent network location reports; a nearby owner-connected device may not
produce the same network reports as a separated accessory.

## Security and state

- Output files, diagnostic backups, and archives contain **private tracking keys**.
  Do not publish them or paste their contents into issues/chat.
- On Unix, exported files and diagnostic backups use mode `0600`; created output
  directories use `0700`. Protect copies and non-Unix destinations yourself.
- `state/keystore.plist` and `state/anisette_state/` beneath the application-data
  directory contain provisioning/keychain state. Keep them private.
- The exporter authenticates as a synthetic device and joins the iCloud Keychain
  trust circle. It retains the upstream escrow behavior; this is not a read-only
  Apple account operation.
- The common output, backup, virtual-environment, and state paths are ignored by
  Git. Always inspect the explicit staged file list before publishing; custom
  output directories are your responsibility.
- Never commit real device fixtures. All regression fixtures use synthetic keys.

## Development checks

```bash
cargo test --release --locked
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

Regression coverage includes PCS key recovery, name/alignment association,
collision-safe output, native format conversion, malformed inputs, and safe
Bluetooth alignment updates. Real Bluetooth diagnostics and authenticated iCloud
export require your own devices and cannot be demonstrated by synthetic tests alone.
