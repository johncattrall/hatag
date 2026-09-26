# Home Assistant AirTag Importer

Export your own Find My accessory keys from iCloud, convert existing exports, and
check nearby Bluetooth advertisements before importing devices into Home Assistant.
Despite the name, exports can also include supported AirPods, iPhones, iPads, and Macs.
This is a command-line preparation tool, **not** a Home Assistant integration or an
Apple-supported application.

Fork of [thisiscam/export-findmy](https://github.com/thisiscam/export-findmy), built
on [rustpush](https://github.com/OpenBubbles/rustpush) and
[FindMy.py](https://github.com/malmeloo/FindMy.py).

## Build

On macOS, install the Rust toolchain, protobuf compiler, and OpenSSL CLI:

```bash
brew install rust protobuf openssl

git clone https://github.com/johncattrall/home-assistant-airtag-importer.git
cd home-assistant-airtag-importer
cargo build --release --locked
./target/release/home-assistant-airtag-importer --help
```

The dependency and its related crates are pinned to
[`johncattrall/rustpush@299e4389`](https://github.com/johncattrall/rustpush/commit/299e4389b7bc68123922c651da92dac8ac45c989),
which explicitly supplies the RFC 3394 AES key-wrap IV instead of panicking in
OpenSSL. No dependency source is vendored in this repository.

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
./target/release/home-assistant-airtag-importer \
  --apple-id you@example.com \
  --output json \
  --output-dir ./ha-imports
```

JSON is the default. Choose `--output plist` or `--output both` when needed. Existing
files are never overwritten; use a fresh output directory for a later export.
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

## Convert existing exports offline

```bash
./target/release/home-assistant-airtag-importer \
  --convert=home-assistant \
  --output-dir ./converted \
  /path/to/old-export.plist /path/to/another-export.json
```

This native conversion requires no Python or Apple login. It accepts legacy
exporter plists with raw key bytes, Apple-style nested-key plists, and FindMy.py
accessory JSON. Dates, key lengths, and observed alignment are validated. The old
standalone `convert_findmy_export.py` command has been replaced by this mode.
Original files are unchanged; existing output files are rejected rather than
silently overwritten.

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

./target/release/home-assistant-airtag-importer \
  --diagnose --python .venv/bin/python \
  --scan-seconds 30 \
  ha-imports/*.findmy.json
```

Without explicit files, diagnostics reads JSON files from `--output-dir` (default
`ha-imports`). `FINDMY_PYTHON` can select the interpreter instead of `--python`.
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
./target/release/home-assistant-airtag-importer \
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
- `keystore.plist` and `anisette_state/` contain provisioning/keychain state. They are
  separate from exported accessory files and must stay private.
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
