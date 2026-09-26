#!/usr/bin/env python3
"""Match local FindMy accessory JSON against one Bluetooth scan; never authenticate.

Requires requirements-diagnostics.txt. Matching is read-only unless --save-alignment
is given. Secondary keys cannot establish an exact primary-counter alignment.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from importlib import metadata
import json
import logging
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

FINDMY_VERSION = "0.10.2"
SEARCH_MARGIN = timedelta(hours=12)  # FindMy's public scanner uses this margin.
MAC_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")


class DiagnosticError(Exception):
    """An actionable error whose message contains no key or advertisement data."""


def label(path):
    return json.dumps(Path(path).name, ensure_ascii=True)


def load_runtime():
    # Third-party debug logs include addresses and public keys. This standalone
    # process only emits the explicit, redacted reports below, even with BLEAK_LOGGING.
    logging.disable(logging.CRITICAL)
    if not (3, 10) <= sys.version_info[:2] < (3, 15):
        raise DiagnosticError("Diagnostics require Python 3.10 through 3.14.")
    try:
        if metadata.version("FindMy") != FINDMY_VERSION:
            raise ImportError
        global FindMyAccessory, KeyPairType, OfflineFindingDevice, BleakScanner
        from findmy import FindMyAccessory, KeyPairType, OfflineFindingDevice
        from bleak import BleakScanner
    except Exception:
        raise DiagnosticError(
            "Diagnostics require FindMy==0.10.2 and its Bluetooth dependencies. "
            "Install requirements-diagnostics.txt using the selected Python interpreter."
        ) from None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_snapshot(path):
    """Read a regular, non-symlink file and reject changes during the read."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise DiagnosticError(f"{label(path)}: symbolic-link inputs are not supported.")
    if not stat.S_ISREG(info.st_mode):
        raise DiagnosticError(f"{label(path)}: input must be a regular file.")
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise DiagnosticError(f"{label(path)}: input must be a regular file.")
        raw = stream.read()
        after = os.fstat(stream.fileno())
    if signature(before) != signature(after):
        raise DiagnosticError(f"{label(path)}: input changed while being read; nothing saved.")
    return raw, signature(after)


def json_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def reject_constant(value):
    raise ValueError("non-finite JSON number")


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("date must be a string")
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if date.tzinfo is None or date.utcoffset() is None:
        raise ValueError("date requires a timezone")
    return date.astimezone(timezone.utc)


@dataclass(repr=False)
class InputFile:
    path: Path
    original: bytes
    signature: tuple
    data: dict
    accessory: object


def load_inputs(paths):
    inputs = []
    identities = set()
    for source in paths:
        path = Path(source).absolute()
        # Resolve only the parent; retain the final component for O_NOFOLLOW.
        path = path.parent.resolve() / path.name
        try:
            raw, stamp = read_snapshot(path)
            if stamp[:2] in identities:
                raise DiagnosticError(f"{label(path)}: duplicate input file or hard-link alias.")
            data = json.loads(raw, object_pairs_hook=json_object, parse_constant=reject_constant)
            if not isinstance(data, dict) or data.get("type") != "accessory":
                raise ValueError("expected a rolling-derived accessory")
            for name, size in (("master_key", 28), ("skn", 32), ("sks", 32)):
                value = data[name]
                if not isinstance(value, str) or len(value) != size * 2:
                    raise ValueError("invalid key length")
                if len(bytes.fromhex(value)) != size:
                    raise ValueError("invalid key encoding")
            timestamp(data["paired_at"])
            date, index = data["alignment_date"], data["alignment_index"]
            if (date is None) != (index is None):
                raise ValueError("partial alignment")
            if date is not None:
                timestamp(date)
                if type(index) is not int or index < 0:
                    raise ValueError("invalid alignment index")
            for name in ("name", "model", "identifier"):
                if data[name] is not None and not isinstance(data[name], str):
                    raise ValueError("invalid metadata")
            for name in ("group_identifier", "serial_number"):
                if data.get(name) is not None and not isinstance(data[name], str):
                    raise ValueError("invalid metadata")
            # Validate with the public loader, without serializing it back: that
            # would invent alignment for null values and discard unknown metadata.
            accessory = FindMyAccessory.from_json(data)
            inputs.append(InputFile(path, raw, stamp, data, accessory))
            identities.add(stamp[:2])
        except DiagnosticError:
            raise
        except OSError:
            raise DiagnosticError(f"{label(path)}: cannot read input; check the path and permissions.") from None
        except Exception:
            raise DiagnosticError(
                f"{label(path)}: invalid FindMy accessory JSON; check key encodings, "
                "timezone-aware dates and paired alignment fields."
            ) from None
    return inputs


def decode_advertisements(address, manufacturer_data, observed_at):
    """Decode Apple legacy TLVs using their declared length, not the remaining bytes."""
    if not MAC_PATTERN.fullmatch(address):
        return
    apple = manufacturer_data.get(0x004C, b"")
    offset = 0
    while offset + 2 <= len(apple):
        kind, size = apple[offset:offset + 2]
        end = offset + 2 + size
        if end > len(apple):
            return
        payload = apple[offset + 2:end]
        if kind == 0x12 and size in (2, 25):
            high_bits = payload[1] if size == 2 else payload[23]
            if high_bits <= 3:
                device = OfflineFindingDevice.from_ble_payload(
                    address, apple[offset:end], detected_at=observed_at
                )
                if device is not None:
                    yield device
        offset = end


def observation_key(device):
    if hasattr(device, "partial_adv_key"):
        return "nearby", device.partial_adv_key
    return "separated", device.adv_key_bytes


@dataclass(repr=False)
class ScanCapture:
    advertisements: int = 0
    types: Counter = field(default_factory=Counter)
    observations: dict = field(default_factory=dict)

    def receive(self, device, advertisement):
        self.advertisements += 1
        observed_at = datetime.now(timezone.utc)
        for observed in decode_advertisements(device.address, advertisement.manufacturer_data, observed_at):
            kind, key = observation_key(observed)
            self.types[(observed.device_type, kind)] += 1
            # Retain the most recent genuine observation, not processing time.
            self.observations[(kind, key)] = observed


def bluetooth_error(error):
    reason = getattr(getattr(error, "reason", None), "name", "")
    if reason in ("NO_BLUETOOTH", "NO_BLE_CENTRAL_ROLE"):
        return "No usable Bluetooth LE adapter. Connect or enable an adapter with BLE scanning support."
    if reason == "POWERED_OFF":
        return "Bluetooth is powered off. Turn Bluetooth on in system settings before scanning."
    if reason.startswith("DENIED_"):
        return (
            "Bluetooth permission was denied. On macOS allow this terminal/Python app in "
            "System Settings > Privacy & Security > Bluetooth; elsewhere check Bluetooth permissions."
        )
    return (
        "Bluetooth scan failed. Check that a BLE adapter is present and powered on, and grant "
        "Bluetooth permission to this terminal/Python app (macOS: Privacy & Security > Bluetooth). "
        "On Linux also check that the BlueZ service is running."
    )


async def scan(scan_seconds):
    capture = ScanCapture()
    try:
        options = {"cb": {"use_bdaddr": True}} if sys.platform == "darwin" else {}
        async with BleakScanner(detection_callback=capture.receive, **options):
            await asyncio.sleep(scan_seconds)
    except Exception as error:
        raise DiagnosticError(bluetooth_error(error)) from None
    return capture


@dataclass(repr=False, frozen=True)
class Candidate:
    key: object
    index: int
    primary_min: int
    primary_max: int


def candidates(accessory, lower, upper):
    """Equivalent to keys_at over the range, deriving secondary keys only once.

    FindMy 0.10.2 exposes only keys_at/keys_between publicly; both recompute two
    secondary EC keys per primary index. Reuse its pinned generators rather than
    reimplementing crypto. Tests compare this iterator against public keys_at.
    Secondary j can accompany primary [(j-2)*96, j*96-1], clipped at zero.
    """
    if lower > upper:
        return
    for index in range(lower, upper + 1):
        yield Candidate(accessory._primary_gen[index], index, index, index)
    for index in range(lower // 96 + 1, upper // 96 + 3):
        yield Candidate(accessory._secondary_gen[index], index,
                        max(lower, (index - 2) * 96), min(upper, index * 96 - 1))


@dataclass(repr=False, frozen=True)
class Match:
    key_type: object
    index: int
    observed_at: datetime
    advertisement_type: str
    primary_min: int
    primary_max: int
    within_bounds: bool
    ambiguous: bool = False


def match_input(item, observations):
    if not observations:
        return []
    accessory = item.accessory
    lower = max(0, min(accessory.get_min_index(device.detected_at - SEARCH_MARGIN)
                       for device in observations))
    upper = max(accessory.get_max_index(device.detected_at + SEARCH_MARGIN)
                for device in observations)
    lookup = defaultdict(list)
    for number, device in enumerate(observations):
        lookup[observation_key(device)].append((number, device))
    found = []
    primary_indices = defaultdict(set)
    for candidate in candidates(accessory, lower, upper):
        public = candidate.key.adv_key_bytes
        for kind, key in (("separated", public), ("nearby", public[:6])):
            for number, device in lookup.get((kind, key), ()):
                search_low = max(0, accessory.get_min_index(device.detected_at - SEARCH_MARGIN))
                search_high = accessory.get_max_index(device.detected_at + SEARCH_MARGIN)
                low = max(candidate.primary_min, search_low)
                high = min(candidate.primary_max, search_high)
                if low > high:
                    continue
                key_type = candidate.key.key_type
                if key_type == KeyPairType.PRIMARY:
                    primary_indices[number].add(candidate.index)
                within = (max(0, accessory.get_min_index(device.detected_at)) <= candidate.index
                          <= accessory.get_max_index(device.detected_at))
                found.append((number, Match(key_type, candidate.index, device.detected_at,
                                           kind, low, high, within)))
    return [Match(match.key_type, match.index, match.observed_at, match.advertisement_type,
                  match.primary_min, match.primary_max, match.within_bounds,
                  len(primary_indices[number]) > 1)
            for number, match in found]


def preferred_match(matches):
    return max(matches, default=None, key=lambda match: (
        match.key_type == KeyPairType.PRIMARY, not match.ambiguous,
        match.within_bounds, match.index, match.observed_at,
        match.advertisement_type == "separated",
    ))


@dataclass(repr=False)
class Change:
    item: InputFile
    payload: bytes
    observation: Match


def observed_alignment_json(original, index, observed_at):
    """Replace only the two alignment values, retaining all other JSON verbatim."""
    encoding = json.detect_encoding(original)
    text = original.decode(encoding)
    decoder = json.JSONDecoder()
    offset = text.index("{") + 1
    replacements = []
    values = {"alignment_index": index, "alignment_date": observed_at.isoformat()}
    while True:
        while text[offset].isspace() or text[offset] == ",":
            offset += 1
        if text[offset] == "}":
            break
        name, offset = decoder.raw_decode(text, offset)
        while text[offset].isspace() or text[offset] == ":":
            offset += 1
        _, end = decoder.raw_decode(text, offset)
        if name in values:
            replacements.append((offset, end, json.dumps(values[name])))
        offset = end
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    return text.encode(encoding)


def alignment_change(item, matches):
    # Do not use FindMy's is_from(accessory): it updates alignment to processing
    # time and treats a secondary match as an exact primary-index observation.
    eligible = [match for match in matches
                if match.key_type == KeyPairType.PRIMARY and match.within_bounds
                and not match.ambiguous]
    old_index = item.data["alignment_index"]
    old_date = item.data["alignment_date"]
    if old_date is not None:
        previous = timestamp(old_date)
        eligible = [match for match in eligible
                    if match.index > old_index and match.observed_at >= previous]
    else:
        paired = timestamp(item.data["paired_at"])
        eligible = [match for match in eligible if match.observed_at >= paired]
    if not eligible:
        return None
    observed = max(eligible, key=lambda match: (match.index, match.observed_at))
    return Change(item, observed_alignment_json(
        item.original, observed.index, observed.observed_at.astimezone(timezone.utc)
    ), observed)


def check_unchanged(item):
    try:
        raw, stamp = read_snapshot(item.path)
    except (OSError, DiagnosticError):
        raise DiagnosticError(f"{label(item.path)}: input was replaced or became unreadable; save aborted.") from None
    if stamp != item.signature or raw != item.original:
        raise DiagnosticError(f"{label(item.path)}: input changed since validation; save aborted.")


def backup_inputs(changes):
    """Create and verify private ZIPs beside each input group, before any replacements."""
    groups = defaultdict(list)
    for change in changes:
        groups[change.item.path.parent].append(change.item)
    archives = []
    for parent, items in groups.items():
        directory = parent / ".alignment-backups"
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise DiagnosticError("Backup directory must be a real, private directory with mode 0700.")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise DiagnosticError("Backup directory must be owned by the current user.")
        fd, name = tempfile.mkstemp(prefix="alignment-", suffix=".zip", dir=directory)
        archive = Path(name)
        try:
            with os.fdopen(fd, "w+b") as stream:
                os.fchmod(stream.fileno(), 0o600)
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                    for item in items:
                        member = zipfile.ZipInfo(item.path.name)
                        member.create_system = 3
                        member.external_attr = (stat.S_IFREG | 0o600) << 16
                        zipped.writestr(member, item.original)
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
                with zipfile.ZipFile(stream) as zipped:
                    if zipped.testzip() is not None or zipped.namelist() != [item.path.name for item in items]:
                        raise DiagnosticError("Backup ZIP verification failed; no inputs saved.")
                    for item in items:
                        if zipped.read(item.path.name) != item.original:
                            raise DiagnosticError("Backup content verification failed; no inputs saved.")
            archives.append(archive)
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
    return archives


def save_alignments(changes):
    if not changes:
        return []
    staged = []
    try:
        for change in changes:
            check_unchanged(change.item)
        archives = backup_inputs(changes)
        for change in changes:
            fd, name = tempfile.mkstemp(prefix=".alignment-", suffix=".tmp", dir=change.item.path.parent)
            temporary = Path(name)
            staged.append((change, temporary))
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(change.payload)
                stream.flush()
                os.fsync(stream.fileno())
        # Validate the entire batch, then check again immediately before each
        # per-file atomic replacement. This is not a multi-file transaction.
        for change in changes:
            check_unchanged(change.item)
        for change, temporary in staged:
            check_unchanged(change.item)
            os.replace(temporary, change.item.path)
        return archives
    except DiagnosticError as error:
        raise DiagnosticError(
            f"{error} Any already completed per-file replacements have verified originals "
            "in .alignment-backups."
        ) from None
    except Exception:
        raise DiagnosticError(
            "Alignment save failed; check directory permissions and disk space. "
            "Any completed replacements have verified originals in .alignment-backups."
        ) from None
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def report_matches(item, matches, saved=None):
    match = saved if saved is not None else preferred_match(matches)
    if match is None:
        print(f"{label(item.path)}: UNMATCHED (no matching advertisement in existing alignment bounds).")
        return
    observed = match.observed_at.astimezone(timezone.utc).isoformat()
    if match.key_type == KeyPairType.PRIMARY:
        state = "saved observed alignment" if saved is not None else "alignment unchanged"
        if match.ambiguous:
            state = "ambiguous partial-key match; alignment unchanged"
        elif not match.within_bounds:
            state = "outside strict alignment bounds; alignment unchanged"
        print(f"{label(item.path)}: MATCHED PRIMARY index {match.index}, "
              f"{match.advertisement_type}, observed {observed}; {state}.")
    else:
        print(f"{label(item.path)}: MATCHED SECONDARY index {match.index}, "
              f"{match.advertisement_type}, observed {observed}; conservative primary-index "
              f"bound {match.primary_min}..{match.primary_max}, not an exact alignment; unchanged.")


def positive_seconds(value):
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("scan seconds must be a positive finite number") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("scan seconds must be a positive finite number")
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-seconds", type=positive_seconds, default=30.0)
    parser.add_argument("--save-alignment", action="store_true",
                        help="save only non-regressing exact primary observations, with private backups")
    parser.add_argument("files", metavar="FILE", type=Path, nargs="+")
    args = parser.parse_args(argv)
    try:
        load_runtime()
        inputs = load_inputs(args.files)
        print(f"Validated {len(inputs)} input(s). Scanning Bluetooth for {args.scan_seconds:g} seconds...", flush=True)
        capture = asyncio.run(scan(args.scan_seconds))
        print(f"Scan completed: {capture.advertisements} BLE advertisement event(s).")
        for (device_type, kind), count in sorted(capture.types.items()):
            print(f"  {device_type} / {kind}: {count} legacy Offline Finding advertisement(s).")
        if not capture.observations:
            print("No legacy Offline Finding advertisements observed; this is not evidence of invalid keys.")
        print("Matching collected advertisements against existing alignment bounds...", flush=True)
        observations = list(capture.observations.values())
        # Finish ALL matching and planning before backing up or mutating any input.
        results = [(item, match_input(item, observations)) for item in inputs]
        changes = []
        if args.save_alignment:
            changes = [change for item, matches in results
                       if (change := alignment_change(item, matches)) is not None]
            archives = save_alignments(changes)
            for archive in archives:
                print(f"Verified private backup {label(archive)} in the input directory's .alignment-backups.")
        saved = {change.item.path: change.observation for change in changes}
        for item, matches in results:
            report_matches(item, matches, saved.get(item.path))
        if not args.save_alignment:
            print("Read-only: no files changed. --save-alignment explicitly enables safe primary-only updates.")
        return 0
    except DiagnosticError as error:
        print(f"Diagnostics: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Diagnostics interrupted. Completed per-file saves, if any, have private backups.", file=sys.stderr)
        return 130
    except Exception:
        print("Diagnostics failed; no error details printed because they may contain private data. "
              "Check the pinned dependencies and input files; any completed saves have private backups.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
