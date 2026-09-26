import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from python import diagnose as diag


PAIRED = datetime(2025, 1, 1, tzinfo=timezone.utc)
OBSERVED = PAIRED + timedelta(minutes=15 * 220)


def fixture(**updates):
    return {
        "type": "accessory",
        "master_key": bytes([1] * 28).hex(),
        "skn": bytes([2] * 32).hex(),
        "sks": bytes([3] * 32).hex(),
        "paired_at": PAIRED.isoformat(),
        "name": "Synthetic device",
        "model": "Synthetic model",
        "identifier": "synthetic-id",
        "serial_number": "synthetic-serial-not-for-output",
        "alignment_date": None,
        "alignment_index": None,
        "unknown_metadata": {"nested": [1, True, None, "unchanged"], "fraction": 1.25},
        **updates,
    }


def public_key(accessory, index, key_type):
    return next(key for key in accessory.keys_at(index) if key.key_type == key_type)


def advertisement(key, observed_at=OBSERVED, nearby=False, suffix=b""):
    payload = (bytes((0x12, 2, 0x10, key.adv_key_bytes[0] >> 6))
               if nearby else key.of_data(status=0x10))
    return next(diag.decode_advertisements(key.mac_address, {0x004C: payload + suffix}, observed_at))


class DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        diag.load_runtime()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()

    def write_input(self, name="tag.json", data=None):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture() if data is None else data), encoding="utf-8")
        return diag.load_inputs([path])[0]

    def primary(self, item, index=200, observed_at=OBSERVED, nearby=False):
        key = public_key(item.accessory, index, diag.KeyPairType.PRIMARY)
        return advertisement(key, observed_at, nearby)

    def test_cached_generators_agree_with_public_keys_at(self):
        accessory = self.write_input().accessory
        for lower, upper in ((0, 3), (94, 98), (190, 194), (210, 220)):
            with self.subTest(lower=lower, upper=upper):
                candidates = list(diag.candidates(accessory, lower, upper))
                for index in range(lower, upper + 1):
                    expected = {(key.key_type, key.adv_key_bytes) for key in accessory.keys_at(index)}
                    actual = {(candidate.key.key_type, candidate.key.adv_key_bytes)
                              for candidate in candidates
                              if candidate.primary_min <= index <= candidate.primary_max}
                    self.assertEqual(actual, expected)
                expected = {(key.key_type, key.adv_key_bytes)
                            for _, key in accessory.keys_between(lower, upper)}
                actual = {(candidate.key.key_type, candidate.key.adv_key_bytes)
                          for candidate in candidates}
                self.assertEqual(actual, expected)

    def test_primary_full_and_partial_matches_use_observation_not_current_time(self):
        for nearby in (False, True):
            with self.subTest(nearby=nearby):
                item = self.write_input()
                observed = self.primary(item, nearby=nearby)
                primary = public_key(item.accessory, 200, diag.KeyPairType.PRIMARY)
                self.assertTrue(observed.is_from(primary))
                matches = diag.match_input(item, [observed])
                match = diag.preferred_match(matches)
                self.assertEqual(match.key_type, diag.KeyPairType.PRIMARY)
                self.assertEqual(match.index, 200)
                self.assertEqual(match.observed_at, OBSERVED)
                data = json.loads(diag.alignment_change(item, matches).payload)
                self.assertEqual(data["alignment_index"], 200)
                self.assertEqual(data["alignment_date"], OBSERVED.isoformat())
                self.assertEqual(data["unknown_metadata"], item.data["unknown_metadata"])

    def test_secondary_only_has_conservative_bounds_and_never_saves(self):
        item = self.write_input()
        secondary_keys = [candidate for candidate in diag.candidates(item.accessory, 192, 192)
                          if candidate.key.key_type == diag.KeyPairType.SECONDARY]
        for candidate in secondary_keys:
            for nearby in (False, True):
                with self.subTest(index=candidate.index, nearby=nearby):
                    observed = advertisement(candidate.key, nearby=nearby)
                    self.assertTrue(observed.is_from(candidate.key))
                    matches = diag.match_input(item, [observed])
                    match = diag.preferred_match(matches)
                    self.assertEqual(match.key_type, diag.KeyPairType.SECONDARY)
                    self.assertEqual(match.index, candidate.index)
                    self.assertEqual(match.primary_min, max(0, (candidate.index - 2) * 96))
                    self.assertEqual(match.primary_max, min(268, candidate.index * 96 - 1))
                    self.assertIsNone(diag.alignment_change(item, matches))
        self.assertEqual(item.path.read_bytes(), item.original)
        self.assertFalse((self.directory / ".alignment-backups").exists())

    def test_primary_takes_precedence_over_secondary(self):
        item = self.write_input()
        secondary = next(candidate.key for candidate in diag.candidates(item.accessory, 192, 192)
                         if candidate.key.key_type == diag.KeyPairType.SECONDARY)
        matches = diag.match_input(item, [advertisement(secondary), self.primary(item)])
        match = diag.preferred_match(matches)
        self.assertEqual((match.key_type, match.index), (diag.KeyPairType.PRIMARY, 200))
        self.assertEqual(json.loads(diag.alignment_change(item, matches).payload)["alignment_index"], 200)

    def test_unmatched_and_read_only_are_byte_identical(self):
        item = self.write_input()
        other = diag.FindMyAccessory.from_json(fixture(skn=bytes([4] * 32).hex()))
        unrelated = advertisement(public_key(other, 200, diag.KeyPairType.PRIMARY))
        self.assertEqual(diag.match_input(item, [unrelated]), [])
        matches = diag.match_input(item, [self.primary(item)])
        self.assertEqual(diag.preferred_match(matches).index, 200)
        self.assertEqual(item.path.read_bytes(), item.original)
        self.assertEqual(set(self.directory.iterdir()), {item.path})

    def test_observation_margin_does_not_authorize_out_of_bounds_save(self):
        item = self.write_input()
        # The search includes +/-12h, but this key is beyond the strict maximum 220.
        matches = diag.match_input(item, [self.primary(item, index=225)])
        self.assertEqual(diag.preferred_match(matches).index, 225)
        self.assertFalse(diag.preferred_match(matches).within_bounds)
        self.assertIsNone(diag.alignment_change(item, matches))

    def test_alignment_does_not_regress_date_or_index(self):
        aligned_at = PAIRED + timedelta(minutes=15 * 200)
        item = self.write_input(data=fixture(alignment_index=200, alignment_date=aligned_at.isoformat()))
        for index, date in ((199, OBSERVED), (200, OBSERVED),
                            (201, aligned_at - timedelta(minutes=15))):
            with self.subTest(index=index, date=date):
                matches = diag.match_input(item, [self.primary(item, index=index, observed_at=date)])
                self.assertIsNone(diag.alignment_change(item, matches))

    def test_unknown_metadata_backup_permissions_and_repeat_are_preserved(self):
        item = self.write_input()
        matches = diag.match_input(item, [self.primary(item)])
        change = diag.alignment_change(item, matches)
        archives = diag.save_alignments([change])
        self.assertEqual(len(archives), 1)
        with zipfile.ZipFile(archives[0]) as archive:
            self.assertEqual(archive.namelist(), [item.path.name])
            self.assertEqual(archive.read(item.path.name), item.original)
            self.assertEqual((archive.getinfo(item.path.name).external_attr >> 16) & 0o777, 0o600)
        updated = json.loads(item.path.read_bytes())
        for key in set(item.data) - {"alignment_date", "alignment_index"}:
            self.assertEqual(updated[key], item.data[key])
        self.assertEqual(updated["alignment_index"], 200)
        self.assertEqual(updated["alignment_date"], OBSERVED.isoformat())
        self.assertEqual(stat.S_IMODE(item.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(archives[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(archives[0].parent.stat().st_mode), 0o700)
        reloaded = diag.load_inputs([item.path])[0]
        later_same_key = self.primary(reloaded, observed_at=OBSERVED + timedelta(minutes=1))
        self.assertIsNone(diag.alignment_change(reloaded, diag.match_input(reloaded, [later_same_key])))
        diag.save_alignments([])
        self.assertEqual(list(archives[0].parent.iterdir()), archives)

    def test_alignment_changes_only_alignment_values_not_json_formatting(self):
        item = self.write_input()
        original = item.original.replace(b'"fraction": 1.25', b'"fraction": 1.2500000000000000000000001')
        original = original.replace(b'"alignment_date": null', b'"alignment_date" : null')
        item.path.write_bytes(original)
        item = diag.load_inputs([item.path])[0]
        change = diag.alignment_change(item, diag.match_input(item, [self.primary(item)]))
        expected = original.replace(b'"alignment_index": null', b'"alignment_index": 200')
        expected = expected.replace(b'"alignment_date" : null',
                                    b'"alignment_date" : "' + OBSERVED.isoformat().encode() + b'"')
        self.assertEqual(change.payload, expected)

    def test_separate_input_directories_backup_without_name_collisions(self):
        first = self.write_input("one/tag.json")
        second = self.write_input("two/tag.json", fixture(skn=bytes([4] * 32).hex()))
        items = [first, second]
        changes = [diag.alignment_change(item, diag.match_input(item, [self.primary(item)])) for item in items]
        archives = diag.save_alignments(changes)
        self.assertEqual({archive.parent for archive in archives},
                         {item.path.parent / ".alignment-backups" for item in items})
        for item in items:
            archive = next(archive for archive in archives if archive.parent.parent == item.path.parent)
            with zipfile.ZipFile(archive) as zipped:
                self.assertEqual(zipped.read("tag.json"), item.original)

    def test_concurrent_mutation_aborts_entire_batch_before_replacement(self):
        first = self.write_input("one.json")
        second = self.write_input("two.json")
        changes = [diag.alignment_change(item, diag.match_input(item, [self.primary(item)]))
                   for item in (first, second)]
        newer = b'{"user_changed_this": true}\n'
        original_backup = diag.backup_inputs

        def concurrent_editor(batch):
            archives = original_backup(batch)
            second.path.write_bytes(newer)
            return archives

        with patch.object(diag, "backup_inputs", side_effect=concurrent_editor):
            with self.assertRaises(diag.DiagnosticError):
                diag.save_alignments(changes)
        self.assertEqual(first.path.read_bytes(), first.original)
        self.assertEqual(second.path.read_bytes(), newer)
        self.assertFalse(list(self.directory.glob(".alignment-*.tmp")))
        with zipfile.ZipFile(next((self.directory / ".alignment-backups").iterdir())) as backup:
            self.assertEqual(backup.read(second.path.name), second.original)

    def test_identical_bytes_in_replaced_inode_still_abort(self):
        item = self.write_input()
        change = diag.alignment_change(item, diag.match_input(item, [self.primary(item)]))
        replacement = self.directory / "replacement.json"
        replacement.write_bytes(item.original)
        replacement.replace(item.path)
        with self.assertRaises(diag.DiagnosticError):
            diag.save_alignments([change])
        self.assertFalse((self.directory / ".alignment-backups").exists())

    def test_tlv_declared_lengths_allow_other_apple_records(self):
        item = self.write_input()
        key = public_key(item.accessory, 200, diag.KeyPairType.PRIMARY)
        prefix, suffix = b"\x10\x03\x01\x02\x03", b"\x07\x01\x00"
        for nearby in (False, True):
            payload = bytes((0x12, 2, 0x10, key.adv_key_bytes[0] >> 6)) if nearby else key.of_data(0x10)
            records = list(diag.decode_advertisements(key.mac_address, {0x004C: prefix + payload + suffix}, OBSERVED))
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0].is_from(key))
        for raw in (b"\x12\x19\x00", b"\x12\x03\x00\x00\x00", b"\x10\x00", b"\x12\x02\x00\xff"):
            self.assertEqual(list(diag.decode_advertisements(key.mac_address, {0x004C: raw}, OBSERVED)), [])
        self.assertEqual(list(diag.decode_advertisements(key.mac_address, {0xFFFF: key.of_data()}, OBSERVED)), [])

    def test_all_inputs_validate_before_scanning(self):
        valid = self.write_input()
        invalid = self.directory / "invalid.json"
        for invalid_data in (fixture(master_key="bad"), fixture(alignment_index=3),
                             fixture(alignment_date=OBSERVED.isoformat(), alignment_index=True),
                             fixture(paired_at="2025-01-01T00:00:00"), fixture(type="keypair")):
            invalid.write_text(json.dumps(invalid_data), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()), patch.object(diag, "scan") as scanner:
                self.assertEqual(diag.main([str(valid.path), str(invalid)]), 1)
                scanner.assert_not_called()
            self.assertEqual(valid.path.read_bytes(), valid.original)
        invalid.write_bytes(b'{"type":"accessory","type":"accessory"}')
        with self.assertRaises(diag.DiagnosticError):
            diag.load_inputs([invalid])

    def test_matching_failure_never_saves_an_earlier_match(self):
        first = self.write_input("one.json")
        second = self.write_input("two.json")
        observed = self.primary(first)
        capture = diag.ScanCapture(observations={diag.observation_key(observed): observed})
        original_match = diag.match_input

        def failure_on_second(item, observations):
            if item.path.name == second.path.name:
                raise RuntimeError("synthetic matching failure")
            return original_match(item, observations)

        with patch.object(diag, "scan", return_value=capture), \
                patch.object(diag, "match_input", side_effect=failure_on_second), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = diag.main(["--save-alignment", str(first.path), str(second.path)])
        self.assertEqual(result, 1)
        self.assertEqual(first.path.read_bytes(), first.original)
        self.assertEqual(second.path.read_bytes(), second.original)
        self.assertFalse((self.directory / ".alignment-backups").exists())

    def test_reports_exclude_private_metadata_and_advertisement_identifiers(self):
        item = self.write_input()
        observed = self.primary(item)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            diag.report_matches(item, diag.match_input(item, [observed]))
        for secret in (item.data["master_key"], item.data["skn"], item.data["sks"],
                       item.data["serial_number"], observed.mac_address, observed.adv_key_b64):
            self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    unittest.main()
