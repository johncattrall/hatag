use super::*;
use crate::output::{accessory_filename, accessory_to_plist, convert_home_assistant, write_accessory, OutputFormat};
use std::path::Path;
use std::time::SystemTime;

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("hatag-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn time(value: &str) -> SystemTime {
    plist::Date::from_xml_format(value).unwrap().into()
}

fn master(stable_id: &str) -> MasterBeaconRecord {
    MasterBeaconRecord {
        stable_identifier: stable_id.to_string(),
        private_key: vec![1; 28],
        shared_secret: vec![2; 32],
        shared_secret_2: Some(vec![3; 32]),
        pairing_date: Some(time("2022-05-12T13:21:41Z")),
        model: "AirTag".to_string(),
        ..Default::default()
    }
}

fn accessory() -> BeaconAccessory {
    assemble_accessories(
        HashMap::from([("fixture-record".to_string(), master("2006~#00-device~#full-identifier"))]),
        HashMap::new(),
        HashMap::new(),
    ).remove("fixture-record").unwrap()
}

fn json_file(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn json_fixture() -> serde_json::Value {
    serde_json::json!({
        "type": "accessory",
        "master_key": "01".repeat(28),
        "skn": "02".repeat(32),
        "sks": "03".repeat(32),
        "paired_at": "2022-05-12T13:21:41+00:00",
        "name": "House keys",
        "model": "AirTag",
        "identifier": "2006~#00-device~#full-identifier",
        "group_identifier": null,
        "serial_number": null,
        "alignment_date": null,
        "alignment_index": null,
    })
}

fn write_json_fixture(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn naming_and_alignment_join_by_cloudkit_record_id() {
    let id = "cloudkit-record";
    let stable_id = "2006~#00-device";
    let observed_at = time("2026-09-26T03:00:00Z");
    let accessories = assemble_accessories(
        HashMap::from([(id.to_string(), master(stable_id))]),
        HashMap::from([(id.to_string(), ("name-record".to_string(), BeaconNamingRecord {
            associated_beacon: id.to_string(),
            name: "House keys".to_string(),
            emoji: "key".to_string(),
            ..Default::default()
        }))]),
        HashMap::from([(id.to_string(), ("alignment-record".to_string(), KeyAlignmentRecord {
            beacon_identifier: id.to_string(),
            last_index_observed: 42,
            last_index_observation_date: Some(observed_at),
        }))]),
    );
    let fixture = FixtureDirectory::new();
    let paths = write_accessory(&fixture.0, id, &accessories[id], OutputFormat::Both).unwrap();
    let json = json_file(&paths[0]);
    assert_eq!(json["name"], "House keys");
    assert_eq!(json["identifier"], stable_id);
    assert_eq!(json["alignment_index"], 42);
    assert_eq!(json["alignment_date"], "2026-09-26T03:00:00+00:00");
    let plist = plist::Value::from_file(&paths[1]).unwrap();
    let dict = plist.as_dictionary().unwrap();
    assert_eq!(dict["name"].as_string(), Some("House keys"));
    assert_eq!(dict["identifier"].as_string(), Some(stable_id));
    assert_eq!(dict["lastIndexObserved"].as_signed_integer(), Some(42));
    assert_eq!(dict["lastIndexObservationDate"].as_date(), Some(observed_at.into()));
}

#[test]
fn duplicate_names_and_repeat_exports_preserve_each_version() {
    let fixture = FixtureDirectory::new();
    let mut first = accessory();
    first.naming.name = "Keys/home".into();
    let mut second = accessory();
    second.naming.name = "Keys:home".into();
    second.master_record.stable_identifier = "2006~#00-second".into();
    let first_path = write_accessory(&fixture.0, "record-one", &first, OutputFormat::Json).unwrap().remove(0);
    let second_path = write_accessory(&fixture.0, "record-two", &second, OutputFormat::Json).unwrap().remove(0);
    assert_ne!(first_path, second_path);
    assert_eq!(json_file(&first_path)["name"], "Keys/home");
    assert_eq!(json_file(&second_path)["identifier"], "2006~#00-second");
    let original = std::fs::read(&first_path).unwrap();
    first.alignment.last_index_observed = 123456;
    first.alignment.last_index_observation_date = Some(time("2026-09-26T00:00:00Z"));
    let updated = write_accessory(&fixture.0, "record-one", &first, OutputFormat::Json).unwrap().remove(0);
    assert_ne!(updated, first_path);
    assert_eq!(std::fs::read(&first_path).unwrap(), original);
    assert_eq!(json_file(&updated)["alignment_index"], 123456);
    assert_eq!(write_accessory(&fixture.0, "record-one", &first, OutputFormat::Json).unwrap(), vec![updated]);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 3);
}

#[test]
fn filenames_are_bounded_safe_and_hash_the_entire_record_id() {
    for name in ["", "../outside", &"鑰匙".repeat(100), &"a".repeat(120)] {
        let filename = accessory_filename(name, "record/with:punctuation");
        assert!(filename.len() <= 255);
        assert!(Path::new(&filename).with_extension("findmy.json").as_os_str().len() <= 255);
        assert_eq!(Path::new(&filename).components().count(), 1);
        assert!(filename.ends_with(".plist"));
    }
    assert_ne!(accessory_filename("Keys", "same-prefix/one"), accessory_filename("Keys", "same-prefix/two"));
    assert_ne!(accessory_filename("", "one"), accessory_filename("", "two"));
    let prefix = "a".repeat(120);
    assert_ne!(accessory_filename(&format!("{prefix}one"), "record-one"), accessory_filename(&format!("{prefix}two"), "record-two"));
    let mut missing = master("stable-id");
    missing.model.clear();
    let accessories = assemble_accessories(
        HashMap::from([("model".to_string(), master("one")), ("unknown".to_string(), missing)]),
        HashMap::new(), HashMap::new(),
    );
    assert_eq!(accessories["model"].naming.name, "AirTag");
    assert_eq!(accessories["unknown"].naming.name, "Unknown");
}

#[test]
fn json_preserves_full_metadata_key_tails_dates_and_zero_alignment() {
    let fixture = FixtureDirectory::new();
    let mut acc = accessory();
    let name = "鑰匙 / House keys".repeat(20);
    acc.naming.name = name.clone();
    acc.master_record.private_key = [vec![9; 7], (1..=28).collect()].concat();
    acc.master_record.secure_locations_shared_secret = Some(vec![4; 32]);
    acc.master_record.pairing_date = Some(time("2022-05-12T13:21:41.125Z"));
    acc.alignment.last_index_observed = 0;
    acc.alignment.last_index_observation_date = Some(time("2026-09-26T03:00:00.5Z"));
    let path = write_accessory(&fixture.0, "record", &acc, OutputFormat::Json).unwrap().remove(0);
    let json = json_file(&path);
    assert_eq!(json["type"], "accessory");
    assert_eq!(json["master_key"], "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c");
    assert_eq!(json["skn"], "02".repeat(32));
    assert_eq!(json["sks"], "03".repeat(32));
    assert_eq!(json["name"], name);
    assert_eq!(json["identifier"], "2006~#00-device~#full-identifier");
    assert_eq!(json["model"], "AirTag");
    assert_eq!(json["paired_at"], "2022-05-12T13:21:41.125+00:00");
    assert_eq!(json["alignment_date"], "2026-09-26T03:00:00.500+00:00");
    assert_eq!(json["alignment_index"], 0);
}

#[test]
fn unknown_alignment_stays_null_and_secondary_fallback_is_preserved() {
    let fixture = FixtureDirectory::new();
    let mut acc = accessory();
    acc.master_record.shared_secret_2 = None;
    acc.master_record.secure_locations_shared_secret = Some(vec![4; 32]);
    let path = write_accessory(&fixture.0, "record", &acc, OutputFormat::Json).unwrap().remove(0);
    let json = json_file(&path);
    assert!(json["alignment_date"].is_null());
    assert!(json["alignment_index"].is_null());
    assert_eq!(json["sks"], "04".repeat(32));
}

#[test]
fn plist_uses_findmy_nested_keys_and_whole_second_utc_dates() {
    let fixture = FixtureDirectory::new();
    let mut acc = accessory();
    acc.master_record.pairing_date = Some(time("2022-05-12T13:21:41.125Z"));
    acc.alignment.last_index_observation_date = Some(time("2026-09-26T03:00:00.999Z"));
    acc.alignment.last_index_observed = 123456;
    let path = write_accessory(&fixture.0, "record", &acc, OutputFormat::Plist).unwrap().remove(0);
    let value = plist::Value::from_file(&path).unwrap();
    let dict = value.as_dictionary().unwrap();
    for (field, expected) in [("privateKey", vec![1; 28]), ("sharedSecret", vec![2; 32]), ("secondarySharedSecret", vec![3; 32])] {
        let key = dict[field].as_dictionary().unwrap()["key"].as_dictionary().unwrap();
        assert_eq!(key["data"].as_data(), Some(expected.as_slice()));
    }
    assert_eq!(dict["pairingDate"].as_date(), Some(time("2022-05-12T13:21:41Z").into()));
    assert_eq!(dict["lastIndexObservationDate"].as_date(), Some(time("2026-09-26T03:00:00Z").into()));
    assert_eq!(dict["lastIndexObserved"].as_signed_integer(), Some(123456));
    assert_eq!(dict["identifier"].as_string(), Some("2006~#00-device~#full-identifier"));
}

#[test]
fn invalid_native_records_never_leave_partial_both_outputs() {
    let fixture = FixtureDirectory::new();
    let mut invalid = Vec::new();
    let mut acc = accessory();
    acc.master_record.pairing_date = None;
    invalid.push(acc);
    for size in [0, 27] {
        let mut acc = accessory();
        acc.master_record.private_key.resize(size, 1);
        invalid.push(acc);
    }
    for size in [31, 33] {
        let mut acc = accessory();
        acc.master_record.shared_secret.resize(size, 2);
        invalid.push(acc);
        let mut acc = accessory();
        acc.master_record.shared_secret_2 = Some(vec![3; size]);
        invalid.push(acc);
    }
    let mut acc = accessory();
    acc.master_record.shared_secret_2 = None;
    invalid.push(acc);
    let mut acc = accessory();
    acc.master_record.stable_identifier.clear();
    invalid.push(acc);
    let mut acc = accessory();
    acc.alignment.last_index_observed = 12;
    invalid.push(acc);
    let mut acc = accessory();
    acc.alignment.last_index_observed = -1;
    acc.alignment.last_index_observation_date = Some(time("2026-09-26T00:00:00Z"));
    invalid.push(acc);
    for (index, acc) in invalid.iter().enumerate() {
        let output = fixture.0.join(index.to_string());
        assert!(write_accessory(&output, "record", acc, OutputFormat::Both).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn both_keeps_matching_basenames_when_one_old_format_conflicts() {
    let fixture = FixtureDirectory::new();
    let acc = accessory();
    let existing = fixture.0.join(accessory_filename(&acc.naming.name, "record"));
    std::fs::write(&existing, b"previous user data").unwrap();
    let outputs = write_accessory(&fixture.0, "record", &acc, OutputFormat::Both).unwrap();
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].with_extension("").with_extension("plist"), outputs[1]);
    assert!(!existing.with_extension("findmy.json").exists());
    assert_eq!(std::fs::read(existing).unwrap(), b"previous user data");
    assert_eq!(write_accessory(&fixture.0, "record", &acc, OutputFormat::Both).unwrap(), outputs);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 3);
}

fn legacy_plist() -> plist::Value {
    let mut value = accessory_to_plist(&accessory());
    let dict = value.as_dictionary_mut().unwrap();
    for field in ["privateKey", "sharedSecret", "secondarySharedSecret"] {
        let wrapped = dict.remove(field).unwrap();
        let bytes = wrapped.as_dictionary().unwrap()["key"].as_dictionary().unwrap()["data"].clone();
        dict.insert(field.into(), bytes);
    }
    value
}

#[test]
fn legacy_raw_and_nested_plists_convert_equivalently_including_fractional_dates() {
    let fixture = FixtureDirectory::new();
    let mut results = Vec::new();
    for (index, mut value) in [legacy_plist(), accessory_to_plist(&accessory())].into_iter().enumerate() {
        let dict = value.as_dictionary_mut().unwrap();
        let private = [vec![9; 7], vec![5; 28]].concat();
        if index == 0 {
            dict.insert("privateKey".into(), plist::Value::Data(private));
        } else {
            dict.get_mut("privateKey").unwrap().as_dictionary_mut().unwrap()
                .get_mut("key").unwrap().as_dictionary_mut().unwrap()
                .insert("data".into(), plist::Value::Data(private));
        }
        dict.insert("pairingDate".into(), plist::Value::Date(time("2022-05-12T13:21:41.125Z").into()));
        dict.insert("lastIndexObservationDate".into(), plist::Value::Date(time("2026-09-26T03:00:00.5Z").into()));
        dict.insert("lastIndexObserved".into(), plist::Value::Integer(0.into()));
        dict.insert("groupIdentifier".into(), plist::Value::String("group-full".into()));
        dict.insert("serialNumber".into(), plist::Value::String("serial-full".into()));
        let source = fixture.0.join(format!("{index}.plist"));
        value.to_file_xml(&source).unwrap();
        let target = convert_home_assistant(&[source], &fixture.0.join(index.to_string())).unwrap().remove(0);
        results.push(json_file(&target));
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0]["master_key"], "05".repeat(28));
    assert_eq!(results[0]["paired_at"], "2022-05-12T13:21:41.125+00:00");
    assert_eq!(results[0]["alignment_date"], "2026-09-26T03:00:00.500+00:00");
    assert_eq!(results[0]["alignment_index"], 0);
    assert_eq!(results[0]["group_identifier"], "group-full");
    assert_eq!(results[0]["serial_number"], "serial-full");
}

#[test]
fn legacy_secondary_fallback_and_unknown_alignment_survive_conversion() {
    let fixture = FixtureDirectory::new();
    let mut value = legacy_plist();
    let dict = value.as_dictionary_mut().unwrap();
    let secondary = dict.remove("secondarySharedSecret").unwrap();
    dict.insert("secureLocationsSharedSecret".into(), secondary);
    dict.remove("name");
    let source = fixture.0.join("Named tag.plist");
    value.to_file_binary(&source).unwrap();
    let target = convert_home_assistant(&[source], &fixture.0.join("out")).unwrap().remove(0);
    let result = json_file(&target);
    assert_eq!(result["sks"], "03".repeat(32));
    assert_eq!(result["name"], "Named tag");
    assert!(result["alignment_date"].is_null());
    assert!(result["alignment_index"].is_null());
}

#[test]
fn json_conversion_preserves_metadata_and_alignment_without_repeated_suffixes() {
    let fixture = FixtureDirectory::new();
    let source = fixture.0.join("tag.findmy.json");
    let mut value = json_fixture();
    value["alignment_date"] = serde_json::json!("2026-09-26T04:00:00.123456+01:00");
    value["alignment_index"] = serde_json::json!(123456);
    value["serial_number"] = serde_json::json!("serial-full");
    value["group_identifier"] = serde_json::json!("group-full");
    value["custom_metadata"] = serde_json::json!({"source": "local Bluetooth alignment"});
    write_json_fixture(&source, &value);
    let first = convert_home_assistant(&[source], &fixture.0.join("one")).unwrap().remove(0);
    let second = convert_home_assistant(&[first.clone()], &fixture.0.join("two")).unwrap().remove(0);
    assert_eq!(json_file(&first), value);
    assert_eq!(json_file(&second), value);
    assert_eq!(first.file_name(), second.file_name());
    assert_eq!(first.file_name().unwrap().to_str().unwrap().matches(".findmy.json").count(), 1);
    assert_eq!(convert_home_assistant(&[first], &fixture.0.join("two")).unwrap(), vec![second.clone()]);
    assert_eq!(json_file(&second), value);
}

#[test]
fn nameless_json_conversion_keeps_a_stable_filename() {
    let fixture = FixtureDirectory::new();
    let source = fixture.0.join("tag.findmy.json");
    let mut value = json_fixture();
    value["name"] = serde_json::Value::Null;
    write_json_fixture(&source, &value);
    let first = convert_home_assistant(&[source], &fixture.0.join("one")).unwrap().remove(0);
    let second = convert_home_assistant(&[first.clone()], &fixture.0.join("two")).unwrap().remove(0);
    assert_eq!(first.file_name(), second.file_name());
    assert!(json_file(&second)["name"].is_null());
}

#[test]
fn malformed_json_keys_dates_and_partial_alignment_are_rejected() {
    let fixture = FixtureDirectory::new();
    let cases = [
        ("master_key", serde_json::json!("01".repeat(27))),
        ("master_key", serde_json::json!("01".repeat(29))),
        ("skn", serde_json::json!("gg".repeat(32))),
        ("sks", serde_json::json!("02".repeat(31))),
        ("paired_at", serde_json::Value::Null),
        ("paired_at", serde_json::json!("2026-02-30T00:00:00Z")),
        ("paired_at", serde_json::json!("2026-09-26T00:00:00")),
        ("paired_at", serde_json::json!("2016-12-31T23:59:60Z")),
        ("identifier", serde_json::json!("")),
        ("type", serde_json::json!("key_pair")),
        ("name", serde_json::json!(12)),
        ("alignment_index", serde_json::json!(12)),
        ("alignment_date", serde_json::json!("2026-09-26T00:00:00Z")),
    ];
    let source = fixture.0.join("source.json");
    let output = fixture.0.join("out");
    for (field, replacement) in cases {
        let mut value = json_fixture();
        value[field] = replacement;
        write_json_fixture(&source, &value);
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
        assert!(!output.exists());
    }
    for index in [serde_json::json!(-1), serde_json::json!(true), serde_json::json!(1.5)] {
        let mut value = json_fixture();
        value["alignment_date"] = serde_json::json!("2026-09-26T00:00:00Z");
        value["alignment_index"] = index;
        write_json_fixture(&source, &value);
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
    }
    for date in ["not a date", "2026-02-30T00:00:00Z", "2026-09-26T00:00:00"] {
        let mut value = json_fixture();
        value["alignment_date"] = serde_json::json!(date);
        value["alignment_index"] = serde_json::json!(0);
        write_json_fixture(&source, &value);
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
    }
    for field in ["paired_at", "alignment_date", "alignment_index"] {
        let mut value = json_fixture();
        value.as_object_mut().unwrap().remove(field);
        write_json_fixture(&source, &value);
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
    }
}

#[test]
fn malformed_plist_keys_dates_and_partial_alignment_are_rejected() {
    let fixture = FixtureDirectory::new();
    let source = fixture.0.join("source.plist");
    let output = fixture.0.join("out");
    let cases = [
        ("privateKey", plist::Value::Data(vec![1; 27])),
        ("sharedSecret", plist::Value::Data(vec![2; 31])),
        ("secondarySharedSecret", plist::Value::Data(vec![3; 33])),
        ("privateKey", plist::Value::String("not binary".into())),
        ("pairingDate", plist::Value::String("2022-05-12T13:21:41Z".into())),
        ("lastIndexObservationDate", plist::Value::Date(time("2026-09-26T00:00:00Z").into())),
        ("lastIndexObserved", plist::Value::Integer(42.into())),
    ];
    for (field, replacement) in cases {
        let mut value = legacy_plist();
        value.as_dictionary_mut().unwrap().insert(field.into(), replacement);
        value.to_file_xml(&source).unwrap();
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
        assert!(!output.exists());
    }
    for index in [plist::Value::Integer((-1).into()), plist::Value::Boolean(true), plist::Value::Real(1.5)] {
        let mut value = legacy_plist();
        let dict = value.as_dictionary_mut().unwrap();
        dict.insert("lastIndexObservationDate".into(), plist::Value::Date(time("2026-09-26T00:00:00Z").into()));
        dict.insert("lastIndexObserved".into(), index);
        value.to_file_xml(&source).unwrap();
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
    }
    for field in ["pairingDate", "identifier", "secondarySharedSecret"] {
        let mut value = legacy_plist();
        value.as_dictionary_mut().unwrap().remove(field);
        value.to_file_xml(&source).unwrap();
        assert!(convert_home_assistant(&[source.clone()], &output).is_err());
    }
    let mut value = legacy_plist();
    let dict = value.as_dictionary_mut().unwrap();
    dict.insert("lastIndexObservationDate".into(), plist::Value::String("not a date".into()));
    dict.insert("lastIndexObserved".into(), plist::Value::Integer(0.into()));
    value.to_file_xml(&source).unwrap();
    assert!(convert_home_assistant(&[source.clone()], &output).is_err());
    let mut malformed_key = accessory_to_plist(&accessory());
    malformed_key.as_dictionary_mut().unwrap()["privateKey"].as_dictionary_mut().unwrap().remove("key");
    malformed_key.to_file_xml(&source).unwrap();
    assert!(convert_home_assistant(&[source], &output).is_err());
}

#[test]
fn conversion_prechecks_every_input_and_duplicate_destination() {
    let fixture = FixtureDirectory::new();
    let first = fixture.0.join("first.plist");
    let second = fixture.0.join("second.plist");
    let output = fixture.0.join("out");
    legacy_plist().to_file_xml(&first).unwrap();
    legacy_plist().to_file_xml(&second).unwrap();
    assert!(convert_home_assistant(&[first.clone(), second.clone()], &output).is_err());
    assert!(!output.exists());
    std::fs::write(&second, b"not a plist").unwrap();
    assert!(convert_home_assistant(&[first, second], &output).is_err());
    assert!(!output.exists());
    assert!(convert_home_assistant(&[], &output).is_err());
}

#[cfg(unix)]
#[test]
fn exports_create_private_directories_files_and_reject_symlink_targets() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = FixtureDirectory::new();
    let output = fixture.0.join("private").join("exports");
    let acc = accessory();
    let paths = write_accessory(&output, "record", &acc, OutputFormat::Both).unwrap();
    for directory in [output.as_path(), output.parent().unwrap()] {
        assert_eq!(std::fs::metadata(directory).unwrap().permissions().mode() & 0o777, 0o700);
    }
    for path in paths {
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let protected = fixture.0.join("protected");
    std::fs::write(&protected, b"user data").unwrap();
    let link = output.join(accessory_filename(&acc.naming.name, "other-record")).with_extension("findmy.json");
    symlink(&protected, &link).unwrap();
    assert!(write_accessory(&output, "other-record", &acc, OutputFormat::Json).is_err());
    assert_eq!(std::fs::read(&protected).unwrap(), b"user data");
    let linked_directory = fixture.0.join("linked-directory");
    symlink(&output, &linked_directory).unwrap();
    assert!(write_accessory(&linked_directory, "third-record", &acc, OutputFormat::Json).is_err());
}

#[test]
fn rerunning_export_preserves_locally_aligned_json_and_unknown_fields() {
    let fixture = FixtureDirectory::new();
    let acc = accessory();
    let original_path = write_accessory(&fixture.0, "record", &acc, OutputFormat::Json).unwrap().remove(0);
    let mut aligned = json_file(&original_path);
    aligned["alignment_date"] = serde_json::json!("2026-09-26T03:00:00+00:00");
    aligned["alignment_index"] = serde_json::json!(98765);
    aligned["custom_metadata"] = serde_json::json!({"keep": true});
    write_json_fixture(&original_path, &aligned);
    let original_bytes = std::fs::read(&original_path).unwrap();
    let fresh_path = write_accessory(&fixture.0, "record", &acc, OutputFormat::Json).unwrap().remove(0);
    assert_ne!(fresh_path, original_path);
    assert_eq!(std::fs::read(&original_path).unwrap(), original_bytes);
    assert_eq!(json_file(&fresh_path)["master_key"], aligned["master_key"]);
    assert!(json_file(&fresh_path)["alignment_index"].is_null());
    assert_eq!(write_accessory(&fixture.0, "record", &acc, OutputFormat::Json).unwrap(), vec![fresh_path]);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
}

#[test]
fn repeated_conversion_keeps_old_keys_and_uses_existing_identical_version() {
    let fixture = FixtureDirectory::new();
    let source = fixture.0.join("input.json");
    let output = fixture.0.join("out");
    let original = json_fixture();
    write_json_fixture(&source, &original);
    let first = convert_home_assistant(&[source.clone()], &output).unwrap().remove(0);
    let mut changed = original.clone();
    changed["skn"] = serde_json::json!("04".repeat(32));
    write_json_fixture(&source, &changed);
    let second = convert_home_assistant(&[source.clone()], &output).unwrap().remove(0);
    assert_ne!(first, second);
    assert_eq!(json_file(&first), original);
    assert_eq!(json_file(&second), changed);
    assert_eq!(convert_home_assistant(&[source], &output).unwrap(), vec![second]);
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 2);
}
