use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use plist::{Dictionary, Value as PlistValue};
use rustpush::findmy::BeaconAccessory;
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Plist,
    Both,
}

#[derive(Serialize)]
struct AccessoryJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    master_key: String,
    skn: String,
    sks: String,
    paired_at: String,
    name: Option<&'a str>,
    model: Option<&'a str>,
    identifier: &'a str,
    group_identifier: Option<&'a str>,
    serial_number: Option<&'a str>,
    alignment_date: Option<String>,
    alignment_index: Option<u64>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_keys(master: &[u8], primary: &[u8], secondary: &[u8]) -> io::Result<()> {
    if master.len() < 28 || primary.len() != 32 || secondary.len() != 32 {
        return Err(invalid("Expected at least 28 master-key bytes and two 32-byte shared secrets"));
    }
    Ok(())
}

fn validate_identifier(identifier: &str) -> io::Result<()> {
    if identifier.trim().is_empty() {
        return Err(invalid("Missing accessory identifier"));
    }
    Ok(())
}

fn datetime(time: SystemTime) -> io::Result<DateTime<Utc>> {
    let (seconds, nanos) = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (
            i64::try_from(duration.as_secs()).map_err(|_| invalid("Date is out of range"))?,
            duration.subsec_nanos(),
        ),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs())
                .map_err(|_| invalid("Date is out of range"))?;
            if duration.subsec_nanos() == 0 {
                (-seconds, 0)
            } else {
                (-seconds - 1, 1_000_000_000 - duration.subsec_nanos())
            }
        }
    };
    let date = DateTime::from_timestamp(seconds, nanos)
        .ok_or_else(|| invalid("Date is out of range"))?;
    if !(1..=9999).contains(&date.year()) {
        return Err(invalid("Date is outside the FindMy.py supported range"));
    }
    Ok(date)
}

fn date_string(time: SystemTime) -> io::Result<String> {
    Ok(datetime(time)?.to_rfc3339_opts(SecondsFormat::AutoSi, false))
}

fn whole_seconds(time: SystemTime) -> SystemTime {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => UNIX_EPOCH + Duration::from_secs(duration.as_secs()),
        Err(error) => {
            let duration = error.duration();
            UNIX_EPOCH - Duration::from_secs(duration.as_secs() + u64::from(duration.subsec_nanos() != 0))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn nested_key(bytes: &[u8]) -> PlistValue {
    let mut data = Dictionary::new();
    data.insert("data".into(), PlistValue::Data(bytes.to_vec()));
    let mut key = Dictionary::new();
    key.insert("key".into(), PlistValue::Dictionary(data));
    PlistValue::Dictionary(key)
}

pub fn accessory_to_plist(acc: &BeaconAccessory) -> PlistValue {
    let master = &acc.master_record;
    let mut dict = Dictionary::new();
    dict.insert("privateKey".into(), nested_key(&master.private_key));
    dict.insert("sharedSecret".into(), nested_key(&master.shared_secret));
    if let Some(secret) = &master.shared_secret_2 {
        dict.insert("secondarySharedSecret".into(), nested_key(secret));
    }
    if let Some(secret) = &master.secure_locations_shared_secret {
        dict.insert("secureLocationsSharedSecret".into(), nested_key(secret));
    }
    dict.insert("publicKey".into(), nested_key(&master.public_key));
    dict.insert("identifier".into(), PlistValue::String(master.stable_identifier.clone()));
    dict.insert("model".into(), PlistValue::String(master.model.clone()));
    if let Some(paired_at) = master.pairing_date {
        dict.insert("pairingDate".into(), PlistValue::Date(whole_seconds(paired_at).into()));
    }
    if let Some(observed_at) = acc.alignment.last_index_observation_date {
        dict.insert("lastIndexObservationDate".into(), PlistValue::Date(whole_seconds(observed_at).into()));
        dict.insert("lastIndexObserved".into(), PlistValue::Integer(acc.alignment.last_index_observed.into()));
    }
    dict.insert("name".into(), PlistValue::String(acc.naming.name.clone()));
    dict.insert("emoji".into(), PlistValue::String(acc.naming.emoji.clone()));
    PlistValue::Dictionary(dict)
}

pub fn accessory_filename(name: &str, record_id: &str) -> String {
    // Leave room below the filesystem's 255-byte limit, including the JSON suffix.
    let mut filename = String::with_capacity(196);
    for c in name.chars() {
        let c = if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' };
        if filename.len() + c.len_utf8() > 120 {
            break;
        }
        filename.push(c);
    }
    if filename.is_empty() {
        filename.push_str("Unknown");
    }
    filename.push_str("--");
    use std::fmt::Write as _;
    for byte in Sha256::digest(record_id.as_bytes()) {
        write!(&mut filename, "{byte:02x}").unwrap();
    }
    filename.push_str(".plist");
    filename
}

pub fn write_accessory(
    output_dir: &Path,
    record_id: &str,
    acc: &BeaconAccessory,
    format: OutputFormat,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let master = &acc.master_record;
    let secondary = master.shared_secret_2.as_deref()
        .or(master.secure_locations_shared_secret.as_deref())
        .ok_or_else(|| invalid("Missing secondary shared secret"))?;
    validate_keys(&master.private_key, &master.shared_secret, secondary)?;
    validate_identifier(&master.stable_identifier)?;
    let paired_at = datetime(master.pairing_date.ok_or_else(|| invalid("Missing pairing date"))?)?;
    let (alignment_date, alignment_index) = match acc.alignment.last_index_observation_date {
        Some(observed_at) => (
            Some(datetime(observed_at)?),
            Some(u64::try_from(acc.alignment.last_index_observed)
                .map_err(|_| invalid("Alignment index must be non-negative"))?),
        ),
        None if acc.alignment.last_index_observed == 0 => (None, None),
        None => return Err(invalid("Alignment requires both an observation date and index").into()),
    };
    let path = output_dir.join(accessory_filename(&acc.naming.name, record_id));
    let mut outputs = Vec::with_capacity(if format == OutputFormat::Both { 2 } else { 1 });
    if matches!(format, OutputFormat::Json | OutputFormat::Both) {
        let json = AccessoryJson {
            kind: "accessory",
            master_key: hex(&master.private_key[master.private_key.len() - 28..]),
            skn: hex(&master.shared_secret),
            sks: hex(secondary),
            paired_at: paired_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
            name: Some(&acc.naming.name),
            model: Some(&master.model),
            identifier: &master.stable_identifier,
            group_identifier: None,
            serial_number: None,
            alignment_date: alignment_date.map(|date| date.to_rfc3339_opts(SecondsFormat::AutoSi, false)),
            alignment_index,
        };
        outputs.push((path.with_extension("findmy.json"), serde_json::to_vec_pretty(&json)?));
    }
    if matches!(format, OutputFormat::Plist | OutputFormat::Both) {
        let mut bytes = Vec::new();
        accessory_to_plist(acc).to_writer_xml(&mut bytes)?;
        outputs.push((path, bytes));
    }
    write_outputs(output_dir, outputs)
}

fn plist_key<'a>(dict: &'a Dictionary, field: &str) -> io::Result<&'a [u8]> {
    let value = dict.get(field).ok_or_else(|| invalid("Missing key data"))?;
    let data = if let Some(data) = value.as_data() {
        Some(data)
    } else {
        value.as_dictionary()
            .and_then(|outer| outer.get("key"))
            .and_then(PlistValue::as_dictionary)
            .and_then(|inner| inner.get("data"))
            .and_then(PlistValue::as_data)
    };
    data.ok_or_else(|| invalid("Expected binary key data or nested key/data structure"))
}

fn plist_string<'a>(dict: &'a Dictionary, field: &str) -> io::Result<Option<&'a str>> {
    dict.get(field).map(|value| value.as_string()
        .ok_or_else(|| invalid("Accessory metadata must be text"))).transpose()
}

fn plist_json<'a>(value: &'a PlistValue, fallback_name: &'a str) -> io::Result<AccessoryJson<'a>> {
    let dict = value.as_dictionary().ok_or_else(|| invalid("Expected an accessory plist dictionary"))?;
    let master = plist_key(dict, "privateKey")?;
    let primary = plist_key(dict, "sharedSecret")?;
    let secondary = plist_key(dict, if dict.contains_key("secondarySharedSecret") {
        "secondarySharedSecret"
    } else {
        "secureLocationsSharedSecret"
    })?;
    validate_keys(master, primary, secondary)?;
    let identifier = plist_string(dict, "identifier")?.ok_or_else(|| invalid("Missing accessory identifier"))?;
    validate_identifier(identifier)?;
    let pairing = dict.get("pairingDate").and_then(PlistValue::as_date)
        .ok_or_else(|| invalid("Missing or invalid pairing date"))?;
    let (alignment_date, alignment_index) = match (dict.get("lastIndexObservationDate"), dict.get("lastIndexObserved")) {
        (None, None) => (None, None),
        (Some(date), Some(index)) => (
            Some(date_string(date.as_date().ok_or_else(|| invalid("Invalid alignment date"))?.into())?),
            Some(index.as_unsigned_integer().ok_or_else(|| invalid("Alignment index must be a non-negative integer"))?),
        ),
        _ => return Err(invalid("Alignment requires both an observation date and index")),
    };
    Ok(AccessoryJson {
        kind: "accessory",
        master_key: hex(&master[master.len() - 28..]),
        skn: hex(primary),
        sks: hex(secondary),
        paired_at: date_string(pairing.into())?,
        name: Some(plist_string(dict, "name")?.filter(|name| !name.is_empty()).unwrap_or(fallback_name)),
        model: plist_string(dict, "model")?,
        identifier,
        group_identifier: plist_string(dict, "groupIdentifier")?,
        serial_number: plist_string(dict, "serialNumber")?,
        alignment_date,
        alignment_index,
    })
}

fn validate_json_date(value: &JsonValue) -> io::Result<()> {
    let text = value.as_str().ok_or_else(|| invalid("Expected an ISO 8601 date with timezone"))?;
    let date = DateTime::parse_from_rfc3339(text).map_err(|_| invalid("Invalid ISO 8601 date or missing timezone"))?;
    if !(1..=9999).contains(&date.year()) {
        return Err(invalid("Date is outside the FindMy.py supported range"));
    }
    if date.timestamp_subsec_nanos() >= 1_000_000_000 {
        return Err(invalid("FindMy.py dates cannot contain leap seconds"));
    }
    Ok(())
}

fn validate_json(value: &JsonValue) -> io::Result<()> {
    let dict = value.as_object().ok_or_else(|| invalid("Expected an accessory JSON object"))?;
    if dict.get("type").and_then(JsonValue::as_str) != Some("accessory") {
        return Err(invalid("Expected FindMy.py accessory JSON"));
    }
    for (field, length) in [("master_key", 56), ("skn", 64), ("sks", 64)] {
        let key = dict.get(field).and_then(JsonValue::as_str).ok_or_else(|| invalid("Missing hexadecimal key"))?;
        if key.len() != length || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("Invalid hexadecimal key or key length"));
        }
    }
    let identifier = dict.get("identifier").and_then(JsonValue::as_str)
        .ok_or_else(|| invalid("Missing accessory identifier"))?;
    validate_identifier(identifier)?;
    for field in ["name", "model"] {
        if !dict.get(field).is_some_and(|v| v.is_null() || v.is_string()) {
            return Err(invalid("Missing or invalid accessory metadata"));
        }
    }
    for field in ["group_identifier", "serial_number"] {
        if dict.get(field).is_some_and(|v| !v.is_null() && !v.is_string()) {
            return Err(invalid("Accessory metadata must be text or null"));
        }
    }
    validate_json_date(dict.get("paired_at").ok_or_else(|| invalid("Missing pairing date"))?)?;
    match (dict.get("alignment_date"), dict.get("alignment_index")) {
        (Some(JsonValue::Null), Some(JsonValue::Null)) => {},
        (Some(date), Some(index)) if index.as_u64().is_some() => validate_json_date(date)?,
        _ => return Err(invalid("Alignment requires both a date and non-negative integer index, or two nulls")),
    }
    Ok(())
}

pub fn convert_home_assistant(
    inputs: &[PathBuf],
    output_dir: &Path,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    if inputs.is_empty() {
        return Err(invalid("At least one input file is required").into());
    }
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let bytes = fs::read(input)?;
        let stem = input.file_stem().and_then(|name| name.to_str()).unwrap_or("Unknown");
        let fallback_name = stem.strip_suffix(".findmy").unwrap_or(stem);
        let is_json = input.extension().and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            || matches!(bytes.iter().find(|byte| !byte.is_ascii_whitespace()), Some(b'{' | b'['));
        let (path, output) = if is_json {
            // Preserve all metadata, including extension fields and an existing BLE alignment.
            let value: JsonValue = serde_json::from_slice(&bytes).map_err(|_| invalid("Invalid JSON input"))?;
            validate_json(&value)?;
            let identifier = value["identifier"].as_str().expect("validated identifier");
            let name = value["name"].as_str().filter(|name| !name.is_empty()).unwrap_or(identifier);
            (output_dir.join(accessory_filename(name, identifier)).with_extension("findmy.json"),
                bytes)
        } else {
            let value = PlistValue::from_reader(Cursor::new(bytes)).map_err(|_| invalid("Invalid plist input"))?;
            let json = plist_json(&value, fallback_name)?;
            (output_dir.join(accessory_filename(json.name.unwrap_or(fallback_name), json.identifier)).with_extension("findmy.json"),
                serde_json::to_vec_pretty(&json)?)
        };
        outputs.push((path, output));
    }
    write_outputs(output_dir, outputs)
}


fn write_outputs(
    output_dir: &Path,
    outputs: Vec<(PathBuf, Vec<u8>)>,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    // Validate every payload and destination before creating any files. create_new also
    // closes the overwrite race between this check and the actual write.
    let mut destinations = HashSet::with_capacity(outputs.len());
    for (path, _) in &outputs {
        if !destinations.insert(path) {
            return Err(invalid("Multiple inputs resolve to the same output filename").into());
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Output file already exists; choose a fresh directory").into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
    }
    crate::paths::private_directory(output_dir)?;
    let mut paths = Vec::with_capacity(outputs.len());
    for (path, bytes) in outputs {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        if let Err(error) = file.write_all(&bytes) {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(error.into());
        }
        paths.push(path);
    }
    Ok(paths)
}
