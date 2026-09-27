mod cli;
mod output;
mod paths;

use clap::Parser;
use output::{write_accessory, OutputFormat};

use std::collections::HashMap;
use std::io::IsTerminal;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use keystore::{init_keystore, software::{NoEncryptor, SoftwareKeystore}};
use sha2::{Sha256, Digest};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient};
use plist::Dictionary;
use tokio::sync::Mutex;

use rustpush::cloudkit::{
    pcs_keys_for_record, should_reset, CloudKitClient, CloudKitState,
    FetchRecordChangesOperation, NO_ASSETS,
};
use rustpush::cloudkit_proto::CloudKitRecord;
use rustpush::findmy::{
    BeaconAccessory, BeaconNamingRecord, BeaconRatchet,
    KeyAlignmentRecord, MasterBeaconRecord,
    SEARCH_PARTY_CONTAINER, FIND_MY_SERVICE,
};
use rustpush::keychain::{KeychainClient, KeychainClientState};
use rustpush::{
    login_apple_delegates, APSState, ActivationInfo, AppleAccount, DebugMutex, DebugRwLock,
    LoginDelegate, OSConfig, PushError, TokenProvider,
};
use rustpush::{DebugMeta, RegisterMeta};

// ── Fake OSConfig (presents as iPhone to avoid NAS validation) ───────

struct FakeIOSConfig {
    device_uuid: String,
    serial: String,
    udid: String,
}

impl FakeIOSConfig {
    fn new() -> Self {
        FakeIOSConfig {
            device_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: "F2LZN0FAKE00".to_string(),
            udid: format!("{:032X}", rand::random::<u128>()),
        }
    }
}

#[async_trait]
impl OSConfig for FakeIOSConfig {
    fn build_activation_info(&self, _csr: Vec<u8>) -> ActivationInfo {
        unreachable!("activation not needed for FindMy export")
    }

    fn get_activation_device(&self) -> String {
        "iPhone".to_string()
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        Ok(vec![])
    }

    fn get_protocol_version(&self) -> u32 {
        1640
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: "iPhone15,2".to_string(),
            os_version: "iPhone OS,17.4,21E219".to_string(),
            software_version: "21E219".to_string(),
        }
    }

    fn get_normal_ua(&self, item: &str) -> String {
        format!("{item} CFNetwork/1494.0.7 Darwin/23.4.0")
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<iPhone15,2> <iPhone OS;17.4;21E219> <{}>", for_item)
    }

    fn get_version_ua(&self) -> String {
        "[iPhone OS,17.4,21E219,iPhone15,2]".to_string()
    }

    fn get_device_name(&self) -> String {
        "iPhone".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_uuid.clone()
    }

    fn get_private_data(&self) -> Dictionary {
        Dictionary::new()
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: "17.4".to_string(),
            hardware_version: "iPhone15,2".to_string(),
            serial_number: self.serial.clone(),
        }
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    }

    fn get_serial_number(&self) -> String {
        self.serial.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn get_aoskit_version(&self) -> String {
        "com.apple.AuthKit/1 (com.apple.akd/1.0)".to_string()
    }

    fn get_udid(&self) -> String {
        self.udid.clone()
    }
}


fn assemble_accessories(
    beacon_records: HashMap<String, MasterBeaconRecord>,
    mut naming_records: HashMap<String, (String, BeaconNamingRecord)>,
    mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)>,
) -> HashMap<String, BeaconAccessory> {
    let mut accessories = HashMap::new();
    for (id, master) in beacon_records {
        // Naming and alignment records reference the CloudKit record ID, not stableIdentifier.
        let mut naming = naming_records.remove(&id).unwrap_or_else(|| {
            (
                String::new(),
                BeaconNamingRecord {
                    associated_beacon: id.clone(),
                    ..Default::default()
                },
            )
        });
        if naming.1.name.trim().is_empty() {
            naming.1.name = if master.model.trim().is_empty() {
                "Unknown".to_string()
            } else {
                master.model.clone()
            };
        }
        let alignment = alignment_records.remove(&id).unwrap_or_default();
        accessories.insert(id, BeaconAccessory {
            master_record: master,
            naming: naming.1,
            naming_id: naming.0,
            naming_prot_tag: None,
            alignment: alignment.1.clone(),
            alignment_id: alignment.0,
            aligment_prot_tag: None,
            local_alignment: alignment.1,
            last_report: None,
            primary_ratchet: BeaconRatchet::default(),
            secondary_ratchet: BeaconRatchet::default(),
        });
    }
    accessories
}


#[cfg(test)]
mod tests;

fn run_diagnostics(args: &cli::Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut files = args.files.clone();
    if files.is_empty() {
        let output_dir = paths::output_directory(args.output_dir.as_deref())?;
        for entry in std::fs::read_dir(&output_dir)? {
            let path = entry?.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
                files.push(path);
            }
        }
        files.sort();
    }
    if files.is_empty() {
        return Err("No JSON input files found; pass files or --output-dir".into());
    }
    let mut command = std::process::Command::new(&args.python);
    command.args(["-u", "-c", include_str!("../python/diagnose.py"), "--scan-seconds"])
        .arg(args.scan_seconds.to_string());
    if args.save_alignment {
        command.arg("--save-alignment");
    }
    let status = command.arg("--").args(files).status().map_err(|err| {
        format!("Cannot run {}: {err}. Use --python PATH with requirements-diagnostics.txt installed.", args.python.display())
    })?;
    if !status.success() {
        return Err(format!("Bluetooth diagnostics exited with {status}").into());
    }
    Ok(())
}

// ── Password reading ────────────────────────────────────────────────────

fn read_password() -> String {
    if std::io::stdin().is_terminal() {
        let pass = disable_echo_read();
        eprintln!();
        pass
    } else {
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        pass.trim().to_string()
    }
}

#[cfg(unix)]
fn disable_echo_read() -> String {
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut termios);
        let old = termios;
        termios.c_lflag &= !libc::ECHO;
        libc::tcsetattr(fd, libc::TCSANOW, &termios);
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        libc::tcsetattr(fd, libc::TCSANOW, &old);
        pass.trim().to_string()
    }
}

#[cfg(not(unix))]
fn disable_echo_read() -> String {
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).unwrap();
    pass.trim().to_string()
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::Args::parse();
    if args.diagnose {
        return run_diagnostics(&args);
    }
    if args.convert.is_some() {
        if args.files.is_empty() {
            return Err("--convert=home-assistant requires one or more input files".into());
        }
        let output_dir = paths::output_directory(args.output_dir.as_deref())?;
        for path in output::convert_home_assistant(&args.files, &output_dir)? {
            println!("Converted: {}", path.display());
        }
        return Ok(());
    }
    if !args.files.is_empty() {
        return Err("Input files require --convert=home-assistant or --diagnose".into());
    }

    // Export authentication state and key material must be private from creation.
    #[cfg(unix)]
    unsafe { libc::umask(0o077); }
    pretty_env_logger::init();
    let output_dir = paths::output_directory(args.output_dir.as_deref())?;
    paths::require_writable_output_directory(&output_dir)?;
    let state_dir = paths::state_directory(args.state_dir.as_deref())?;
    paths::require_writable_directory(&state_dir, "--state-dir")?;
    let anisette_config_path = state_dir.join("anisette_state");
    paths::require_writable_directory(&anisette_config_path, "--state-dir")?;
    let keystore_path = state_dir.join("keystore.plist");
    paths::check_existing_state_file(&keystore_path)?;
    paths::check_existing_state_file(&anisette_config_path.join("state.plist"))?;
    let keystore_state = match std::fs::read(&keystore_path) {
        Ok(bytes) => plist::from_bytes(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Default::default(),
        Err(error) => return Err(error.into()),
    };
    eprintln!("Authentication state: {}", state_dir.display());
    eprintln!("Export directory: {}", output_dir.display());
    init_keystore(SoftwareKeystore {
        state: keystore_state,
        update_state: Box::new(move |state| {
            plist::to_file_xml(&keystore_path, state).expect("Cannot persist keychain state in the selected --state-dir");
        }),
        encryptor: NoEncryptor,
    });
    let mut apple_id = args.apple_id.unwrap_or_default();
    let anisette_url = args.anisette_url;
    let format: OutputFormat = args.output.into();



    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());

    // ── Step 1: Create anisette client ──────────────────────────────
    eprintln!("[1/7] Connecting to anisette server...");

    let login_info = config.get_gsa_config(&APSState::default(), false);

    let anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3> =
        Arc::new(Mutex::new(AnisetteClient::new(
            RemoteAnisetteProviderV3::new(
                anisette_url.clone(),
                login_info.clone(),
                anisette_config_path,
            ),
        )));
    anisette_client.lock().await.get_headers().await.map_err(|error| {
        format!("Anisette service {anisette_url} failed before Apple login: {error}. No Apple credentials were submitted. Retry later or select --anisette-url URL; keep the existing state directory.")
    })?;
    eprintln!("  Anisette headers ready.");

    if apple_id.is_empty() {
        eprint!("Apple ID: ");
        std::io::stdin().read_line(&mut apple_id)?;
        apple_id = apple_id.trim().to_string();
    }

    eprint!("Password: ");
    let password = read_password();

    // ── Step 2: Login to Apple ──────────────────────────────────────
    eprintln!("[2/7] Logging in to Apple ID...");
    let apple_id_clone = apple_id.clone();
    let password_hash: Vec<u8> = Sha256::digest(password.as_bytes()).to_vec();
    let appleid_closure = move || (apple_id_clone.clone(), password_hash.clone());
    let tfa_closure = || {
        eprint!("2FA code: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    };

    let account = AppleAccount::login(
        appleid_closure,
        tfa_closure,
        login_info,
        anisette_client.clone(),
    )
    .await?;

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"]
        .as_unsigned_integer()
        .unwrap()
        .to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();

    eprintln!("  Logged in (dsid={})", dsid);

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    eprintln!("[3/7] Fetching MobileMe delegate...");
    let delegates = login_apple_delegates(
        &account,
        None,
        config.as_ref(),
        &[LoginDelegate::MobileMe],
    )
    .await?;
    let mobileme = delegates
        .mobileme
        .expect("No MobileMe delegate returned");

    // ── Step 4: Create CloudKit + Keychain clients ──────────────────
    eprintln!("[4/7] Setting up CloudKit & Keychain...");

    let keychain_state = KeychainClientState::new(dsid.clone(), adsid.clone(), &mobileme)
        .unwrap_or_else(|| {
            eprintln!("  (escrowProxyUrl not in MobileMe config, using default)");
            KeychainClientState::new_with_host(dsid.clone(), adsid.clone(), "https://p97-escrowproxy.icloud.com:443".to_string())
        });

    let account_arc = Arc::new(DebugMutex::new(account));
    let token_provider = TokenProvider::new(account_arc.clone(), config.clone());
    token_provider.set_mme_delegate(mobileme).await;

    let cloudkit_state =
        CloudKitState::new(dsid.clone()).expect("Failed to create CloudKitState");
    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(cloudkit_state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(keychain_state),
        config: config.clone(),
        update_state: Box::new(|_| {}),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    // ── Step 5: Join iCloud Keychain circle via escrow ────────────
    eprintln!("[5/7] Joining iCloud Keychain trust circle...");
    let bottles = keychain.get_viable_bottles().await?;
    if bottles.is_empty() {
        return Err("No escrow bottles found. Make sure you have another trusted device.".into());
    }
    eprintln!("  Found {} escrow bottle(s):", bottles.len());
    for (i, (_, meta)) in bottles.iter().enumerate() {
        eprintln!("    [{}] {}", i, meta.serial);
    }
    let bottle_idx = if bottles.len() == 1 {
        0
    } else {
        eprint!("  Choose bottle [0]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let idx = input.trim().parse::<usize>().unwrap_or(0);
        if idx >= bottles.len() {
            return Err(format!("Invalid bottle index {}. Must be 0-{}.", idx, bottles.len() - 1).into());
        }
        idx
    };
    let (bottle, meta) = &bottles[bottle_idx];
    eprintln!("  Using escrow bottle from device: {}", meta.serial);
    eprint!("  Enter the passcode of that device: ");
    let passcode = read_password();

    keychain
        .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
        .await?;
    eprintln!("  Joined keychain trust circle!");

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    eprintln!("[6/7] Fetching FindMy accessories from CloudKit...");

    let container = SEARCH_PARTY_CONTAINER
        .init(cloudkit.clone())
        .await?;
    let beacon_zone = container.private_zone("BeaconStore".to_string());
    let key = container
        .get_zone_encryption_config(&beacon_zone, &keychain, &FIND_MY_SERVICE)
        .await?;

    let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
    let mut naming_records: HashMap<String, (String, BeaconNamingRecord)> = HashMap::new();
    let mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)> = HashMap::new();

    let mut result = FetchRecordChangesOperation::do_sync(
        &container,
        &[(beacon_zone.clone(), None)],
        &NO_ASSETS,
    )
    .await;
    if should_reset(result.as_ref().err()) {
        result = FetchRecordChangesOperation::do_sync(
            &container,
            &[(beacon_zone.clone(), None)],
            &NO_ASSETS,
        )
        .await;
    }

    let (_, changes, _) = result?.remove(0);

    for change in changes {
        let identifier = change
            .identifier
            .as_ref()
            .unwrap()
            .value
            .as_ref()
            .unwrap()
            .name()
            .to_string();
        let Some(record) = change.record else { continue };
        let record_type = record.r#type.as_ref().unwrap().name().to_string();

        if record_type == MasterBeaconRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            beacon_records.insert(identifier, item);
        } else if record_type == BeaconNamingRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            naming_records.insert(
                item.associated_beacon.clone(),
                (identifier, item),
            );
        } else if record_type == KeyAlignmentRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            alignment_records.insert(
                item.beacon_identifier.clone(),
                (identifier, item),
            );
        }
    }

    // ── Assemble accessories ────────────────────────────────────────
    let accessories = assemble_accessories(beacon_records, naming_records, alignment_records);

    // ── Step 7: Write requested output formats ───────────────────────
    eprintln!("[7/7] Writing accessory files...");

    if accessories.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    for (id, acc) in &accessories {
        for path in write_accessory(&output_dir, id, acc, format)? {
            eprintln!(
                "  {} {} ({}) -> {}",
                acc.naming.emoji,
                acc.naming.name,
                acc.master_record.model,
                path.display()
            );
        }
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} accessory record(s) to {}",
        accessories.len(),
        output_dir.display()
    );

    Ok(())
}
