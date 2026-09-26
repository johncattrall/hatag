use rustpush::pcs::{PCSKey, PCSShareProtection};
use rustpush::CompactECKey;

#[test]
fn cloudkit_protection_recovers_wrapped_keys() -> Result<(), Box<dyn std::error::Error>> {
    let mut owner_scalar = [0u8; 32];
    owner_scalar[31] = 1;
    let owner = CompactECKey::decompress_private_small(owner_scalar);
    let mut record_scalar = [0u8; 32];
    record_scalar[31] = 2;
    let record_key = CompactECKey::decompress_private_small(record_scalar);
    let expected_record_key = record_key.compress_private();
    let master_key = PCSKey::random();
    let expected_master_id = master_key.key_id()?;
    let protection = PCSShareProtection::create(
        &owner,
        &[record_key],
        &std::slice::from_ref(&owner)[..0],
        master_key,
        None,
        &[],
        None,
        1,
        None,
        false,
    )?;

    let (recovered_master_keys, recovered_record_keys) =
        protection.decode(std::slice::from_ref(&owner), Some(&owner))?;
    assert_eq!(recovered_master_keys.len(), 1);
    assert_eq!(recovered_master_keys[0].key_id()?, expected_master_id);
    assert_eq!(recovered_record_keys.len(), 1);
    assert_eq!(recovered_record_keys[0].compress_private(), expected_record_key);
    Ok(())
}
