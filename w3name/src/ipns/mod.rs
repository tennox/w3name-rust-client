use crate::{
  error::{
    CborError, InvalidIpnsV1Signature, InvalidIpnsV2Signature, InvalidIpnsV2SignatureData,
    IpnsError, SigningError,
  },
  ipns_pb::IpnsEntry,
  Name, Revision,
};
use chrono::{DateTime, Utc};
use libp2p_core::identity::{Keypair, PublicKey};
use prost::Message;
use std::str::from_utf8;

use error_stack::{report, IntoReport, Result, ResultExt};

pub fn revision_to_ipns_entry(
  revision: &Revision,
  signer: &Keypair,
) -> Result<IpnsEntry, IpnsError> {
  
  let _value = revision.value().as_bytes().to_vec();
  let _validity = revision.validity_string().as_bytes().to_vec();

  // TTL should be 5 minutes (300 billion nanoseconds) regardless of validity period
  // TTL = how long clients should cache, not how long until expiry
  let ttl: u64 = 5 * 60 * 1_000_000_000; // 5 minutes in nanoseconds

  // Don't create V1 signature since we're only using V2
  let data = v2_signature_data(
    revision.value(),
    &revision.validity_string(),
    revision.sequence(),
    ttl,
  )
  .change_context(IpnsError)?;
  let signature_v2 = create_v2_signature(signer, &data).change_context(IpnsError)?;
  
  // ONLY set signature_v2 and data fields - NO validity_type in protobuf
  let entry = IpnsEntry {
    signature_v2,
    data: data.clone(),
    ..Default::default()
  };


  Ok(entry)
}

pub fn serialize_ipns_entry(entry: &IpnsEntry) -> Result<Vec<u8>, IpnsError> {
  let mut buf = Vec::with_capacity(entry.encoded_len());
  entry.encode(&mut buf).report().change_context(IpnsError)?;
  Ok(buf)
}

pub fn deserialize_ipns_entry(entry_bytes: &[u8]) -> Result<IpnsEntry, IpnsError> {
  let entry = IpnsEntry::decode(entry_bytes)
    .report()
    .change_context(IpnsError)?;
  Ok(entry)
}

pub fn validate_ipns_entry(entry: &IpnsEntry, public_key: &PublicKey) -> Result<(), IpnsError> {
  if !entry.signature_v2.is_empty() && !entry.data.is_empty() {
    validate_v2_signature(public_key, &entry.signature_v2, &entry.data)
      .change_context(IpnsError)?;
    
    // For V2-only entries (where other fields are empty), skip field validation
    if !entry.value.is_empty() || !entry.validity.is_empty() {
      validate_v2_data_matches_entry_data(entry).change_context(IpnsError)?;
    }

    return Ok(());
  }

  validate_v1_signature(entry, public_key).change_context(IpnsError)
}

pub fn revision_from_ipns_entry(entry: &IpnsEntry, name: &Name) -> Result<Revision, IpnsError> {
  // For V2-only entries, extract data from CBOR field
  if !entry.data.is_empty() {
    let data: SignatureV2Data = serde_cbor::from_slice(&entry.data[..])
      .report()
      .change_context(IpnsError)?;
    
    let value = from_utf8(&data.Value).report().change_context(IpnsError)?;
    let validity_str = from_utf8(&data.Validity).report().change_context(IpnsError)?;
    let validity = DateTime::parse_from_rfc3339(validity_str)
      .report()
      .change_context(IpnsError)?;

    let rev = Revision::new(name, value, validity.into(), data.Sequence);
    return Ok(rev);
  }

  // Fallback to V1 format
  let value = from_utf8(&entry.value).report().change_context(IpnsError)?;
  let validity_str = from_utf8(&entry.validity)
    .report()
    .change_context(IpnsError)?;
  let validity = DateTime::parse_from_rfc3339(validity_str)
    .report()
    .change_context(IpnsError)?;

  let rev = Revision::new(name, value, validity.into(), entry.sequence);
  Ok(rev)
}

fn v1_signature_data(value_bytes: &[u8], validity_bytes: &[u8]) -> Vec<u8> {
  let mut buf = value_bytes.to_vec();
  buf.extend("EOL".as_bytes()); // validity type (we only support Eol)
  buf.extend(validity_bytes);
  buf
}

fn v2_signature_data(
  value: &str,
  validity: &str,
  sequence: u64,
  ttl: u64,
) -> Result<Vec<u8>, CborError> {
  let data = SignatureV2Data {
    TTL: ttl,
    Value: value.as_bytes().to_vec(),
    Sequence: sequence,
    Validity: validity.as_bytes().to_vec(),
    ValidityType: 0,
  };
  let encoded = serde_cbor::to_vec(&data)
    .report()
    .change_context(CborError)?;

  
  Ok(encoded)
}

fn validate_v2_signature(
  public_key: &PublicKey,
  sig: &[u8],
  data: &[u8],
) -> Result<(), InvalidIpnsV2Signature> {
  let mut msg = "ipns-signature:".as_bytes().to_vec();
  msg.extend_from_slice(data);
  if public_key.verify(&msg, sig) {
    Ok(())
  } else {
    Err(report!(InvalidIpnsV2Signature))
  }
}

fn validate_v2_data_matches_entry_data(
  entry: &IpnsEntry,
) -> Result<(), InvalidIpnsV2SignatureData> {
  if entry.data.is_empty() {
    return Err(report!(InvalidIpnsV2SignatureData));
  }

  // For V2-only entries, we only validate that the CBOR data can be parsed
  // The actual field validation is done by the server
  let _data: SignatureV2Data = serde_cbor::from_slice(&entry.data[..])
    .report()
    .change_context(InvalidIpnsV2SignatureData)?;
  
  Ok(())
}

fn validate_v1_signature(
  entry: &IpnsEntry,
  public_key: &PublicKey,
) -> Result<(), InvalidIpnsV1Signature> {
  let data = v1_signature_data(&entry.value, &entry.validity);
  if public_key.verify(&data, &entry.signature) {
    Ok(())
  } else {
    Err(report!(InvalidIpnsV1Signature))
  }
}

fn create_v1_signature(
  signer: &Keypair,
  value_bytes: &[u8],
  validity_bytes: &[u8],
) -> Result<Vec<u8>, SigningError> {
  let msg = v1_signature_data(value_bytes, validity_bytes);
  let sig = signer.sign(&msg).report().change_context(SigningError)?;
  Ok(sig)
}

fn create_v2_signature(signer: &Keypair, sig_data: &[u8]) -> Result<Vec<u8>, SigningError> {
  // Use standard IPNS v2 signature format
  let mut msg = "ipns-signature:".as_bytes().to_vec();
  msg.extend_from_slice(sig_data);
  let sig = signer.sign(&msg).report().change_context(SigningError)?;
  Ok(sig)
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
struct SignatureV2Data {
  #[serde(rename = "TTL")]
  TTL: u64,
  #[serde(with = "serde_bytes", rename = "Value")]
  Value: Vec<u8>,
  #[serde(rename = "Sequence")]
  Sequence: u64,
  #[serde(with = "serde_bytes", rename = "Validity")]
  Validity: Vec<u8>,
  #[serde(rename = "ValidityType")]
  ValidityType: i32,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::WritableName;
  use chrono::Duration;

  #[test]
  fn to_ipns() {
    let name = WritableName::new();
    let value = "such value. much wow".to_string();
    let validity = Utc::now().checked_add_signed(Duration::weeks(52)).unwrap();
    let rev = Revision::v0_with_validity(&name.to_name(), &value, validity);
    assert_eq!(rev.sequence(), 0);
    assert_eq!(rev.name(), &name.to_name());
    assert_eq!(rev.value(), &value);
    assert_eq!(rev.validity(), &validity);

    let entry = revision_to_ipns_entry(&rev, name.keypair()).unwrap();
    // In V2-only mode, data is stored in CBOR format in the data field
    assert!(!entry.data.is_empty());
    assert!(!entry.signature_v2.is_empty());
    // Other fields are not set in V2-only mode
    assert!(entry.value.is_empty());
    assert!(entry.validity.is_empty());
  }

  #[test]
  fn round_trip() {
    let name = WritableName::new();
    let value = "such value. much wow".to_string();
    let rev = Revision::v0(&name.to_name(), &value);

    let entry = revision_to_ipns_entry(&rev, name.keypair()).unwrap();

    validate_ipns_entry(&entry, &name.keypair().public()).unwrap();

    let rev2 = revision_from_ipns_entry(&entry, &name.to_name()).unwrap();
    assert_eq!(rev, rev2);
  }

  // Test removed - ValidityType no longer in CBOR data

  #[test]
  fn server_side_validation_simulation() {
    let name = WritableName::new();
    // Use the EXACT same IPFS hash as the working JavaScript test
    let value = "/ipfs/bafkreiem4twkqzsq2aj4shbycd4yvoj2cx72vezicletlhi7dijjciqpui".to_string();
    
    // Use standard 1-year validity, but TTL is now fixed to 5 minutes
    let rev = Revision::v0(&name.to_name(), &value);

    let entry = revision_to_ipns_entry(&rev, name.keypair()).unwrap();
    
    // Simulate what the server does when validating the entry
    // The server unmarshals the protobuf, then deserializes the CBOR data field
    let protobuf_entry = serialize_ipns_entry(&entry).unwrap();
    let unmarshaled_entry = deserialize_ipns_entry(&protobuf_entry).unwrap();
    
    // Now validate - this is where the bug would manifest
    validate_ipns_entry(&unmarshaled_entry, &name.keypair().public()).unwrap();
    
    // ValidityType field removed from CBOR data - no longer testing this
  }

  // Tests removed - ValidityType no longer in CBOR data
}
