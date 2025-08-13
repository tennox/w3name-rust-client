use crate::{
  error::{
    CborError, InvalidIpnsV1Signature, InvalidIpnsV2Signature, InvalidIpnsV2SignatureData,
    IpnsError, SigningError,
  },
  ipns_pb::IpnsEntry,
  Name, Revision,
};
use chrono::{DateTime, Duration, Utc};
use libp2p_core::identity::{Keypair, PublicKey};
use prost::Message;
use std::{fmt::Display, str::from_utf8};

use error_stack::{report, IntoReport, Result, ResultExt};

pub fn revision_to_ipns_entry(
  revision: &Revision,
  signer: &Keypair,
) -> Result<IpnsEntry, IpnsError> {
  let duration = revision.validity().signed_duration_since(Utc::now());
  let ttl: u64 = duration.num_nanoseconds().unwrap_or(i64::MAX) as u64;

  let data = v2_signature_data(
    revision.value(),
    &revision.validity_string(),
    revision.sequence(),
    ttl,
  )
  .change_context(IpnsError)?;
  let signature_v2 = create_v2_signature(signer, &data).change_context(IpnsError)?;
  
  // V2-only mode: set signature_v2 and data fields
  // Also populate the top-level fields to match what's in data
  // This is required for validate_v2_data_matches_entry_data to pass
  let entry = IpnsEntry {
    value: revision.value().as_bytes().to_vec(),
    validity: revision.validity_string().as_bytes().to_vec(),
    validity_type: 0, // EOL = 0
    sequence: revision.sequence(),
    ttl,
    signature_v2,
    data: data.clone(),
    ..Default::default()
  };

  Ok(entry)
}

pub fn serialize_ipns_entry(entry: &IpnsEntry) -> Result<Vec<u8>, IpnsError> {
  let mut buf = Vec::new();
  buf.reserve(entry.encoded_len());
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
    validate_v2_data_matches_entry_data(entry).change_context(IpnsError)?;

    return Ok(());
  }

  validate_v1_signature(entry, public_key).change_context(IpnsError)
}

pub fn revision_from_ipns_entry(entry: &IpnsEntry, name: &Name) -> Result<Revision, IpnsError> {
  // Check if this is an old record with empty V1 fields
  let is_old_record = entry.value.is_empty() 
    && entry.validity.is_empty() 
    && entry.ttl == 0 
    && entry.sequence == 0;
    
  if is_old_record && !entry.data.is_empty() {
    // Old record: Extract data from V2 CBOR
    let data: SignatureV2Data = serde_cbor::from_slice(&entry.data[..])
      .report()
      .change_context(IpnsError)?;
      
    let value = from_utf8(&data.Value).report().change_context(IpnsError)?;
    let validity_str = from_utf8(&data.Validity).report().change_context(IpnsError)?;
    let validity = DateTime::parse_from_rfc3339(validity_str)
      .report()
      .change_context(IpnsError)?;
      
    // Note: Using TTL from CBOR data and converting properly
    let rev = Revision::new(
      name,
      value, 
      validity.into(),
      i64::try_from(data.TTL)
        .map(Duration::nanoseconds)
        .report()
        .change_context(IpnsError)?,
      data.Sequence,
    );
    Ok(rev)
  } else {
    // New record: Use V1 fields as before
    let value = from_utf8(&entry.value).report().change_context(IpnsError)?;
    let rev = Revision::new(
      name,
      value,
      from_utf8(&entry.validity)
        .report()
        .change_context(IpnsError)
        .and_then(|encoded| {
          DateTime::parse_from_rfc3339(encoded)
            .report()
            .change_context(IpnsError)
        })?
        .into(),
      i64::try_from(entry.ttl)
        .map(Duration::nanoseconds)
        .report()
        .change_context(IpnsError)?,
      entry.sequence,
    );
    Ok(rev)
  }
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
    Value: value.as_bytes().to_vec(),
    Validity: validity.as_bytes().to_vec(),
    ValidityType: 0,
    Sequence: sequence,
    TTL: ttl,
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

  let data: SignatureV2Data = serde_cbor::from_slice(&entry.data[..])
    .report()
    .change_context(InvalidIpnsV2SignatureData)?;
  
  // Backward compatibility: Check if this is an old record with empty V1 fields
  let is_old_record = entry.value.is_empty() 
    && entry.validity.is_empty() 
    && entry.ttl == 0 
    && entry.sequence == 0;
  
  if is_old_record {
    // Old record: V1 fields are empty but V2 data is valid
    // Skip V1/V2 consistency check - only V2 signature validation matters
    return Ok(());
  }
  
  // New record: Require V1 fields to match V2 CBOR data
  if entry.value != data.Value
    || entry.validity != data.Validity
    || entry.sequence != data.Sequence
    || entry.ttl != data.TTL
    || entry.validity_type != data.ValidityType as i32
  {
    Err(report!(InvalidIpnsV2SignatureData))
  } else {
    Ok(())
  }
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
  let mut msg = "ipns-signature:".as_bytes().to_vec();
  msg.extend_from_slice(sig_data);
  let sig = signer.sign(&msg).report().change_context(SigningError)?;
  Ok(sig)
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
struct SignatureV2Data {
  #[serde(with = "serde_bytes")]
  Value: Vec<u8>,
  #[serde(with = "serde_bytes")]
  Validity: Vec<u8>,
  ValidityType: u64,
  Sequence: u64,
  TTL: u64,
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
    assert_eq!(rev.sequence(), entry.sequence);
    assert_eq!(rev.value().as_bytes(), &entry.value);
    assert_eq!(rev.validity_string().as_bytes(), &entry.validity);
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
}
