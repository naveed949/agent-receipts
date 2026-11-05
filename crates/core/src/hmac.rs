use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{encode_hex, stable_hash_value, Error, Json, Wtf16};

type HmacSha256 = Hmac<Sha256>;

pub const AUDIT_RECEIPT_VERSION: &str = "adaptive-sandbox.audit-receipt/v1";
pub const AUDIT_RECEIPT_V2_VERSION: &str = "adaptive-sandbox.audit-receipt/v2";
pub const CONTROLLED_INTEGRITY_VERSION: &str = "controlled-integrity/v1";

const HTTPS_EVIDENCE_FIELD: &str = "gondolinHttps";
const MIN_SIGNER_UNITS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerError {
    ShortAuditKey,
    ShortControlledKey,
    InvalidKeyId,
    RejectedInput,
}

impl SignerError {
    pub fn code(self) -> &'static str {
        match self {
            SignerError::ShortAuditKey => "short_audit_key",
            SignerError::ShortControlledKey => "short_controlled_key",
            SignerError::InvalidKeyId => "invalid_key_id",
            SignerError::RejectedInput => "type_error",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SigningKey<'a> {
    Text { utf8: &'a [u8], utf16_len: usize },
    Bytes(&'a [u8]),
}

impl<'a> SigningKey<'a> {
    pub fn utf8(self) -> &'a [u8] {
        match self {
            SigningKey::Text { utf8, .. } => utf8,
            SigningKey::Bytes(bytes) => bytes,
        }
    }

    fn audit_units(self) -> usize {
        match self {
            SigningKey::Text { utf16_len, .. } => utf16_len,
            SigningKey::Bytes(bytes) => bytes.len(),
        }
    }
}

pub fn audit_signing_key(key: SigningKey<'_>) -> Result<&[u8], SignerError> {
    if key.audit_units() < MIN_SIGNER_UNITS {
        return Err(SignerError::ShortAuditKey);
    }
    Ok(key.utf8())
}

pub fn controlled_signing_key(key: &[u8]) -> Result<&[u8], SignerError> {
    if key.len() < MIN_SIGNER_UNITS {
        return Err(SignerError::ShortControlledKey);
    }
    Ok(key)
}

pub fn verify_audit_receipt_bytes(receipt: &[u8], key: &[u8]) -> bool {
    match crate::parse::parse(receipt) {
        Ok(value) => verify_audit_receipt(&value, key),
        Err(_) => false,
    }
}

pub fn resign_audit_receipt_bytes(receipt: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let value = crate::parse::parse(receipt)?;
    let resigned = resign_audit_receipt(&value, key)?;
    crate::canonical_json_value(&resigned)
}

pub fn sign_controlled_integrity_bytes(
    value: &[u8],
    key: &[u8],
    key_id: &str,
) -> Result<Vec<u8>, SignerError> {
    let value = crate::parse::parse(value).map_err(|_| SignerError::RejectedInput)?;
    let evidence = sign_controlled_integrity(&value, key, key_id)?;
    crate::canonical_json_value(&evidence).map_err(|_| SignerError::RejectedInput)
}

pub fn verify_controlled_integrity_bytes(
    value: &[u8],
    key: &[u8],
    key_id: &str,
    evidence: &[u8],
) -> bool {
    let Ok(value) = crate::parse::parse(value) else {
        return false;
    };
    let Ok(evidence) = crate::parse::parse(evidence) else {
        return false;
    };
    verify_controlled_integrity(&value, key, key_id, &evidence)
}

pub fn verify_audit_receipt(receipt: &Json, key: &[u8]) -> bool {
    let Some(expected) = audit_tag(receipt) else {
        return false;
    };
    let Some(offered) = decode_lowercase_tag(
        field(receipt, "integrity").and_then(|integrity| field(integrity, "signature")),
    ) else {
        return false;
    };
    if hmac_verify(key, expected.mac_input.as_bytes(), &offered).is_none() {
        return false;
    }
    artifact_hashes_match(receipt) && linkage_ok(receipt)
}

pub fn resign_audit_receipt(receipt: &Json, key: &[u8]) -> Result<Json, Error> {
    let mac = audit_tag(receipt).ok_or(Error::TypeError)?;
    let tag = hmac_sign(key, mac.mac_input.as_bytes()).ok_or(Error::TypeError)?;
    set_integrity_signature(receipt, &encode_hex(&tag))
}

pub fn verify_controlled_integrity(
    value: &Json,
    key: &[u8],
    key_id: &str,
    evidence: &Json,
) -> bool {
    if text(evidence, "integrityVersion").as_deref() != Some(CONTROLLED_INTEGRITY_VERSION) {
        return false;
    }
    if text(evidence, "integrityKeyId").as_deref() != Some(key_id) {
        return false;
    }
    let Some(offered) = decode_lowercase_tag(field(evidence, "integrityDigest")) else {
        return false;
    };
    let Ok(canonical) = crate::canonical_json_value(value) else {
        return false;
    };
    hmac_verify(key, &canonical, &offered).is_some()
}

pub fn sign_controlled_integrity(
    value: &Json,
    key: &[u8],
    key_id: &str,
) -> Result<Json, SignerError> {
    if !valid_controlled_key_id(key_id) {
        return Err(SignerError::InvalidKeyId);
    }
    let canonical = crate::canonical_json_value(value).map_err(|_| SignerError::RejectedInput)?;
    let tag = hmac_sign(key, &canonical).ok_or(SignerError::RejectedInput)?;
    Json::object(vec![
        (
            Wtf16::from_str("integrityVersion"),
            Json::string(Wtf16::from_str(CONTROLLED_INTEGRITY_VERSION)),
        ),
        (
            Wtf16::from_str("integrityKeyId"),
            Json::string(Wtf16::from_str(key_id)),
        ),
        (
            Wtf16::from_str("integrityDigest"),
            Json::string(Wtf16::from_str(&encode_hex(&tag))),
        ),
    ])
    .map_err(|_| SignerError::RejectedInput)
}

struct AuditMac {
    mac_input: String,
}

pub fn audit_mac_input_ascii(receipt: &Json) -> Option<String> {
    audit_tag(receipt).map(|mac| mac.mac_input)
}

fn audit_tag(receipt: &Json) -> Option<AuditMac> {
    let version = text(receipt, "version")?;
    if version != AUDIT_RECEIPT_VERSION && version != AUDIT_RECEIPT_V2_VERSION {
        return None;
    }
    let integrity = field(receipt, "integrity")?;
    if text(integrity, "algorithm").as_deref() != Some("hmac-sha256") {
        return None;
    }
    let key_id = field(integrity, "keyId").and_then(unicode)?;
    if key_id.is_empty() || key_id.trim() != key_id {
        return None;
    }
    let document = mac_document(receipt)?;
    let hash = stable_hash_value(&document).ok()?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    Some(AuditMac { mac_input: hash })
}

fn mac_document(receipt: &Json) -> Option<Json> {
    let integrity = field(receipt, "integrity")?;
    let stripped = without_key(integrity, "signature")?;
    replace_field(receipt, "integrity", stripped)
}

fn set_integrity_signature(receipt: &Json, signature: &str) -> Result<Json, Error> {
    let integrity = field(receipt, "integrity").ok_or(Error::TypeError)?;
    let updated = replace_field(
        integrity,
        "signature",
        Json::string(Wtf16::from_str(signature)),
    )
    .or_else(|| {
        let mut entries = integrity.as_object()?.to_vec();
        entries.push((
            Wtf16::from_str("signature"),
            Json::string(Wtf16::from_str(signature)),
        ));
        Json::object(entries).ok()
    })
    .ok_or(Error::TypeError)?;
    replace_field(receipt, "integrity", updated).ok_or(Error::TypeError)
}

fn artifact_hashes_match(receipt: &Json) -> bool {
    let Some(artifacts) = field(receipt, "artifacts").and_then(Json::as_object) else {
        return false;
    };
    artifacts.iter().all(|(_, entry)| {
        let Some(value) = field(entry, "value") else {
            return false;
        };
        let Some(hash) = text(entry, "hash") else {
            return false;
        };
        match stable_hash_value(value) {
            Ok(computed) => computed == hash,
            Err(_) => false,
        }
    })
}

fn linkage_ok(receipt: &Json) -> bool {
    match field(receipt, "authorityPolicyVersion") {
        None => v1_linkage(receipt),
        Some(_) => v2_linkage(receipt),
    }
}

fn v1_linkage(receipt: &Json) -> bool {
    if text(receipt, "version").as_deref() != Some(AUDIT_RECEIPT_VERSION) {
        return false;
    }
    if field(receipt, HTTPS_EVIDENCE_FIELD).is_some() {
        return false;
    }
    version_absent_or(envelope(receipt), "1") && granted_v1_ok(receipt)
}

fn v2_linkage(receipt: &Json) -> bool {
    if text(receipt, "version").as_deref() != Some(AUDIT_RECEIPT_V2_VERSION) {
        return false;
    }
    if text(receipt, "authorityPolicyVersion").as_deref() != Some("2") {
        return false;
    }
    if text_path(receipt, &["artifacts", "policy", "version"]).as_deref() != Some("2") {
        return false;
    }
    let Some(plan) = field_path(receipt, &["artifacts", "plan", "value"]) else {
        return false;
    };
    if !plan.is_object() {
        return false;
    }
    let Some(envelope) = field(plan, "authority").filter(|value| value.is_object()) else {
        return false;
    };
    if text(envelope, "version").as_deref() != Some("2") {
        return false;
    }
    if !lowercase_hex64(text(plan, "authorityHash").as_deref()) {
        return false;
    }
    if !artifact_hashes_match(receipt) {
        return false;
    }
    if text_path(plan, &["argumentAuthority", "version"]).as_deref() != Some("2") {
        return false;
    }
    if !field_path(plan, &["argumentAuthority"]).is_some_and(Json::is_object) {
        return false;
    }
    let Some(backend) = field_path(receipt, &["artifacts", "backend", "value"]) else {
        return false;
    };
    if text(backend, "authorityPolicyVersion").as_deref() != Some("2") {
        return false;
    }
    if text_path(backend, &["authority", "version"]).as_deref() != Some("2") {
        return false;
    }
    let Some(policy) = field_path(receipt, &["artifacts", "policy", "value"]) else {
        return false;
    };
    for layer in ["outer", "agent", "session", "state"] {
        if text_path(policy, &[layer, "version"]).as_deref() != Some("2") {
            return false;
        }
        if !field(policy, layer).is_some_and(Json::is_object) {
            return false;
        }
    }
    if text_path(
        receipt,
        &[
            "artifacts",
            "contract",
            "value",
            "authority",
            "grants",
            "version",
        ],
    )
    .as_deref()
        != Some("2")
    {
        return false;
    }
    if !field_path(
        receipt,
        &["artifacts", "contract", "value", "authority", "grants"],
    )
    .is_some_and(Json::is_object)
    {
        return false;
    }
    let Some(request) = field_path(receipt, &["artifacts", "request", "value"]) else {
        return false;
    };
    for actor in ["agent", "session"] {
        if text_path(request, &[actor, "authority", "version"]).as_deref() != Some("2") {
            return false;
        }
        if !field_path(request, &[actor, "authority"]).is_some_and(Json::is_object) {
            return false;
        }
    }
    granted_v2_ok(receipt, envelope)
}

fn envelope(receipt: &Json) -> Option<&Json> {
    let plan = field_path(receipt, &["artifacts", "plan", "value"])?;
    if !plan.is_object() {
        return None;
    }
    field(plan, "authority").filter(|value| value.is_object())
}

fn granted_authority(receipt: &Json) -> Option<&Json> {
    field_path(receipt, &["authority", "granted", "authority"])
}

fn granted_v1_ok(receipt: &Json) -> bool {
    match granted_authority(receipt) {
        None => true,
        Some(granted) if !granted.is_object() => true,
        Some(granted) => version_absent_or(Some(granted), "1"),
    }
}

fn granted_v2_ok(receipt: &Json, envelope: &Json) -> bool {
    match granted_authority(receipt) {
        None => true,
        Some(granted) if !granted.is_object() => false,
        Some(granted) => {
            if text(granted, "version").as_deref() != Some("2") {
                return false;
            }
            match (stable_hash_value(granted), stable_hash_value(envelope)) {
                (Ok(left), Ok(right)) => left == right,
                _ => false,
            }
        }
    }
}

fn version_absent_or(value: Option<&Json>, allowed: &str) -> bool {
    match value.and_then(|value| field(value, "version")) {
        None => true,
        Some(version) => text_value(version).as_deref() == Some(allowed),
    }
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    Some(mac.finalize().into_bytes().into())
}

fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8; 32]) -> Option<()> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    mac.verify_slice(tag).ok()
}

fn decode_lowercase_tag(value: Option<&Json>) -> Option<[u8; 32]> {
    let text = unicode(value?)?;
    if text.len() != 64 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = lowercase_nibble(bytes[index * 2])?;
        let lo = lowercase_nibble(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn lowercase_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn lowercase_hex64(text: Option<&str>) -> bool {
    let Some(text) = text else {
        return false;
    };
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_controlled_key_id(key_id: &str) -> bool {
    let bytes = key_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn field<'a>(value: &'a Json, name: &str) -> Option<&'a Json> {
    let want = Wtf16::from_str(name);
    value
        .as_object()?
        .iter()
        .find(|(key, _)| key == &want)
        .map(|(_, child)| child)
}

fn field_path<'a>(value: &'a Json, path: &[&str]) -> Option<&'a Json> {
    let mut current = value;
    for name in path {
        current = field(current, name)?;
    }
    Some(current)
}

fn text(value: &Json, name: &str) -> Option<String> {
    unicode(field(value, name)?)
}

fn text_path(value: &Json, path: &[&str]) -> Option<String> {
    unicode(field_path(value, path)?)
}

fn text_value(value: &Json) -> Option<String> {
    unicode(value)
}

fn unicode(value: &Json) -> Option<String> {
    String::from_utf16(value.as_string()?.units()).ok()
}

fn without_key(value: &Json, name: &str) -> Option<Json> {
    let want = Wtf16::from_str(name);
    let entries = value
        .as_object()?
        .iter()
        .filter(|(key, _)| key != &want)
        .cloned()
        .collect();
    Json::object(entries).ok()
}

fn replace_field(value: &Json, name: &str, next: Json) -> Option<Json> {
    let want = Wtf16::from_str(name);
    let mut found = false;
    let mut entries = Vec::new();
    for (key, child) in value.as_object()? {
        if key == &want {
            entries.push((key.clone(), next.clone()));
            found = true;
        } else {
            entries.push((key.clone(), child.clone()));
        }
    }
    if !found {
        return None;
    }
    Json::object(entries).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controlled_digest_matches_vector() {
        let value = Json::object(vec![
            (Wtf16::from_str("a"), Json::string(Wtf16::from_str("x"))),
            (
                Wtf16::from_str("b"),
                Json::array(vec![Json::number(1.0).unwrap(), Json::number(2.0).unwrap()]),
            ),
        ])
        .unwrap();
        let key = b"synthetic-controlled-key-0001";
        let evidence = sign_controlled_integrity(&value, key, "synthetic-key-1").unwrap();
        assert_eq!(
            text(&evidence, "integrityDigest").unwrap(),
            "acccb6932644f91306b14c6b012149321e0abb5b204f4fa4e61b15a8640dd69e"
        );
        assert!(verify_controlled_integrity(
            &value,
            key,
            "synthetic-key-1",
            &evidence
        ));
        assert!(!verify_controlled_integrity(
            &value,
            key,
            "synthetic-key-2",
            &evidence
        ));
    }

    #[test]
    fn audit_verify_fails_closed() {
        let key = b"synthetic-audit-key-0123456789ab";
        assert!(!verify_audit_receipt(&Json::null(), key));
        assert!(!verify_audit_receipt(&Json::array(Vec::new()), key));
        let empty = Json::object(Vec::new()).unwrap();
        assert!(!verify_audit_receipt(&empty, key));
        let unknown_version = Json::object(vec![(
            Wtf16::from_str("version"),
            Json::string(Wtf16::from_str("not-a-receipt")),
        )])
        .unwrap();
        assert!(!verify_audit_receipt(&unknown_version, key));
        assert!(resign_audit_receipt(&empty, key).is_err());
        assert!(resign_audit_receipt(&Json::null(), key).is_err());
    }

    #[test]
    fn signer_length_and_hex_policy() {
        assert_eq!(
            audit_signing_key(SigningKey::Text {
                utf8: b"short",
                utf16_len: 5
            }),
            Err(SignerError::ShortAuditKey)
        );
        assert_eq!(
            controlled_signing_key(b"0123456789abcde"),
            Err(SignerError::ShortControlledKey)
        );
        assert!(controlled_signing_key(b"0123456789abcdef").is_ok());
        let eeee = "é".repeat(8);
        assert_eq!(
            audit_signing_key(SigningKey::Text {
                utf8: eeee.as_bytes(),
                utf16_len: 8
            }),
            Err(SignerError::ShortAuditKey)
        );
        assert!(controlled_signing_key(eeee.as_bytes()).is_ok());
    }
}
