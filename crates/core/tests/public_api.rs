use sha2::{Digest, Sha256};

use agent_receipts::{
    audit_mac_input_ascii, audit_signing_key, canonical_json, canonical_json_value, check_depth,
    compare_authority_contracts, compare_authority_contracts_bytes, controlled_signing_key,
    is_https_authority_subset, is_https_authority_subset_bytes, normalize_authority_policy,
    normalize_authority_policy_bytes, normalize_https_authority_rules,
    normalize_https_authority_rules_bytes, resign_audit_receipt, resign_audit_receipt_bytes,
    sign_controlled_integrity, sign_controlled_integrity_bytes, stable_hash, stable_hash_value,
    verify_audit_receipt, verify_audit_receipt_bytes, verify_controlled_integrity,
    verify_controlled_integrity_bytes, AuthorityError, AuthorityPath, CompareResult, Error, Json,
    Receipt, Relationship, SignerError, SigningKey, Wtf16, AUDIT_RECEIPT_V2_VERSION,
    AUDIT_RECEIPT_VERSION, CONTROLLED_INTEGRITY_VERSION, MAX_DEPTH,
};

type ResignBytes = fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>;
type SignControlledBytes = fn(&[u8], &[u8], &str) -> Result<Vec<u8>, SignerError>;
type ObjectCtor = fn(Vec<(Wtf16, Json)>) -> Result<Json, Error>;

#[test]
fn public_signatures_compile() {
    let _: fn(&[u8]) -> Result<Vec<u8>, Error> = canonical_json;
    let _: fn(&[u8]) -> Result<String, Error> = stable_hash;
    let _: fn(&Json) -> Result<Vec<u8>, Error> = canonical_json_value;
    let _: fn(&Json) -> Result<String, Error> = stable_hash_value;
    let _: fn(usize) -> Result<(), Error> = check_depth;
    let _: fn(&Json, &Json) -> Result<CompareResult, AuthorityError> = compare_authority_contracts;
    let _: fn(&[u8], &[u8]) -> Result<CompareResult, AuthorityError> =
        compare_authority_contracts_bytes;
    let _: fn(&Json, &Json) -> Result<bool, AuthorityError> = is_https_authority_subset;
    let _: fn(&[u8], &[u8]) -> Result<bool, AuthorityError> = is_https_authority_subset_bytes;
    let _: fn(&Json) -> Result<Json, AuthorityError> = normalize_authority_policy;
    let _: fn(&[u8]) -> Result<Json, AuthorityError> = normalize_authority_policy_bytes;
    let _: fn(&Json) -> Result<Json, AuthorityError> = normalize_https_authority_rules;
    let _: fn(&[u8]) -> Result<Json, AuthorityError> = normalize_https_authority_rules_bytes;
    let _: fn(SigningKey<'_>) -> Result<&[u8], SignerError> = audit_signing_key;
    let _: fn(&[u8]) -> Result<&[u8], SignerError> = controlled_signing_key;
    let _: fn(&Json, &[u8]) -> bool = verify_audit_receipt;
    let _: fn(&[u8], &[u8]) -> bool = verify_audit_receipt_bytes;
    let _: fn(&Json, &[u8]) -> Result<Json, Error> = resign_audit_receipt;
    let _: ResignBytes = resign_audit_receipt_bytes;
    let _: fn(&Json, &[u8], &str, &Json) -> bool = verify_controlled_integrity;
    let _: fn(&[u8], &[u8], &str, &[u8]) -> bool = verify_controlled_integrity_bytes;
    let _: fn(&Json, &[u8], &str) -> Result<Json, SignerError> = sign_controlled_integrity;
    let _: SignControlledBytes = sign_controlled_integrity_bytes;
    let _: fn(&Json) -> Option<String> = audit_mac_input_ascii;

    let _: fn(Error) -> &'static str = Error::code;
    let _: fn(SignerError) -> &'static str = SignerError::code;
    let _: fn(AuthorityError) -> &'static str = AuthorityError::code;
    let _: fn(AuthorityPath) -> &'static str = AuthorityPath::as_str;
    let _: fn(Relationship) -> &'static str = Relationship::as_str;
    let _: fn(SigningKey<'static>) -> &'static [u8] = SigningKey::utf8;
    let _: fn(Vec<u16>) -> Wtf16 = Wtf16::from_units;
    let _: fn(&str) -> Wtf16 = Wtf16::from_str;
    let _: fn(&Wtf16) -> &[u16] = Wtf16::units;
    let _: fn() -> Json = Json::null;
    let _: fn(bool) -> Json = Json::bool;
    let _: fn(f64) -> Result<Json, Error> = Json::number;
    let _: fn(Wtf16) -> Json = Json::string;
    let _: fn(Vec<Json>) -> Json = Json::array;
    let _: ObjectCtor = Json::object;

    let _: usize = MAX_DEPTH;
    let _: &str = AUDIT_RECEIPT_VERSION;
    let _: &str = AUDIT_RECEIPT_V2_VERSION;
    let _: &str = CONTROLLED_INTEGRITY_VERSION;
    let _: [AuthorityPath; 11] = AuthorityPath::ALL;
    let _: Option<Receipt> = None;
    let _: CompareResult = CompareResult {
        relationship: Relationship::Unchanged,
        widened: Vec::new(),
        narrowed: Vec::new(),
    };
}

#[test]
fn public_enum_variants_are_exhaustive() {
    assert_eq!(
        match Error::TypeError {
            Error::NotUtf8 => "not_utf8",
            Error::InvalidJson => "invalid_json",
            Error::TooDeep => "too_deep",
            Error::Cycle => "cycle",
            Error::TypeError => "type_error",
        },
        Error::TypeError.code()
    );
    assert_eq!(
        match SignerError::RejectedInput {
            SignerError::ShortAuditKey => "short_audit_key",
            SignerError::ShortControlledKey => "short_controlled_key",
            SignerError::InvalidKeyId => "invalid_key_id",
            SignerError::RejectedInput => "type_error",
        },
        SignerError::RejectedInput.code()
    );
    assert_eq!(
        match AuthorityError::InvalidHttpsShape {
            AuthorityError::InvalidInput => "invalid_input",
            AuthorityError::NotAnObject => "not_an_object",
            AuthorityError::CrossVersion => "cross_version",
            AuthorityError::UnsupportedVersion => "unsupported_version",
            AuthorityError::UnknownField => "unknown_field",
            AuthorityError::HttpsInV1 => "https_in_v1",
            AuthorityError::OutboundInV2 => "outbound_in_v2",
            AuthorityError::InvalidScope => "invalid_scope",
            AuthorityError::InvalidFlag => "invalid_flag",
            AuthorityError::InvalidHttpsHost => "invalid_https_host",
            AuthorityError::InvalidHttpsPort => "invalid_https_port",
            AuthorityError::InvalidHttpsMethod => "invalid_https_method",
            AuthorityError::InvalidHttpsBounds => "invalid_https_bounds",
            AuthorityError::InvalidHttpsShape => "invalid_https_shape",
        },
        AuthorityError::InvalidHttpsShape.code()
    );
    assert_eq!(
        match Relationship::Unchanged {
            Relationship::Widening => "widening",
            Relationship::Narrowing => "narrowing",
            Relationship::Mixed => "mixed",
            Relationship::Unchanged => "unchanged",
        },
        Relationship::Unchanged.as_str()
    );
    let path = AuthorityPath::FilesystemRead;
    assert_eq!(
        match path {
            AuthorityPath::FilesystemRead => "filesystem.read",
            AuthorityPath::FilesystemSensitiveRead => "filesystem.sensitiveRead",
            AuthorityPath::FilesystemWrite => "filesystem.write",
            AuthorityPath::NetworkOutbound => "network.outbound",
            AuthorityPath::NetworkHttps => "network.https",
            AuthorityPath::GitWrite => "git.write",
            AuthorityPath::GitHooks => "git.hooks",
            AuthorityPath::EnvironmentSecrets => "environment.secrets",
            AuthorityPath::EnvironmentAmbientSecrets => "environment.ambientSecrets",
            AuthorityPath::OutputUnrestricted => "output.unrestricted",
            AuthorityPath::ContainerSocket => "container.socket",
        },
        path.as_str()
    );
}

#[test]
fn signing_key_variants_are_exhaustive() {
    let text = SigningKey::Text {
        utf8: b"key-material-16b",
        utf16_len: 16,
    };
    let bytes = SigningKey::Bytes(b"key-material-16b");
    for key in [text, bytes] {
        match key {
            SigningKey::Text { utf8, utf16_len } => {
                assert_eq!(utf8, key.utf8());
                assert_eq!(utf16_len, 16);
            }
            SigningKey::Bytes(raw) => {
                assert_eq!(raw, key.utf8());
            }
        }
    }
}

#[test]
fn reference_vectors_sha256_is_pinned() {
    let bytes = include_bytes!("../../../vectors/reference/vectors.json");
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    assert_eq!(
        hex, "70507a2b636c05bf9841cb99921ff91908cd5e2ab7e270b14802f32727bbb7c1",
        "vectors/reference/vectors.json sha256"
    );
}
