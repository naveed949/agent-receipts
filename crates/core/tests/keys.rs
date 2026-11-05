use agent_receipts::{
    canonical_json, canonical_json_value, check_depth, stable_hash, stable_hash_value, Error, Json,
    Wtf16,
};

#[test]
fn documented_object_and_hash() {
    let input = br#"{"b":1,"a":2}"#;
    let bytes = canonical_json(input).unwrap();
    assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    let digest = stable_hash(input).unwrap();
    assert_eq!(
        digest,
        "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772"
    );
    assert_eq!(canonical_json(&bytes).unwrap(), bytes);
    assert_eq!(stable_hash(&bytes).unwrap(), digest);
}

#[test]
fn canonical_key_order() {
    let input = br#"{"b":1,"4294967295":2,"4294967294":3,"01":4,"-1":5,"10":6,"2":7,"0":8,"1":9}"#;
    let expected =
        br#"{"0":8,"1":9,"2":7,"10":6,"4294967294":3,"-1":5,"01":4,"4294967295":2,"b":1}"#;
    assert_eq!(canonical_json(input).unwrap(), expected);
    assert_eq!(
        canonical_json(br#"{"00":1,"0":2}"#).unwrap(),
        br#"{"0":2,"00":1}"#
    );
    assert_eq!(
        canonical_json(b"[2,1,{\"z\":1,\"y\":2}]").unwrap(),
        b"[2,1,{\"y\":2,\"z\":1}]"
    );
}

#[test]
fn utf16_order_puts_emoji_before_private_use() {
    let input = "{\"\\uE000\":1,\"😀\":2}";
    let expected = "{\"😀\":2,\"\u{E000}\":1}";
    assert_eq!(
        canonical_json(input.as_bytes()).unwrap(),
        expected.as_bytes()
    );
}

#[test]
fn string_escapes() {
    assert_eq!(canonical_json(br#""\ud800""#).unwrap(), br#""\ud800""#);
    assert_eq!(canonical_json(br#""\uD800""#).unwrap(), br#""\ud800""#);
    assert_eq!(canonical_json(br#""\udc00""#).unwrap(), br#""\udc00""#);
    assert_eq!(
        canonical_json(br#""\ud83d\ude00""#).unwrap(),
        "\"😀\"".as_bytes()
    );
    assert_eq!(canonical_json(br#""\/""#).unwrap(), br#""/""#);
    assert_eq!(canonical_json(br#""\n""#).unwrap(), br#""\n""#);
    let lone = Json::string(Wtf16::from_units(vec![0xD800]));
    assert_eq!(canonical_json_value(&lone).unwrap(), br#""\ud800""#);
    let pair = Json::string(Wtf16::from_units(vec![0xD83D, 0xDE00]));
    assert_eq!(canonical_json_value(&pair).unwrap(), "\"😀\"".as_bytes());
}

#[test]
fn number_spelling() {
    assert_eq!(canonical_json(b"1e2").unwrap(), b"100");
    assert_eq!(canonical_json(b"1.0").unwrap(), b"1");
    assert_eq!(canonical_json(b"-0").unwrap(), b"0");
    assert_eq!(canonical_json(b"-0.0").unwrap(), b"0");
    assert_eq!(canonical_json(b"-0e0").unwrap(), b"0");
    assert_eq!(
        canonical_json(b"9007199254740993").unwrap(),
        b"9007199254740992"
    );
    assert_eq!(
        canonical_json(b"[1e+21,1e-7,5e-324]").unwrap(),
        b"[1e+21,1e-7,5e-324]"
    );
    let zero = Json::number(-0.0).unwrap();
    assert_eq!(canonical_json_value(&zero).unwrap(), b"0");
    assert_eq!(
        stable_hash_value(&zero).unwrap(),
        stable_hash(b"0").unwrap()
    );
}

#[test]
fn duplicate_keys() {
    assert_invalid(br#"{"a":1,"a":2}"#);
    assert_invalid(br#"{"a":1,"\u0061":2}"#);
    let duplicate = Json::object(vec![
        (Wtf16::from_str("a"), Json::null()),
        (Wtf16::from_str("a"), Json::bool(true)),
    ]);
    assert_eq!(duplicate.unwrap_err(), Error::InvalidJson);
}

#[test]
fn object_constructor_sorts() {
    let object = Json::object(vec![
        (Wtf16::from_str("b"), Json::number(1.0).unwrap()),
        (Wtf16::from_str("10"), Json::number(2.0).unwrap()),
        (Wtf16::from_str("2"), Json::number(3.0).unwrap()),
    ])
    .unwrap();
    assert_eq!(
        canonical_json_value(&object).unwrap(),
        br#"{"2":3,"10":2,"b":1}"#
    );
}

#[test]
fn depth_limit() {
    assert_eq!(check_depth(128), Ok(()));
    assert_eq!(check_depth(129), Err(Error::TooDeep));
    assert!(canonical_json(&nested_arrays(128)).is_ok());
    assert_eq!(
        canonical_json(&nested_arrays(129)).unwrap_err(),
        Error::TooDeep
    );

    let mut value = Json::number(1.0).unwrap();
    for _ in 0..128 {
        value = Json::array(vec![value]);
    }
    assert!(canonical_json_value(&value).is_ok());
    value = Json::array(vec![value]);
    assert_eq!(canonical_json_value(&value).unwrap_err(), Error::TooDeep);

    let mut object = Json::null();
    for _ in 0..128 {
        object = Json::object(vec![(Wtf16::from_str("a"), object)]).unwrap();
    }
    assert!(canonical_json_value(&object).is_ok());
    object = Json::object(vec![(Wtf16::from_str("a"), object)]).unwrap();
    assert_eq!(canonical_json_value(&object).unwrap_err(), Error::TooDeep);
}

#[test]
fn scalars_whitespace_and_rejections() {
    assert_eq!(canonical_json(b" null ").unwrap(), b"null");
    assert_eq!(canonical_json(b"true").unwrap(), b"true");
    assert_eq!(canonical_json(b"false").unwrap(), b"false");
    assert_eq!(canonical_json(b"[]").unwrap(), b"[]");
    assert_eq!(canonical_json(b"{}").unwrap(), b"{}");
    assert_eq!(
        canonical_json(b" { \"b\" : 1 , \"a\" : 2 } ").unwrap(),
        br#"{"a":2,"b":1}"#
    );
    for input in [
        b"".as_slice(),
        b" ",
        b"[",
        b"]",
        b"{",
        b"}",
        b"[1,]",
        b"{,}",
        b"01",
        b"+1",
        b"1.",
        b"1e",
        b"1e+",
        b"-",
        b"\xEF\xBB\xBF{}",
        b"{}{}",
        b"\"\n\"",
        b"1e309",
    ] {
        assert_invalid(input);
    }
    assert_eq!(canonical_json(&[0xFF]).unwrap_err().code(), "not_utf8");
    assert_eq!(
        canonical_json(&[0xC3, 0x28]).unwrap_err().code(),
        "not_utf8"
    );
}

#[test]
fn host_number_rejections() {
    assert_eq!(Json::number(f64::NAN).unwrap_err(), Error::TypeError);
    assert_eq!(
        Json::number(f64::INFINITY).unwrap_err().code(),
        "type_error"
    );
    assert_eq!(
        Json::number(f64::NEG_INFINITY).unwrap_err().code(),
        "type_error"
    );
}

#[test]
fn error_codes_match_display() {
    for error in [
        Error::NotUtf8,
        Error::InvalidJson,
        Error::TooDeep,
        Error::Cycle,
        Error::TypeError,
    ] {
        assert_eq!(error.to_string(), error.code());
    }
    assert_eq!(Error::NotUtf8.code(), "not_utf8");
    assert_eq!(Error::InvalidJson.code(), "invalid_json");
    assert_eq!(Error::TooDeep.code(), "too_deep");
    assert_eq!(Error::Cycle.code(), "cycle");
    assert_eq!(Error::TypeError.code(), "type_error");
}

fn assert_invalid(input: &[u8]) {
    assert_eq!(
        canonical_json(input).unwrap_err().code(),
        "invalid_json",
        "{input:?}"
    );
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(depth * 2 + 1);
    bytes.extend(std::iter::repeat(b'[').take(depth));
    bytes.push(b'0');
    bytes.extend(std::iter::repeat(b']').take(depth));
    bytes
}
