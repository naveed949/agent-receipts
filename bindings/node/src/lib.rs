use std::ffi::CString;
use std::ptr;

use napi::bindgen_prelude::{Buffer, Either, Env, JsObjectValue, Object, Unknown as JsUnknown};
use napi::sys::{self, napi_value};
use napi::{check_status, Error as NapiError, JsValue, Status, ValueType};
use napi_derive::napi;

use agent_receipts::{Error, Json, SignerError, SigningKey, Wtf16};

enum Fail {
    Core(Error),
    Host(NapiError),
}

struct Host<'a> {
    env: &'a Env,
    object_ctor: napi_value,
    is_proxy: napi_value,
    object_proto: JsUnknown<'a>,
    array_proto: JsUnknown<'a>,
}

#[napi(js_name = "canonicalJson")]
pub fn canonical_json(
    env: &Env,
    value: JsUnknown,
) -> std::result::Result<String, NapiError<&'static str>> {
    match build(env, value) {
        Ok(tree) => agent_receipts::canonical_json_value(&tree)
            .and_then(decode_utf8)
            .map_err(core_error),
        Err(err) => Err(fail_to_napi(err)),
    }
}

#[napi(js_name = "stableHash")]
pub fn stable_hash(
    env: &Env,
    value: JsUnknown,
) -> std::result::Result<String, NapiError<&'static str>> {
    match build(env, value) {
        Ok(tree) => agent_receipts::stable_hash_value(&tree).map_err(core_error),
        Err(err) => Err(fail_to_napi(err)),
    }
}

#[napi(js_name = "verifyAuditReceipt")]
pub fn verify_audit_receipt(env: &Env, receipt: JsUnknown, key: JsUnknown) -> bool {
    let ok = match (build(env, receipt), key_from_unknown(&key)) {
        (Ok(tree), Ok(key)) => agent_receipts::verify_audit_receipt(&tree, &key),
        _ => false,
    };
    clear_pending_exception(env);
    ok
}

#[napi(js_name = "resignAuditReceipt")]
pub fn resign_audit_receipt<'env>(
    env: &'env Env,
    receipt: JsUnknown,
    key: Either<String, Buffer>,
) -> std::result::Result<JsUnknown<'env>, NapiError<&'static str>> {
    let tree = build(env, receipt).map_err(fail_to_napi)?;
    let key = key_bytes(&key).map_err(fail_to_napi)?;
    let resigned = agent_receipts::resign_audit_receipt(&tree, &key).map_err(core_error)?;
    let bytes = agent_receipts::canonical_json_value(&resigned).map_err(core_error)?;
    json_parse(env, bytes).map_err(fail_to_napi)
}

#[napi(js_name = "verifyControlledIntegrity")]
pub fn verify_controlled_integrity(
    env: &Env,
    value: JsUnknown,
    key: JsUnknown,
    key_id: JsUnknown,
    evidence: JsUnknown,
) -> bool {
    let ok = match (
        build(env, value),
        key_from_unknown(&key),
        js_string(&key_id),
        build(env, evidence),
    ) {
        (Ok(value), Ok(key), Ok(key_id), Ok(evidence)) => {
            agent_receipts::verify_controlled_integrity(&value, &key, &key_id, &evidence)
        }
        _ => false,
    };
    clear_pending_exception(env);
    ok
}

#[napi(js_name = "signControlledIntegrity")]
pub fn sign_controlled_integrity<'env>(
    env: &'env Env,
    value: JsUnknown,
    key: Either<String, Buffer>,
    key_id: String,
) -> std::result::Result<JsUnknown<'env>, NapiError<&'static str>> {
    let tree = build(env, value).map_err(fail_to_napi)?;
    let key = key_bytes(&key).map_err(fail_to_napi)?;
    let evidence =
        agent_receipts::sign_controlled_integrity(&tree, &key, &key_id).map_err(signer_error)?;
    let bytes = agent_receipts::canonical_json_value(&evidence).map_err(core_error)?;
    json_parse(env, bytes).map_err(fail_to_napi)
}

#[napi(js_name = "auditSigningKey")]
pub fn audit_signing_key_js(
    key: Either<String, Buffer>,
) -> std::result::Result<Buffer, NapiError<&'static str>> {
    let checked = match &key {
        Either::A(text) => {
            let utf8 = text.as_bytes();
            agent_receipts::audit_signing_key(SigningKey::Text {
                utf8,
                utf16_len: text.encode_utf16().count(),
            })
        }
        Either::B(bytes) => agent_receipts::audit_signing_key(SigningKey::Bytes(bytes.as_ref())),
    }
    .map_err(signer_error)?;
    Ok(Buffer::from(checked.to_vec()))
}

#[napi(js_name = "controlledSigningKey")]
pub fn controlled_signing_key_js(
    key: Either<String, Buffer>,
) -> std::result::Result<Buffer, NapiError<&'static str>> {
    let bytes = key_bytes(&key).map_err(fail_to_napi)?;
    let checked = agent_receipts::controlled_signing_key(&bytes).map_err(signer_error)?;
    Ok(Buffer::from(checked.to_vec()))
}

#[napi]
pub const AUDIT_RECEIPT_VERSION: &str = agent_receipts::AUDIT_RECEIPT_VERSION;

#[napi]
pub const AUDIT_RECEIPT_V2_VERSION: &str = agent_receipts::AUDIT_RECEIPT_V2_VERSION;

#[napi]
pub const CONTROLLED_INTEGRITY_VERSION: &str = agent_receipts::CONTROLLED_INTEGRITY_VERSION;

fn key_bytes(key: &Either<String, Buffer>) -> Result<Vec<u8>, Fail> {
    match key {
        Either::A(text) => Ok(text.as_bytes().to_vec()),
        Either::B(bytes) => Ok(bytes.to_vec()),
    }
}

fn key_from_unknown(value: &JsUnknown<'_>) -> Result<Vec<u8>, Fail> {
    match value.get_type().map_err(Fail::Host)? {
        ValueType::String => utf8_from_js_string(value),
        _ if value.is_buffer().map_err(Fail::Host)? => buffer_bytes(value),
        _ => Err(Fail::Core(Error::TypeError)),
    }
}

fn js_string(value: &JsUnknown<'_>) -> Result<String, Fail> {
    if value.get_type().map_err(Fail::Host)? != ValueType::String {
        return Err(Fail::Core(Error::TypeError));
    }
    String::from_utf8(utf8_from_js_string(value)?).map_err(|_| Fail::Core(Error::TypeError))
}

fn utf8_from_js_string(value: &JsUnknown<'_>) -> Result<Vec<u8>, Fail> {
    let raw_env = value.value().env;
    let raw_value = value.raw();
    let mut len = 0usize;
    check_status!(unsafe {
        sys::napi_get_value_string_utf8(raw_env, raw_value, ptr::null_mut(), 0, &mut len)
    })
    .map_err(Fail::Host)?;
    let mut buf = vec![0u8; len + 1];
    let mut written = 0usize;
    check_status!(unsafe {
        sys::napi_get_value_string_utf8(
            raw_env,
            raw_value,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut written,
        )
    })
    .map_err(Fail::Host)?;
    buf.truncate(written);
    Ok(buf)
}

fn buffer_bytes(value: &JsUnknown<'_>) -> Result<Vec<u8>, Fail> {
    let mut data = ptr::null_mut();
    let mut len = 0usize;
    check_status!(unsafe {
        sys::napi_get_buffer_info(value.value().env, value.raw(), &mut data, &mut len)
    })
    .map_err(Fail::Host)?;
    if data.is_null() {
        return Ok(Vec::new());
    }
    Ok(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) }.to_vec())
}

fn clear_pending_exception(env: &Env) {
    let mut pending = false;
    if unsafe { sys::napi_is_exception_pending(env.raw(), &mut pending) } != 0 {
        return;
    }
    if !pending {
        return;
    }
    let mut exception = ptr::null_mut();
    unsafe {
        sys::napi_get_and_clear_last_exception(env.raw(), &mut exception);
    }
}

fn json_parse(env: &Env, bytes: Vec<u8>) -> Result<JsUnknown<'_>, Fail> {
    let text = decode_utf8(bytes).map_err(Fail::Core)?;
    env.run_script(format!("JSON.parse({})", json_string_literal(&text)))
        .map_err(Fail::Host)
}

fn json_string_literal(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn signer_error(err: SignerError) -> NapiError<&'static str> {
    match err {
        SignerError::ShortAuditKey => NapiError::new(
            "TypeError",
            "audit signingKey must contain at least 16 bytes",
        ),
        SignerError::ShortControlledKey => NapiError::new(
            "RangeError",
            "controlled integrity signing key must contain at least 16 bytes",
        ),
        SignerError::InvalidKeyId => NapiError::new("TypeError", "invalid key id"),
        SignerError::RejectedInput => NapiError::new("type_error", "type_error"),
    }
}

fn decode_utf8(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| Error::InvalidJson)
}

fn build(env: &Env, value: JsUnknown) -> Result<Json, Fail> {
    let host = Host::load(env)?;
    let mut ancestors = Vec::new();
    walk(&host, value, &mut ancestors, 0)
}

impl<'a> Host<'a> {
    fn load(env: &'a Env) -> Result<Self, Fail> {
        let global = env.get_global().map_err(Fail::Host)?;
        let object_ctor: JsUnknown = global
            .get_named_property_unchecked("Object")
            .map_err(Fail::Host)?;
        let array_ctor: JsUnknown = global
            .get_named_property_unchecked("Array")
            .map_err(Fail::Host)?;
        let object_proto = object_ctor
            .coerce_to_object()
            .map_err(Fail::Host)?
            .get_named_property("prototype")
            .map_err(Fail::Host)?;
        let array_proto = array_ctor
            .coerce_to_object()
            .map_err(Fail::Host)?
            .get_named_property("prototype")
            .map_err(Fail::Host)?;
        let is_proxy: JsUnknown = env
            .run_script("process.getBuiltinModule('node:util').types.isProxy")
            .map_err(Fail::Host)?;
        Ok(Self {
            env,
            object_ctor: object_ctor.raw(),
            is_proxy: is_proxy.raw(),
            object_proto,
            array_proto,
        })
    }
}

fn walk(
    host: &Host<'_>,
    value: JsUnknown,
    ancestors: &mut Vec<napi_value>,
    depth: usize,
) -> Result<Json, Fail> {
    match value.get_type().map_err(Fail::Host)? {
        ValueType::Null => Ok(Json::null()),
        ValueType::Boolean => {
            let flag = value.coerce_to_bool().map_err(Fail::Host)?;
            Ok(Json::bool(flag))
        }
        ValueType::Number => {
            let number = value.coerce_to_number().map_err(Fail::Host)?;
            let parsed = number.get_double().map_err(Fail::Host)?;
            Json::number(parsed).map_err(Fail::Core)
        }
        ValueType::String => Ok(Json::string(Wtf16::from_units(utf16_units(&value)?))),
        ValueType::Object => walk_object(host, value, ancestors, depth),
        ValueType::Undefined
        | ValueType::Symbol
        | ValueType::Function
        | ValueType::External
        | ValueType::Unknown => Err(Fail::Core(Error::TypeError)),
    }
}

fn walk_object(
    host: &Host<'_>,
    value: JsUnknown,
    ancestors: &mut Vec<napi_value>,
    depth: usize,
) -> Result<Json, Fail> {
    if is_proxy(host, value.raw())? {
        return Err(Fail::Core(Error::TypeError));
    }
    if value.is_buffer().map_err(Fail::Host)?
        || value.is_typedarray().map_err(Fail::Host)?
        || value.is_dataview().map_err(Fail::Host)?
        || value.is_arraybuffer().map_err(Fail::Host)?
    {
        return Err(Fail::Core(Error::TypeError));
    }
    let object = value.coerce_to_object().map_err(Fail::Host)?;
    reject_symbol_keys(host, object.raw())?;
    if value.is_array().map_err(Fail::Host)? {
        return walk_array(host, value, object, ancestors, depth);
    }
    walk_plain(host, value, object, ancestors, depth)
}

fn walk_array(
    host: &Host<'_>,
    value: JsUnknown,
    object: Object<'_>,
    ancestors: &mut Vec<napi_value>,
    depth: usize,
) -> Result<Json, Fail> {
    if !same_unknown(
        host,
        object.get_prototype().map_err(Fail::Host)?,
        host.array_proto,
    )? {
        return Err(Fail::Core(Error::TypeError));
    }
    let length = object.get_array_length().map_err(Fail::Host)?;
    let names = own_string_names(host, object.raw())?;
    let mut data = Vec::new();
    let mut saw_length = false;
    for name in names {
        let units = utf16_units(&name)?;
        // `length` is the array's own non-enumerable property. It is not a JSON element.
        if is_length(&units) {
            saw_length = true;
            continue;
        }
        if !enumerable(host, object.raw(), name.raw())? {
            return Err(Fail::Core(Error::TypeError));
        }
        data.push(units);
    }
    if !saw_length || data.len() != length as usize {
        return Err(Fail::Core(Error::TypeError));
    }
    if data.iter().any(|units| !canonical_index(units, length)) {
        return Err(Fail::Core(Error::TypeError));
    }
    enter_container(host, ancestors, value.raw(), depth)?;
    let result = (|| {
        let mut items = Vec::with_capacity(length as usize);
        for index in 0..length {
            let child = object.get_element::<JsUnknown>(index).map_err(Fail::Host)?;
            items.push(walk(host, child, ancestors, depth + 1)?);
        }
        Ok(Json::array(items))
    })();
    ancestors.pop();
    result
}

fn walk_plain(
    host: &Host<'_>,
    value: JsUnknown,
    object: Object<'_>,
    ancestors: &mut Vec<napi_value>,
    depth: usize,
) -> Result<Json, Fail> {
    let prototype = object.get_prototype().map_err(Fail::Host)?;
    let plain = prototype.get_type().map_err(Fail::Host)? == ValueType::Null
        || same_unknown(host, prototype, host.object_proto)?;
    if !plain {
        return Err(Fail::Core(Error::TypeError));
    }
    let names = own_string_names(host, object.raw())?;
    enter_container(host, ancestors, value.raw(), depth)?;
    let result = (|| {
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            if !enumerable(host, object.raw(), name.raw())? {
                return Err(Fail::Core(Error::TypeError));
            }
            let units = utf16_units(&name)?;
            let child: JsUnknown = object.get_property(name).map_err(Fail::Host)?;
            entries.push((
                Wtf16::from_units(units),
                walk(host, child, ancestors, depth + 1)?,
            ));
        }
        Json::object(entries).map_err(Fail::Core)
    })();
    ancestors.pop();
    result
}

fn enter_container(
    host: &Host<'_>,
    ancestors: &mut Vec<napi_value>,
    raw: napi_value,
    depth: usize,
) -> Result<(), Fail> {
    if is_ancestor(host, ancestors, raw)? {
        return Err(Fail::Core(Error::Cycle));
    }
    agent_receipts::check_depth(depth + 1).map_err(Fail::Core)?;
    ancestors.push(raw);
    Ok(())
}

fn is_proxy(host: &Host<'_>, value: napi_value) -> Result<bool, Fail> {
    let args = [value];
    let mut result = ptr::null_mut();
    check_status!(unsafe {
        sys::napi_call_function(
            host.env.raw(),
            host.object_ctor,
            host.is_proxy,
            args.len(),
            args.as_ptr(),
            &mut result,
        )
    })
    .map_err(Fail::Host)?;
    raw_unknown(host, result)
        .coerce_to_bool()
        .map_err(Fail::Host)
}

fn reject_symbol_keys(host: &Host<'_>, object: napi_value) -> Result<(), Fail> {
    let symbols = call(host, "getOwnPropertySymbols", &[object])?;
    let list = symbols.coerce_to_object().map_err(Fail::Host)?;
    if list.get_array_length().map_err(Fail::Host)? != 0 {
        return Err(Fail::Core(Error::TypeError));
    }
    Ok(())
}

fn own_string_names<'a>(host: &Host<'a>, object: napi_value) -> Result<Vec<JsUnknown<'a>>, Fail> {
    let names = call(host, "getOwnPropertyNames", &[object])?;
    values_of(names)
}

fn enumerable(host: &Host<'_>, object: napi_value, name: napi_value) -> Result<bool, Fail> {
    let descriptor = call(host, "getOwnPropertyDescriptor", &[object, name])?;
    if descriptor.get_type().map_err(Fail::Host)? == ValueType::Undefined {
        return Err(Fail::Core(Error::TypeError));
    }
    let object = descriptor.coerce_to_object().map_err(Fail::Host)?;
    object.get_named_property("enumerable").map_err(Fail::Host)
}

fn values_of(value: JsUnknown<'_>) -> Result<Vec<JsUnknown<'_>>, Fail> {
    let object = value.coerce_to_object().map_err(Fail::Host)?;
    let length = object.get_array_length().map_err(Fail::Host)?;
    let mut items = Vec::with_capacity(length as usize);
    for index in 0..length {
        items.push(object.get_element(index).map_err(Fail::Host)?);
    }
    Ok(items)
}

fn call<'a>(host: &Host<'a>, method: &str, args: &[napi_value]) -> Result<JsUnknown<'a>, Fail> {
    let name = CString::new(method).map_err(|_| Fail::Core(Error::TypeError))?;
    let mut function = ptr::null_mut();
    check_status!(unsafe {
        sys::napi_get_named_property(
            host.env.raw(),
            host.object_ctor,
            name.as_ptr(),
            &mut function,
        )
    })
    .map_err(Fail::Host)?;
    let mut result = ptr::null_mut();
    check_status!(unsafe {
        sys::napi_call_function(
            host.env.raw(),
            host.object_ctor,
            function,
            args.len(),
            args.as_ptr(),
            &mut result,
        )
    })
    .map_err(Fail::Host)?;
    Ok(unsafe { JsUnknown::from_raw_unchecked(host.env.raw(), result) })
}

fn is_ancestor(host: &Host<'_>, ancestors: &[napi_value], raw: napi_value) -> Result<bool, Fail> {
    for ancestor in ancestors {
        if same_raw(host, *ancestor, raw)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn same_raw(host: &Host<'_>, left: napi_value, right: napi_value) -> Result<bool, Fail> {
    same_unknown(host, raw_unknown(host, left), raw_unknown(host, right))
}

fn same_unknown(host: &Host<'_>, left: JsUnknown<'_>, right: JsUnknown<'_>) -> Result<bool, Fail> {
    host.env.strict_equals(left, right).map_err(Fail::Host)
}

fn raw_unknown<'a>(host: &Host<'a>, raw: napi_value) -> JsUnknown<'a> {
    unsafe { JsUnknown::from_raw_unchecked(host.env.raw(), raw) }
}

fn utf16_units(value: &JsUnknown<'_>) -> Result<Vec<u16>, Fail> {
    let raw_env = value.value().env;
    let raw_value = value.raw();
    let mut len = 0usize;
    check_status!(unsafe {
        sys::napi_get_value_string_utf16(raw_env, raw_value, ptr::null_mut(), 0, &mut len)
    })
    .map_err(Fail::Host)?;
    let mut units = vec![0u16; len + 1];
    let mut written = 0usize;
    check_status!(unsafe {
        sys::napi_get_value_string_utf16(
            raw_env,
            raw_value,
            units.as_mut_ptr(),
            units.len(),
            &mut written,
        )
    })
    .map_err(Fail::Host)?;
    units.truncate(written);
    Ok(units)
}

fn is_length(units: &[u16]) -> bool {
    units == [b'l', b'e', b'n', b'g', b't', b'h'].map(u16::from)
}

fn canonical_index(units: &[u16], length: u32) -> bool {
    if units.is_empty() || units.len() > 10 {
        return false;
    }
    if units.len() > 1 && units[0] == u16::from(b'0') {
        return false;
    }
    let mut value = 0u64;
    for &unit in units {
        if !(u16::from(b'0')..=u16::from(b'9')).contains(&unit) {
            return false;
        }
        value = value * 10 + u64::from(unit - u16::from(b'0'));
    }
    u32::try_from(value)
        .map(|index| index < length)
        .unwrap_or(false)
}

fn core_error(err: Error) -> NapiError<&'static str> {
    NapiError::new(err.code(), err.code())
}

fn fail_to_napi(err: Fail) -> NapiError<&'static str> {
    match err {
        Fail::Core(err) => core_error(err),
        Fail::Host(err) if err.status == Status::PendingException => {
            NapiError::new("PendingException", "")
        }
        Fail::Host(err) => NapiError::new("GenericFailure", err.reason.clone()),
    }
}
