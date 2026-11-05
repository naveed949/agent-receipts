use pyo3::exceptions::{PyException, PyOverflowError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{
    PyBool, PyByteArray, PyBytes, PyDict, PyFloat, PyInt, PyList, PyModule, PyString,
};

use receipts::{
    AuthorityError, AuthorityPath, CompareResult, Error, Json, SignerError, SigningKey, Wtf16,
    AUDIT_RECEIPT_V2_VERSION, AUDIT_RECEIPT_VERSION, CONTROLLED_INTEGRITY_VERSION,
};

pyo3::create_exception!(agent_receipts, CanonicalizeError, PyException);

enum Input {
    Bytes(Vec<u8>),
    Value(Json),
}

enum Fail {
    Domain(Error),
    Python(PyErr),
}

#[pyfunction]
fn canonical_json(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<String> {
    let input = read_input(value).map_err(|err| fail_to_py(py, err))?;
    let result = py.detach(move || match input {
        Input::Bytes(bytes) => receipts::canonical_json(&bytes).and_then(decode_utf8),
        Input::Value(value) => receipts::canonical_json_value(&value).and_then(decode_utf8),
    });
    result.map_err(|err| canonicalize_error(py, err))
}

#[pyfunction]
fn stable_hash(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<String> {
    let input = read_input(value).map_err(|err| fail_to_py(py, err))?;
    let result = py.detach(move || match input {
        Input::Bytes(bytes) => receipts::stable_hash(&bytes),
        Input::Value(value) => receipts::stable_hash_value(&value),
    });
    result.map_err(|err| canonicalize_error(py, err))
}

fn decode_utf8(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| Error::InvalidJson)
}

fn read_input(value: &Bound<'_, PyAny>) -> Result<Input, Fail> {
    if let Ok(bytes) = value.cast_exact::<PyBytes>() {
        return Ok(Input::Bytes(bytes.as_bytes().to_vec()));
    }
    if let Ok(array) = value.cast_exact::<PyByteArray>() {
        return Ok(Input::Bytes(array.to_vec()));
    }
    let mut ancestors = Vec::new();
    Ok(Input::Value(walk(value, &mut ancestors, 0)?))
}

fn walk(value: &Bound<'_, PyAny>, ancestors: &mut Vec<usize>, depth: usize) -> Result<Json, Fail> {
    if value.is_none() {
        return Ok(Json::null());
    }
    if let Ok(flag) = value.cast_exact::<PyBool>() {
        return Ok(Json::bool(flag.is_true()));
    }
    if value.cast_exact::<PyInt>().is_ok() {
        return Json::number(exact_int(value)?).map_err(Fail::Domain);
    }
    if let Ok(number) = value.cast_exact::<PyFloat>() {
        let parsed: f64 = number.extract().map_err(Fail::Python)?;
        return Json::number(parsed).map_err(Fail::Domain);
    }
    if value.cast_exact::<PyString>().is_ok() {
        return Ok(Json::string(Wtf16::from_units(utf16(value)?)));
    }
    if let Ok(list) = value.cast_exact::<PyList>() {
        return walk_list(list, ancestors, depth);
    }
    if let Ok(dict) = value.cast_exact::<PyDict>() {
        return walk_dict(dict, ancestors, depth);
    }
    Err(Fail::Domain(Error::TypeError))
}

fn walk_list(
    list: &Bound<'_, PyList>,
    ancestors: &mut Vec<usize>,
    depth: usize,
) -> Result<Json, Fail> {
    enter(ancestors, list.as_ptr() as usize, depth)?;
    let result = (|| {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(walk(&item, ancestors, depth + 1)?);
        }
        Ok(Json::array(items))
    })();
    ancestors.pop();
    result
}

fn walk_dict(
    dict: &Bound<'_, PyDict>,
    ancestors: &mut Vec<usize>,
    depth: usize,
) -> Result<Json, Fail> {
    enter(ancestors, dict.as_ptr() as usize, depth)?;
    let result = (|| {
        let mut entries = Vec::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            let text = key
                .cast_exact::<PyString>()
                .map_err(|_| Fail::Domain(Error::TypeError))?;
            let units = utf16(text.as_any())?;
            entries.push((Wtf16::from_units(units), walk(&item, ancestors, depth + 1)?));
        }
        Json::object(entries).map_err(Fail::Domain)
    })();
    ancestors.pop();
    result
}

fn enter(ancestors: &mut Vec<usize>, id: usize, depth: usize) -> Result<(), Fail> {
    if ancestors.contains(&id) {
        return Err(Fail::Domain(Error::Cycle));
    }
    receipts::check_depth(depth + 1).map_err(Fail::Domain)?;
    ancestors.push(id);
    Ok(())
}

fn exact_int(value: &Bound<'_, PyAny>) -> Result<f64, Fail> {
    let py = value.py();
    let builtins = PyModule::import(py, "builtins").map_err(Fail::Python)?;
    let float_fn = builtins.getattr("float").map_err(Fail::Python)?;
    let as_float = match float_fn.call1((value,)) {
        Ok(result) => result,
        Err(err) if err.is_instance_of::<PyOverflowError>(py) => {
            return Err(Fail::Domain(Error::TypeError));
        }
        Err(err) => return Err(Fail::Python(err)),
    };
    let number: f64 = as_float.extract().map_err(Fail::Python)?;
    if !number.is_finite() {
        return Err(Fail::Domain(Error::TypeError));
    }
    let int_fn = builtins.getattr("int").map_err(Fail::Python)?;
    let back = int_fn.call1((&as_float,)).map_err(Fail::Python)?;
    if !back.eq(value).map_err(Fail::Python)? {
        return Err(Fail::Domain(Error::TypeError));
    }
    Ok(number)
}

fn utf16(value: &Bound<'_, PyAny>) -> Result<Vec<u16>, Fail> {
    let encoded = value
        .call_method("encode", ("utf-16-le", "surrogatepass"), None)
        .map_err(Fail::Python)?;
    let bytes = encoded
        .cast_exact::<PyBytes>()
        .map_err(|_| Fail::Domain(Error::TypeError))?;
    let raw = bytes.as_bytes();
    if raw.len() % 2 != 0 {
        return Err(Fail::Domain(Error::TypeError));
    }
    let mut units = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(units)
}

fn fail_to_py(py: Python<'_>, err: Fail) -> PyErr {
    match err {
        Fail::Domain(err) => canonicalize_error(py, err),
        Fail::Python(err) => err,
    }
}

#[pyfunction]
fn verify_audit_receipt(
    py: Python<'_>,
    receipt: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
) -> bool {
    let Ok(tree) = read_value(receipt) else {
        return false;
    };
    let Ok(key) = read_key_bytes(key) else {
        return false;
    };
    py.detach(move || receipts::verify_audit_receipt(&tree, &key))
}

#[pyfunction]
fn resign_audit_receipt(
    py: Python<'_>,
    receipt: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let tree = read_value(receipt).map_err(|err| fail_to_py(py, err))?;
    let key = read_key_bytes(key).map_err(|err| fail_to_py(py, err))?;
    let resigned = py
        .detach(move || {
            receipts::resign_audit_receipt(&tree, &key)
                .and_then(|value| receipts::canonical_json_value(&value))
        })
        .map_err(|err| canonicalize_error(py, err))?;
    json_loads(py, resigned)
}

#[pyfunction]
fn verify_controlled_integrity(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
    key_id: &Bound<'_, PyAny>,
    evidence: &Bound<'_, PyAny>,
) -> bool {
    let Ok(value) = read_value(value) else {
        return false;
    };
    let Ok(key) = read_key_bytes(key) else {
        return false;
    };
    let Ok(key_id) = key_id.extract::<String>() else {
        return false;
    };
    let Ok(evidence) = read_value(evidence) else {
        return false;
    };
    py.detach(move || receipts::verify_controlled_integrity(&value, &key, &key_id, &evidence))
}

#[pyfunction]
fn sign_controlled_integrity(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
    key_id: &str,
) -> PyResult<Py<PyAny>> {
    let tree = read_value(value).map_err(|err| fail_to_py(py, err))?;
    let key = read_key_bytes(key).map_err(|err| fail_to_py(py, err))?;
    let key_id = key_id.to_owned();
    let evidence = py
        .detach(move || {
            let signed = receipts::sign_controlled_integrity(&tree, &key, &key_id)?;
            receipts::canonical_json_value(&signed).map_err(|_| SignerError::RejectedInput)
        })
        .map_err(signer_error)?;
    json_loads(py, evidence)
}

#[pyfunction]
fn audit_signing_key(key: &Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
    let py = key.py();
    let (bytes, kind) = read_signing_key(key).map_err(|err| fail_to_py(py, err))?;
    let checked = match kind {
        KeyKind::Text { utf16_len } => receipts::audit_signing_key(SigningKey::Text {
            utf8: &bytes,
            utf16_len,
        }),
        KeyKind::Bytes => receipts::audit_signing_key(SigningKey::Bytes(&bytes)),
    }
    .map_err(signer_error)?;
    Ok(PyBytes::new(py, checked).unbind())
}

#[pyfunction]
fn controlled_signing_key(key: &Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
    let py = key.py();
    let bytes = read_key_bytes(key).map_err(|err| fail_to_py(py, err))?;
    let checked = receipts::controlled_signing_key(&bytes).map_err(signer_error)?;
    Ok(PyBytes::new(py, checked).unbind())
}

enum KeyKind {
    Text { utf16_len: usize },
    Bytes,
}

fn read_value(value: &Bound<'_, PyAny>) -> Result<Json, Fail> {
    match read_input(value)? {
        Input::Value(tree) => Ok(tree),
        Input::Bytes(_) => Err(Fail::Domain(Error::TypeError)),
    }
}

fn read_key_bytes(value: &Bound<'_, PyAny>) -> Result<Vec<u8>, Fail> {
    Ok(read_signing_key(value)?.0)
}

fn read_signing_key(value: &Bound<'_, PyAny>) -> Result<(Vec<u8>, KeyKind), Fail> {
    if let Ok(bytes) = value.cast_exact::<PyBytes>() {
        return Ok((bytes.as_bytes().to_vec(), KeyKind::Bytes));
    }
    if let Ok(array) = value.cast_exact::<PyByteArray>() {
        return Ok((array.to_vec(), KeyKind::Bytes));
    }
    if value.cast_exact::<PyString>().is_ok() {
        let units = utf16(value)?;
        let utf8 = value
            .call_method("encode", ("utf-8",), None)
            .map_err(Fail::Python)?;
        let raw = utf8
            .cast_exact::<PyBytes>()
            .map_err(|_| Fail::Domain(Error::TypeError))?;
        return Ok((
            raw.as_bytes().to_vec(),
            KeyKind::Text {
                utf16_len: units.len(),
            },
        ));
    }
    Err(Fail::Domain(Error::TypeError))
}

fn json_loads(py: Python<'_>, bytes: Vec<u8>) -> PyResult<Py<PyAny>> {
    let text = decode_utf8(bytes).map_err(|err| canonicalize_error(py, err))?;
    let json = PyModule::import(py, "json")?;
    Ok(json.call_method1("loads", (text,))?.unbind())
}

#[pyfunction]
fn compare_authority_contracts(
    py: Python<'_>,
    previous: &Bound<'_, PyAny>,
    next: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let previous = read_value(previous).map_err(|err| authority_host_error(py, err))?;
    let next = read_value(next).map_err(|err| authority_host_error(py, err))?;
    let result = py
        .detach(move || receipts::compare_authority_contracts(&previous, &next))
        .map_err(|err| authority_error(py, err))?;
    compare_to_py(py, result)
}

#[pyfunction]
fn normalize_authority_policy(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    let tree = read_value(value).map_err(|err| authority_host_error(py, err))?;
    let normalized = py
        .detach(move || {
            receipts::normalize_authority_policy(&tree).and_then(|value| {
                receipts::canonical_json_value(&value).map_err(|_| AuthorityError::InvalidInput)
            })
        })
        .map_err(|err| authority_error(py, err))?;
    json_loads(py, normalized)
}

#[pyfunction]
fn normalize_https_authority_rules(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let tree = read_value(value).map_err(|err| authority_host_error(py, err))?;
    let normalized = py
        .detach(move || {
            receipts::normalize_https_authority_rules(&tree).and_then(|value| {
                receipts::canonical_json_value(&value).map_err(|_| AuthorityError::InvalidInput)
            })
        })
        .map_err(|err| authority_error(py, err))?;
    json_loads(py, normalized)
}

#[pyfunction]
fn is_https_authority_subset(
    py: Python<'_>,
    inner: &Bound<'_, PyAny>,
    outer: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let inner = read_value(inner).map_err(|err| authority_host_error(py, err))?;
    let outer = read_value(outer).map_err(|err| authority_host_error(py, err))?;
    py.detach(move || receipts::is_https_authority_subset(&inner, &outer))
        .map_err(|err| authority_error(py, err))
}

fn compare_to_py(py: Python<'_>, result: CompareResult) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    dict.set_item("relationship", result.relationship.as_str())?;
    dict.set_item("widened", path_names(py, &result.widened)?)?;
    dict.set_item("narrowed", path_names(py, &result.narrowed)?)?;
    Ok(dict.into_any().unbind())
}

fn path_names(py: Python<'_>, paths: &[AuthorityPath]) -> PyResult<Py<PyList>> {
    let items: Vec<&str> = paths.iter().map(|path| path.as_str()).collect();
    Ok(PyList::new(py, items)?.unbind())
}

fn authority_error(py: Python<'_>, err: AuthorityError) -> PyErr {
    type_error_with_code(py, err.code())
}

fn authority_host_error(py: Python<'_>, err: Fail) -> PyErr {
    match err {
        Fail::Domain(err) => type_error_with_code(py, err.code()),
        Fail::Python(err) => err,
    }
}

fn type_error_with_code(py: Python<'_>, code: &'static str) -> PyErr {
    let raised = PyTypeError::new_err(code);
    match raised.value(py).setattr("code", code) {
        Ok(()) => raised,
        Err(set_err) => set_err,
    }
}

fn signer_error(err: SignerError) -> PyErr {
    match err {
        SignerError::ShortAuditKey => {
            PyTypeError::new_err("audit signingKey must contain at least 16 bytes")
        }
        SignerError::ShortControlledKey => {
            PyValueError::new_err("controlled integrity signing key must contain at least 16 bytes")
        }
        SignerError::InvalidKeyId => PyValueError::new_err("invalid key id"),
        SignerError::RejectedInput => PyTypeError::new_err("type_error"),
    }
}

fn canonicalize_error(py: Python<'_>, err: Error) -> PyErr {
    let raised = CanonicalizeError::new_err(err.code());
    match raised.value(py).setattr("code", err.code()) {
        Ok(()) => raised,
        Err(set_err) => set_err,
    }
}

#[pymodule]
fn agent_receipts(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(canonical_json, module)?)?;
    module.add_function(wrap_pyfunction!(stable_hash, module)?)?;
    module.add_function(wrap_pyfunction!(verify_audit_receipt, module)?)?;
    module.add_function(wrap_pyfunction!(resign_audit_receipt, module)?)?;
    module.add_function(wrap_pyfunction!(verify_controlled_integrity, module)?)?;
    module.add_function(wrap_pyfunction!(sign_controlled_integrity, module)?)?;
    module.add_function(wrap_pyfunction!(audit_signing_key, module)?)?;
    module.add_function(wrap_pyfunction!(controlled_signing_key, module)?)?;
    module.add_function(wrap_pyfunction!(compare_authority_contracts, module)?)?;
    module.add_function(wrap_pyfunction!(normalize_authority_policy, module)?)?;
    module.add_function(wrap_pyfunction!(normalize_https_authority_rules, module)?)?;
    module.add_function(wrap_pyfunction!(is_https_authority_subset, module)?)?;
    module.add("AUDIT_RECEIPT_VERSION", AUDIT_RECEIPT_VERSION)?;
    module.add("AUDIT_RECEIPT_V2_VERSION", AUDIT_RECEIPT_V2_VERSION)?;
    module.add("CONTROLLED_INTEGRITY_VERSION", CONTROLLED_INTEGRITY_VERSION)?;
    module.add(
        "CanonicalizeError",
        module.py().get_type::<CanonicalizeError>(),
    )?;
    Ok(())
}
