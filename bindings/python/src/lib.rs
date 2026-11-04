use pyo3::exceptions::{PyException, PyOverflowError};
use pyo3::prelude::*;
use pyo3::types::{
    PyBool, PyByteArray, PyBytes, PyDict, PyFloat, PyInt, PyList, PyModule, PyString,
};

use receipts::{Error, Json, Wtf16};

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
    module.add(
        "CanonicalizeError",
        module.py().get_type::<CanonicalizeError>(),
    )?;
    Ok(())
}
