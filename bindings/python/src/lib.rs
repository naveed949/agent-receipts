use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use receipts::canonicalize_bytes as canonicalize;

pyo3::create_exception!(agent_receipts, CanonicalizeError, PyException);

#[pyfunction(name = "canonicalize_bytes")]
fn canonicalize_bytes_py(input: &Bound<'_, PyBytes>) -> PyResult<Py<PyBytes>> {
    let py = input.py();
    match canonicalize(input.as_bytes()) {
        Ok(output) => Ok(PyBytes::new(py, &output).unbind()),
        Err(err) => Err(canonicalize_error(py, err)),
    }
}

fn canonicalize_error(py: Python<'_>, err: receipts::Error) -> PyErr {
    let raised = CanonicalizeError::new_err(err.code());
    match raised.value(py).setattr("code", err.code()) {
        Ok(()) => raised,
        Err(set_err) => set_err,
    }
}

#[pymodule]
fn agent_receipts(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(canonicalize_bytes_py, module)?)?;
    module.add(
        "CanonicalizeError",
        module.py().get_type::<CanonicalizeError>(),
    )?;
    Ok(())
}
