mod archive;
mod bindings;
mod crypto;
pub mod hb;
use pyo3::prelude::*;

#[pymodule]
fn honey_native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    bindings::register_all(m)
}
