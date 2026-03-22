use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[pyfunction]
pub fn save_sig_keys(
    output_dir: &str,
    params_bin: &[u8],
    shares_bin: Vec<Vec<u8>>,
) -> PyResult<()> {
    let path = Path::new(output_dir);
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|e| PyValueError::new_err(format!("Failed to create directory: {}", e)))?;
    }

    fs::write(path.join("sPK_native.key"), params_bin)
        .map_err(|e| PyValueError::new_err(format!("Failed to write sPK_native.key: {}", e)))?;

    for (i, share_bin) in shares_bin.iter().enumerate() {
        fs::write(path.join(format!("sSK_native-{}.key", i)), share_bin).map_err(|e| {
            PyValueError::new_err(format!("Failed to write sSK_native-{}.key: {}", i, e))
        })?;
    }

    Ok(())
}

#[pyfunction]
pub fn save_pke_keys(
    output_dir: &str,
    params_bin: &[u8],
    mpk_bin: &[u8],
    shares_bin: Vec<Vec<u8>>,
) -> PyResult<()> {
    let path = Path::new(output_dir);
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|e| PyValueError::new_err(format!("Failed to create directory: {}", e)))?;
    }

    fs::write(path.join("ePK_native_params.key"), params_bin).map_err(|e| {
        PyValueError::new_err(format!("Failed to write ePK_native_params.key: {}", e))
    })?;

    fs::write(path.join("ePK_native_mpk.key"), mpk_bin)
        .map_err(|e| PyValueError::new_err(format!("Failed to write ePK_native_mpk.key: {}", e)))?;

    for (i, share_bin) in shares_bin.iter().enumerate() {
        fs::write(path.join(format!("eSK_native-{}.key", i)), share_bin).map_err(|e| {
            PyValueError::new_err(format!("Failed to write eSK_native-{}.key: {}", i, e))
        })?;
    }

    Ok(())
}

#[pyfunction]
pub fn load_sig_keys(key_dir: &str) -> PyResult<(Vec<u8>, Vec<Vec<u8>>)> {
    let path = Path::new(key_dir);

    // Load params
    let params_path = path.join("sPK_native.key");
    let params_bin = fs::read(&params_path)
        .map_err(|e| PyValueError::new_err(format!("Failed to read sPK_native.key: {}", e)))?;

    // Load shares - discover number of shares by scanning directory
    let mut shares_bin = Vec::new();
    let mut i = 0;
    loop {
        let share_path = path.join(format!("sSK_native-{}.key", i));
        if share_path.exists() {
            let share_data = fs::read(&share_path).map_err(|e| {
                PyValueError::new_err(format!("Failed to read sSK_native-{}.key: {}", i, e))
            })?;
            shares_bin.push(share_data);
            i += 1;
        } else {
            break;
        }
    }

    if shares_bin.is_empty() {
        return Err(PyValueError::new_err(
            "No signature shares found in the key directory",
        ));
    }

    Ok((params_bin, shares_bin))
}

#[pyfunction]
pub fn load_pke_keys(key_dir: &str) -> PyResult<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let path = Path::new(key_dir);

    // Load params
    let params_path = path.join("ePK_native_params.key");
    let params_bin = fs::read(&params_path).map_err(|e| {
        PyValueError::new_err(format!("Failed to read ePK_native_params.key: {}", e))
    })?;

    // Load mpk
    let mpk_path = path.join("ePK_native_mpk.key");
    let mpk_bin = fs::read(&mpk_path)
        .map_err(|e| PyValueError::new_err(format!("Failed to read ePK_native_mpk.key: {}", e)))?;

    // Load shares - discover number of shares by scanning directory
    let mut shares_bin = Vec::new();
    let mut i = 0;
    loop {
        let share_path = path.join(format!("eSK_native-{}.key", i));
        if share_path.exists() {
            let share_data = fs::read(&share_path).map_err(|e| {
                PyValueError::new_err(format!("Failed to read eSK_native-{}.key: {}", i, e))
            })?;
            shares_bin.push(share_data);
            i += 1;
        } else {
            break;
        }
    }

    if shares_bin.is_empty() {
        return Err(PyValueError::new_err(
            "No encryption shares found in the key directory",
        ));
    }

    Ok((params_bin, mpk_bin, shares_bin))
}
