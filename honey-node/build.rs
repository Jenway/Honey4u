//! Copies Python DLLs to the output directory so honey-node.exe
//! can find them at runtime without PATH manipulation.
//! On Windows, the executable's own directory is the first DLL search path.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    #[cfg(target_os = "windows")]
    if env::var_os("CARGO_FEATURE_PYTHON_BACKEND").is_some() {
        copy_python_dlls();
    }
}

#[cfg(target_os = "windows")]
fn copy_python_dlls() {
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_owned());
    let out_dir = env::var("OUT_DIR").ok();

    // Walk from OUT_DIR back to target/<profile>/
    // OUT_DIR = target/<profile>/build/<crate>-<hash>/out
    let target_dir = out_dir
        .as_ref()
        .and_then(|d| {
            Path::new(d)
                .parent() // out/
                .and_then(|p| p.parent()) // build/<hash>/
                .and_then(|p| p.parent()) // build/
                .map(|p| p.to_path_buf())
        })
        .unwrap_or_else(|| PathBuf::from("target").join(&profile));

    let python_dir = match find_python_dir() {
        Some(d) => d,
        None => return,
    };

    let dlls: &[&str] = &["python3.dll", "python314.dll"];
    for dll in dlls {
        let src = python_dir.join(dll);
        if src.exists() {
            let dst = target_dir.join(dll);
            if !dst.exists() {
                std::fs::copy(&src, &dst).ok();
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn find_python_dir() -> Option<PathBuf> {
    // 1. PYO3_PYTHON: the exact python executable path
    if let Some(exe) = env::var("PYO3_PYTHON").ok().or_else(|| {
        // pyo3-build-config may have set this during build
        env::var("DEP_PYTHON3_PYTHON_EXECUTABLE").ok()
    }) && let Some(parent) = Path::new(&exe).parent()
    {
        if parent.join("python314.dll").exists() {
            return Some(parent.to_path_buf());
        }
        // uv places python.exe in the base dir, not Scripts/
        if parent
            .parent()
            .map(|p| p.join("python314.dll").exists())
            .unwrap_or(false)
        {
            return Some(parent.parent().unwrap().to_path_buf());
        }
    }

    // 2. VIRTUAL_ENV: walk up to find the uv python base
    if let Ok(venv) = env::var("VIRTUAL_ENV") {
        // The python.exe is typically under <venv>/Scripts/
        // The actual uv python install is referenced by pyvenv.cfg
        let cfg = Path::new(&venv).join("pyvenv.cfg");
        if let Ok(contents) = std::fs::read_to_string(&cfg) {
            for line in contents.lines() {
                if let Some(path) = line.strip_prefix("home = ") {
                    let trim = path.trim();
                    if Path::new(trim).join("python314.dll").exists() {
                        return Some(PathBuf::from(trim));
                    }
                }
            }
        }
    }

    // 3. Scan uv python installations
    if let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        let uv_python = PathBuf::from(home)
            .join("AppData")
            .join("Roaming")
            .join("uv")
            .join("python");
        if let Ok(entries) = std::fs::read_dir(&uv_python) {
            let mut best: Option<PathBuf> = None;
            for e in entries.flatten() {
                if e.metadata().map(|m| m.is_dir()).unwrap_or(false)
                    && e.path().join("python314.dll").exists()
                {
                    // Prefer the one matching our expected Python version
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.contains("cpython-3.14") {
                        return Some(e.path());
                    }
                    if best.is_none() {
                        best = Some(e.path());
                    }
                }
            }
            if best.is_some() {
                return best;
            }
        }
    }

    None
}
