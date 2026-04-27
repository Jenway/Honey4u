fn main() {
    pyo3_build_config::use_pyo3_cfgs();

    let interpreter = pyo3_build_config::get();
    if let Some(lib_dir) = &interpreter.lib_dir {
        println!("cargo:rustc-link-search=native={lib_dir}");
    }
    if let Some(lib_name) = &interpreter.lib_name {
        println!("cargo:rustc-link-lib={lib_name}");
    }
}
