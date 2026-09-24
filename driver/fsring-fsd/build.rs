//! Build script for `fsring-fsd`.
//!
//! Compiles the sole C4 SEH shim with the same WDK configuration used for the
//! Rust image, then emits the kernel link flags and optional named link map.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

const LINK_MAP_ENV: &str = "FSRING_LINK_MAP_PATH";

fn link_map_path(value: Option<OsString>) -> Result<Option<PathBuf>, std::io::Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.into_string().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FSRING_LINK_MAP_PATH must be valid Unicode",
        )
    })?;
    if value.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FSRING_LINK_MAP_PATH must not be empty",
        ));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FSRING_LINK_MAP_PATH must be absolute",
        ));
    }
    Ok(Some(path))
}

fn compile_seh_shim(config: &wdk_build::Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut build = cc::Build::new();
    for include_path in config.include_paths()? {
        build.include(include_path);
    }
    for (name, value) in config.preprocessor_definitions() {
        build.define(&name, value.as_deref());
    }
    build
        .file(Path::new("native/c4_seh.c"))
        .flag("/kernel")
        .flag("/Zl")
        .flag("/GS-")
        .flag("/W4")
        .flag("/WX")
        // WDK 10.0.26100's own configuration defines `_KERNEL_MODE`; MSVC
        // 14.44 reports C4117 because that reserved spelling arrives on the
        // command line. Keep /W4 + /WX and suppress only that proven kit
        // compatibility warning.
        .flag("/wd4117")
        .compile("fsring_c4_seh");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=native/c4_seh.c");
    println!("cargo::rerun-if-env-changed={LINK_MAP_ENV}");
    println!("cargo::rerun-if-env-changed=WDKContentRoot");
    println!("cargo::rerun-if-env-changed=MicrosoftKitRoot");
    println!("cargo::rerun-if-env-changed=WDKKitVersion");
    println!("cargo::rerun-if-env-changed=Version_Number");

    let map_path = link_map_path(std::env::var_os(LINK_MAP_ENV))?;
    let config = wdk_build::Config::from_env_auto()?;
    compile_seh_shim(&config)?;

    // `fsring-sys` owns the extra `#[link(name = "wdmsec")]` declaration for
    // the control-device DDI. This binary configuration still supplies the WDK
    // `km` library search path; it must not duplicate that binding boundary.
    config.configure_binary_build()?;

    // wdk-build emits a bare /MAP. This named argument deliberately follows it
    // so MSVC's last map-path option wins without requiring the output to exist.
    if let Some(path) = map_path {
        println!("cargo::rustc-cdylib-link-arg=/MAP:{}", path.display());
        println!("cargo::rustc-cdylib-link-arg=/MAPINFO:EXPORTS");
    }
    Ok(())
}
