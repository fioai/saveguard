//! Compiles `tests/c/smoke.c` against the shared library and runs it.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn the_c_api_works_from_c() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipped: no C compiler");
        return;
    }
    // `cargo test` doesn't build a cdylib, so build it here, in a target directory of its own so
    // as not to wait on the one this test is running from.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("capi");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let built = Command::new(cargo)
        .args(["build", "--quiet", "--manifest-path"])
        .arg(crate_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .unwrap();
    assert!(built.success(), "building the library failed");
    let lib_dir = target_dir.join("debug");

    let scratch = std::env::temp_dir().join(format!("saveguard-c-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir(&scratch).unwrap();
    let smoke = scratch.join("smoke");
    let compiled = Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(crate_dir.join("include"))
        .arg(crate_dir.join("tests/c/smoke.c"))
        .arg("-L")
        .arg(&lib_dir)
        .arg("-lsaveguard")
        .arg(format!("-Wl,-rpath,{}", lib_dir.display()))
        .arg("-o")
        .arg(&smoke)
        .status()
        .unwrap();
    assert!(compiled.success(), "smoke.c didn't compile");

    let files = scratch.join("files");
    fs::create_dir(&files).unwrap();
    let out = Command::new(&smoke).arg(&files).output().unwrap();
    let _ = fs::remove_dir_all(&scratch);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ok\n");
}
