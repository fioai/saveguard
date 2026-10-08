//! Extended attributes, ACLs and flags on macOS (APFS).
#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{read, TempDir};
use saveguard::Method;

fn run(program: &str, args: &[&str], path: &Path) -> String {
    let out = Command::new(program).args(args).arg(path).output().unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_replacement_keeps_extended_attributes() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    run("xattr", &["-w", "org.example.saveguard", "kept"], &path);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    assert_eq!(
        run("xattr", &["-p", "org.example.saveguard"], &path).trim(),
        "kept"
    );
    assert_eq!(read(&path), "new");
}

#[test]
fn a_replacement_keeps_the_acl() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    run("chmod", &["+a", "everyone deny chown"], &path);
    let before = run("ls", &["-le"], &path);
    assert!(before.contains("deny chown"), "{before}");
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    let after = run("ls", &["-le"], &path);
    assert!(after.contains("everyone deny chown"), "{after}");
}

#[test]
fn a_replacement_keeps_the_hidden_flag() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    run("chflags", &["hidden"], &path);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    let after = run("ls", &["-lO"], &path);
    assert!(after.contains("hidden"), "{after}");
}
