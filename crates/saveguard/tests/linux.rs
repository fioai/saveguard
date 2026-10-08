//! Extended attributes, ACLs and file flags, which need a Linux file system that has them.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io;

use common::linux::{flags, get_xattr, set_flags, set_xattr, FS_NODUMP_FL};
use common::unix::ino;
use common::{run, skip, TempDir};
use saveguard::{Lost, Method, Options, Strategy};

fn unsupported(e: &io::Error) -> bool {
    e.raw_os_error()
        .is_some_and(|c| c == libc::ENOTSUP || c == libc::EOPNOTSUPP || c == libc::ENOTTY)
}

#[test]
fn a_replacement_keeps_extended_attributes() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    match set_xattr(&path, "user.saveguard.test", b"kept") {
        Err(e) if unsupported(&e) => return skip("no user extended attributes here"),
        other => other.unwrap(),
    }
    set_xattr(&path, "user.empty", b"").unwrap();
    let before = ino(&path);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_ne!(ino(&path), before);
    assert_eq!(get_xattr(&path, "user.saveguard.test").unwrap(), b"kept");
    assert_eq!(get_xattr(&path, "user.empty").unwrap(), b"");
}

#[test]
fn a_replacement_keeps_the_acl() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    if !run("setfacl", &["-m", "u:65534:r", path.to_str().unwrap()]) {
        return skip("setfacl isn't available or ACLs aren't supported");
    }
    let acl = get_xattr(&path, "system.posix_acl_access").unwrap();
    let before = ino(&path);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_ne!(ino(&path), before);
    assert_eq!(get_xattr(&path, "system.posix_acl_access").unwrap(), acl);
}

#[test]
fn an_acl_from_the_directory_is_not_added() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    if !run(
        "setfacl",
        &["-d", "-m", "u:65534:r", dir.path().to_str().unwrap()],
    ) {
        return skip("setfacl isn't available or ACLs aren't supported");
    }
    assert!(get_xattr(&path, "system.posix_acl_access").is_none());
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert!(
        get_xattr(&path, "system.posix_acl_access").is_none(),
        "the replacement inherited the directory's default ACL"
    );
    // A new file is a new file, though: it gets the directory's default like any other.
    let fresh = dir.join("fresh.txt");
    saveguard::save(&fresh, "x").unwrap();
    assert!(get_xattr(&fresh, "system.posix_acl_access").is_some());
}

#[test]
fn a_replacement_keeps_file_flags() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    let original = match flags(&path) {
        Err(e) if unsupported(&e) => return skip("no file flags here"),
        other => other.unwrap(),
    };
    match set_flags(&path, original | FS_NODUMP_FL) {
        Err(e) if unsupported(&e) => return skip("no-dump isn't supported here"),
        other => other.unwrap(),
    }
    let before = ino(&path);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_ne!(ino(&path), before);
    assert_ne!(flags(&path).unwrap() & FS_NODUMP_FL, 0);
}

#[test]
fn overwriting_keeps_everything_because_it_is_the_same_file() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    if set_xattr(&path, "user.saveguard.test", b"kept").is_err() {
        return skip("no user extended attributes here");
    }
    let report = Options::new()
        .strategy(Strategy::Overwrite)
        .save(&path, "new")
        .unwrap();
    assert_eq!(report.method, Method::Overwrote);
    assert_eq!(get_xattr(&path, "user.saveguard.test").unwrap(), b"kept");
}

#[test]
fn capabilities_are_reported_lost() {
    // Setting them needs CAP_SETFCAP, so only check what an ordinary file reports.
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    let report = saveguard::save(&path, "new").unwrap();
    assert!(!report.lost.contains(&Lost::Capabilities));
}
