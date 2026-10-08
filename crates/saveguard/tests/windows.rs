//! Streams, attributes and ACLs on Windows (NTFS).
#![cfg(windows)]

mod common;

use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use common::{read, TempDir};
use saveguard::{Method, Reason};

const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

fn icacls(path: &Path, args: &[&str]) -> String {
    let out = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "icacls {args:?} failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The Mark of the Web, which says a file came from the internet, is an alternate data stream.
#[test]
fn a_replacement_keeps_alternate_data_streams() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    let stream = dir.join("a.txt:Zone.Identifier");
    fs::write(&stream, "[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    assert_eq!(read(&path), "new");
    assert_eq!(read(&stream), "[ZoneTransfer]\r\nZoneId=3\r\n");
}

#[test]
fn a_replacement_keeps_the_hidden_attribute() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    assert!(Command::new("attrib")
        .arg("+h")
        .arg(&path)
        .status()
        .unwrap()
        .success());
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    let attributes = fs::metadata(&path).unwrap().file_attributes();
    assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);
}

/// A file with an ACL of its own (inheritance turned off) gets a copy of it.
#[test]
fn a_replacement_keeps_a_protected_acl() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    icacls(&path, &["/inheritance:d"]);
    let before = icacls(&path, &[]);
    assert!(!before.contains("(I)"), "{before}");
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    let after = icacls(&path, &[]);
    assert!(
        !after.contains("(I)"),
        "the replacement inherited instead: {after}"
    );
    assert_eq!(read(&path), "new");
}

/// An entry added on top of the inherited ones can't be reproduced on a new file by inheritance,
/// so the file is overwritten in place, which keeps it.
#[test]
fn an_acl_with_entries_of_its_own_is_kept_by_overwriting() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    icacls(&path, &["/grant", "*S-1-1-0:(R)"]);
    let before = icacls(&path, &[]);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Overwrote, "{report}");
    assert!(
        matches!(&report.reasons[..], [Reason::Metadata(m)] if m.contains("access control list")),
        "{report}"
    );
    assert_eq!(icacls(&path, &[]), before);
    assert_eq!(read(&path), "new");
}
