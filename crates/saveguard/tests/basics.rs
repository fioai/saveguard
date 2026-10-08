//! What a save does on any platform.

mod common;

use std::fs;
use std::io::Write;
use std::sync::Arc;
use std::thread;

use common::{leftovers, read, TempDir};
use saveguard::{Durability, Error, Lost, Method, Options, Reason, Strategy, Version};

#[test]
fn a_missing_file_is_created() {
    let dir = TempDir::new();
    let path = dir.join("new.txt");
    let report = saveguard::save(&path, "hello").unwrap();
    assert_eq!(report.method, Method::Created);
    assert_eq!(report.path, path);
    assert!(report.reasons.is_empty() && report.lost.is_empty());
    assert_eq!(read(&path), "hello");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn an_ordinary_file_is_replaced() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old contents").unwrap();
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert!(report.reasons.is_empty() && report.lost.is_empty());
    assert_eq!(read(&path), "new");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn an_empty_save_empties_the_file() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "something").unwrap();
    saveguard::save(&path, "").unwrap();
    assert_eq!(read(&path), "");
    Options::new()
        .strategy(Strategy::Overwrite)
        .save(&path, "")
        .unwrap();
    assert_eq!(read(&path), "");
}

#[test]
fn overwriting_shrinks_and_grows_the_file() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "a long first version").unwrap();
    let mut opts = Options::new();
    opts.strategy(Strategy::Overwrite);
    let report = opts.save(&path, "short").unwrap();
    assert_eq!(report.method, Method::Overwrote);
    assert_eq!(report.reasons, vec![Reason::Requested]);
    assert_eq!(read(&path), "short");
    opts.save(&path, "a much, much longer second version")
        .unwrap();
    assert_eq!(read(&path), "a much, much longer second version");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn a_directory_is_not_a_file() {
    let dir = TempDir::new();
    let err = saveguard::save(dir.path(), "x").unwrap_err();
    assert!(matches!(err, Error::NotAFile { .. }), "{err}");
}

#[test]
fn a_missing_directory_is_an_io_error() {
    let dir = TempDir::new();
    let path = dir.join("no/such/dir/file.txt");
    let err = saveguard::save(&path, "x").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
}

#[test]
fn a_writer_takes_the_contents_in_pieces() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    let mut w = Options::new().open(&path).unwrap();
    assert_eq!(w.path(), path);
    assert_eq!(w.method(), Method::Replaced);
    for piece in ["one ", "two ", "three"] {
        w.write_all(piece.as_bytes()).unwrap();
    }
    assert_eq!(read(&path), "old", "nothing happens before commit");
    let report = w.commit().unwrap();
    assert_eq!(read(&path), "one two three");
    assert_eq!(report.version.size(), Some(13));
}

#[test]
fn a_dropped_writer_leaves_the_file_alone() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    let mut w = Options::new().open(&path).unwrap();
    w.write_all(b"never saved").unwrap();
    drop(w);
    assert_eq!(read(&path), "old");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn abort_deletes_what_was_written() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let mut w = Options::new().open(&path).unwrap();
    w.write_all(b"never saved").unwrap();
    w.abort().unwrap();
    assert!(!path.exists());
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn a_change_since_reading_is_a_conflict() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "mine").unwrap();
    let (_, version) = saveguard::read(&path).unwrap();
    fs::write(&path, "theirs, longer").unwrap();
    let err = Options::new()
        .unchanged_since(&version)
        .save(&path, "my edit")
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
    assert_eq!(read(&path), "theirs, longer");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn a_change_of_the_same_size_and_time_is_still_a_conflict() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "aaaa").unwrap();
    let (_, version) = saveguard::read(&path).unwrap();
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    // As if another program wrote within the same tick of the file system's clock.
    fs::write(&path, "bbbb").unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let err = Options::new()
        .unchanged_since(&version)
        .save(&path, "mine")
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
}

#[test]
fn rewriting_the_same_contents_is_not_a_conflict() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "same").unwrap();
    let (_, version) = saveguard::read(&path).unwrap();
    // Another program saves the same bytes as a new file.
    let other = dir.join("other");
    fs::write(&other, "same").unwrap();
    fs::rename(&other, &path).unwrap();
    Options::new()
        .unchanged_since(&version)
        .save(&path, "mine")
        .unwrap();
    assert_eq!(read(&path), "mine");
}

#[test]
fn a_metadata_version_notices_a_change() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "one").unwrap();
    let version = Version::of(&path).unwrap();
    assert!(version.exists());
    fs::write(&path, "three").unwrap();
    let err = Options::new()
        .unchanged_since(&version)
        .save(&path, "x")
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
}

#[test]
fn a_deleted_file_is_a_conflict() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "one").unwrap();
    let (_, version) = saveguard::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let err = Options::new()
        .unchanged_since(&version)
        .save(&path, "x")
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
    assert!(!path.exists());
}

#[test]
fn an_absent_version_means_the_file_must_still_be_missing() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let version = Version::of(&path).unwrap();
    assert_eq!(version, Version::absent());
    fs::write(&path, "someone else's").unwrap();
    let err = Options::new()
        .unchanged_since(&version)
        .save(&path, "mine")
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
    fs::remove_file(&path).unwrap();
    let report = Options::new()
        .unchanged_since(&version)
        .save(&path, "mine")
        .unwrap();
    assert_eq!(report.method, Method::Created);
}

#[test]
fn create_new_refuses_an_existing_file() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let mut opts = Options::new();
    opts.create_new(true);
    assert_eq!(opts.save(&path, "first").unwrap().method, Method::Created);
    let err = opts.save(&path, "second").unwrap_err();
    assert!(matches!(err, Error::Exists { .. }), "{err}");
    assert_eq!(read(&path), "first");
}

#[test]
fn create_new_fails_if_the_file_appears_while_writing() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let mut w = Options::new().create_new(true).open(&path).unwrap();
    w.write_all(b"mine").unwrap();
    fs::write(&path, "theirs").unwrap();
    let err = w.commit().unwrap_err();
    assert!(matches!(err, Error::Exists { .. }), "{err}");
    assert_eq!(read(&path), "theirs");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn each_reports_version_guards_the_next_save() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let first = saveguard::save(&path, "1").unwrap();
    let second = Options::new()
        .unchanged_since(&first.version)
        .save(&path, "22")
        .unwrap();
    let third = Options::new()
        .strategy(Strategy::Overwrite)
        .unchanged_since(&second.version)
        .save(&path, "333")
        .unwrap();
    fs::write(&path, "4444").unwrap();
    let err = Options::new()
        .unchanged_since(&third.version)
        .save(&path, "x")
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
}

#[test]
fn a_report_reads_well() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "x").unwrap();
    let report = Options::new()
        .strategy(Strategy::Overwrite)
        .save(&path, "y")
        .unwrap();
    assert_eq!(
        report.to_string(),
        format!(
            "overwrote {} in place (overwriting was requested)",
            path.display()
        )
    );
    let plan = Options::new().plan(&path).unwrap();
    assert_eq!(
        plan.to_string(),
        format!("would replace {}", path.display())
    );
}

#[test]
fn a_plan_matches_what_happens() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    for strategy in [Strategy::Auto, Strategy::Replace, Strategy::Overwrite] {
        let _ = fs::remove_file(&path);
        let mut opts = Options::new();
        opts.strategy(strategy);
        let plan = opts.plan(&path).unwrap();
        assert_eq!(plan.method, opts.save(&path, "x").unwrap().method);
        let plan = opts.plan(&path).unwrap();
        let report = opts.save(&path, "y").unwrap();
        assert_eq!((plan.method, plan.reasons), (report.method, report.reasons));
    }
}

/// The point of replacing: other processes see the old contents or the new, whole.
#[test]
fn readers_never_see_a_mixture() {
    let dir = TempDir::new();
    let path = Arc::new(dir.join("a.txt"));
    let a = vec![b'a'; 256 * 1024];
    let b = vec![b'b'; 300 * 1024];
    fs::write(&*path, &a).unwrap();
    let writer = {
        let path = Arc::clone(&path);
        let (a, b) = (a.clone(), b.clone());
        thread::spawn(move || {
            let mut opts = Options::new();
            opts.durability(Durability::None);
            for i in 0..100 {
                let report = opts.save(&*path, if i % 2 == 0 { &b } else { &a }).unwrap();
                assert_eq!(report.method, Method::Replaced);
            }
        })
    };
    let mut reads = 0;
    while !writer.is_finished() {
        let seen = fs::read(&*path).unwrap();
        assert!(
            seen == a || seen == b,
            "a read saw {} bytes, mixed",
            seen.len()
        );
        reads += 1;
    }
    writer.join().unwrap();
    assert!(reads > 0);
}

#[test]
fn concurrent_saves_leave_one_complete_version() {
    let dir = TempDir::new();
    let path = Arc::new(dir.join("a.txt"));
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let path = Arc::clone(&path);
            thread::spawn(move || {
                let mut opts = Options::new();
                opts.durability(Durability::None);
                // Every save that didn't simply replace, and why: the evidence when this fails.
                let mut odd = Vec::new();
                for _ in 0..25 {
                    match opts.save(&*path, vec![b'0' + t; 10_000 + usize::from(t)]) {
                        Ok(report) if report.method == Method::Replaced => {}
                        Ok(report) => odd.push(format!("ok: {report}")),
                        Err(e) => odd.push(format!("error: {e} ({e:?})")),
                    }
                }
                odd
            })
        })
        .collect();
    let odd: Vec<String> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    assert!(
        odd.iter().all(|line| !line.starts_with("error")),
        "{odd:#?}"
    );
    let last = fs::read(&*path).unwrap();
    let t = last[0] - b'0';
    assert_eq!(last, vec![b'0' + t; 10_000 + usize::from(t)]);
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn errors_name_the_file() {
    let dir = TempDir::new();
    let err = saveguard::save(dir.path(), "x").unwrap_err();
    assert_eq!(err.path(), dir.path());
    assert_eq!(
        err.to_string(),
        format!("{} is not a regular file", dir.path().display())
    );
    let io: std::io::Error = err.into();
    assert_eq!(io.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn forced_replace_says_what_it_lost() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let other = dir.join("b.txt");
    fs::write(&path, "old").unwrap();
    fs::hard_link(&path, &other).unwrap();
    let report = Options::new()
        .strategy(Strategy::Replace)
        .save(&path, "new")
        .unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_eq!(report.lost, vec![Lost::HardLinks(2)]);
    assert_eq!(read(&path), "new");
    assert_eq!(read(&other), "old", "the other name kept the old file");
}

#[test]
fn hard_links_are_kept_by_overwriting() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    let other = dir.join("b.txt");
    fs::write(&path, "old").unwrap();
    fs::hard_link(&path, &other).unwrap();
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Overwrote);
    assert_eq!(report.reasons, vec![Reason::HardLinks(2)]);
    assert!(report.lost.is_empty());
    assert_eq!(read(&other), "new");
    assert!(leftovers(dir.path()).is_empty());
}

/// Where a file's creation time can be set (macOS, Windows), a replacement keeps it.
#[cfg(any(windows, target_os = "macos"))]
#[test]
fn a_replacement_keeps_the_creation_time() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    let created = fs::metadata(&path).unwrap().created().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced, "{report}");
    assert_eq!(fs::metadata(&path).unwrap().created().unwrap(), created);
}

/// Replacing while others replace the same file loses nothing and fails nothing. On Windows this
/// once lost the ACL: the original read through a handle to a file another save had just deleted.
#[test]
fn concurrent_replaces_lose_nothing() {
    let dir = TempDir::new();
    let path = Arc::new(dir.join("a.txt"));
    fs::write(&*path, "start").unwrap();
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let path = Arc::clone(&path);
            thread::spawn(move || {
                let mut opts = Options::new();
                opts.durability(Durability::None)
                    .strategy(Strategy::Replace);
                let mut odd = Vec::new();
                for _ in 0..25 {
                    match opts.save(&*path, vec![b'0' + t; 10_000]) {
                        Ok(report) if report.lost.is_empty() => {}
                        Ok(report) => odd.push(format!("lost: {report} {:?}", report.lost)),
                        Err(e) => odd.push(format!("error: {e} ({e:?})")),
                    }
                }
                odd
            })
        })
        .collect();
    let odd: Vec<String> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    assert!(odd.is_empty(), "{odd:#?}");
}
