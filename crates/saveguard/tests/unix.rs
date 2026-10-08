//! Symlinks, permissions, ownership and read-only directories.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;

use common::unix::{chgrp, ino, is_root, mode, other_group, set_mode, umask};
use common::{leftovers, read, skip, temp_dir_lock, TempDir};
use saveguard::{Durability, Error, Lost, Method, Options, Reason, Strategy};

#[test]
fn a_replacement_keeps_the_permissions() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    for m in [0o600, 0o640, 0o755, 0o604] {
        set_mode(&path, m);
        let report = saveguard::save(&path, "new").unwrap();
        assert_eq!(report.method, Method::Replaced);
        assert_eq!(mode(&path), m);
    }
}

#[test]
fn a_replacement_keeps_the_group() {
    let Some(group) = other_group() else {
        return skip("this user is in no second group");
    };
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    chgrp(&path, group);
    let before = ino(&path);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_ne!(ino(&path), before);
    use std::os::unix::fs::MetadataExt;
    assert_eq!(fs::metadata(&path).unwrap().gid(), group);
}

#[test]
fn a_new_file_gets_the_mode_asked_for_less_the_umask() {
    let Some(umask) = umask() else {
        return skip("can't read the umask");
    };
    let dir = TempDir::new();
    let path = dir.join("new.txt");
    Options::new().mode(0o664).save(&path, "x").unwrap();
    assert_eq!(mode(&path), 0o664 & !umask);
    let path = dir.join("default.txt");
    saveguard::save(&path, "x").unwrap();
    assert_eq!(mode(&path), 0o666 & !umask);
}

#[test]
fn setuid_is_cleared_as_the_kernel_would() {
    let dir = TempDir::new();
    let path = dir.join("tool");
    fs::write(&path, "old").unwrap();
    set_mode(&path, 0o4755);
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_eq!(report.lost, vec![Lost::SetId]);
    assert_eq!(mode(&path), 0o755);
    // Writing in place is cleared by the kernel itself, and reported the same way.
    set_mode(&path, 0o4755);
    let report = Options::new()
        .strategy(Strategy::Overwrite)
        .save(&path, "newer")
        .unwrap();
    assert_eq!(report.lost, vec![Lost::SetId]);
    assert_eq!(mode(&path), 0o755);
}

#[test]
fn a_symlink_is_followed_and_stays_a_symlink() {
    let dir = TempDir::new();
    let real = dir.join("real.txt");
    let link = dir.join("link.txt");
    fs::write(&real, "old").unwrap();
    symlink("real.txt", &link).unwrap();
    let report = saveguard::save(&link, "new").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_eq!(report.path, dir.join("real.txt"));
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(read(&real), "new");
}

/// anthropics/claude-code#78162: settings.json -> read-only store -> writable file. A writer that
/// stops after one hop puts its temporary file in the read-only directory and fails.
#[test]
fn a_chain_of_symlinks_is_followed_to_the_end() {
    if is_root() {
        return skip("root can write to a read-only directory");
    }
    let dir = TempDir::new();
    fs::create_dir(dir.join("real")).unwrap();
    fs::create_dir(dir.join("store")).unwrap();
    fs::write(dir.join("real/settings.json"), "{}").unwrap();
    symlink("../real/settings.json", dir.join("store/hop")).unwrap();
    symlink("store/hop", dir.join("settings.json")).unwrap();
    set_mode(&dir.join("store"), 0o555);

    let report = saveguard::save(dir.join("settings.json"), "{\"a\": 1}").unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_eq!(read(&dir.join("real/settings.json")), "{\"a\": 1}");
    for link in ["settings.json", "store/hop"] {
        let meta = fs::symlink_metadata(dir.join(link)).unwrap();
        assert!(meta.file_type().is_symlink(), "{link} is still a symlink");
    }
}

#[test]
fn a_dangling_symlink_gets_its_file_created() {
    let dir = TempDir::new();
    let link = dir.join("link.txt");
    symlink("later.txt", &link).unwrap();
    let report = saveguard::save(&link, "made").unwrap();
    assert_eq!(report.method, Method::Created);
    assert_eq!(read(&dir.join("later.txt")), "made");
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn not_following_replaces_the_link_itself() {
    let dir = TempDir::new();
    let real = dir.join("real.txt");
    let link = dir.join("link.txt");
    fs::write(&real, "old").unwrap();
    symlink("real.txt", &link).unwrap();
    let report = Options::new()
        .follow_symlinks(false)
        .save(&link, "new")
        .unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_file());
    assert_eq!(read(&link), "new");
    assert_eq!(read(&real), "old");
}

#[test]
fn a_symlink_loop_is_an_error() {
    let dir = TempDir::new();
    symlink("b", dir.join("a")).unwrap();
    symlink("a", dir.join("b")).unwrap();
    let err = saveguard::save(dir.join("a"), "x").unwrap_err();
    assert!(matches!(err, Error::SymlinkLoop { .. }), "{err}");
}

#[test]
fn hard_links_keep_the_same_file() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    fs::hard_link(&path, dir.join("b.txt")).unwrap();
    let before = ino(&path);
    saveguard::save(&path, "new").unwrap();
    assert_eq!(ino(&path), before);
}

#[test]
fn a_file_in_a_read_only_directory_is_overwritten_in_place() {
    if is_root() {
        return skip("root can write to a read-only directory");
    }
    let _lock = temp_dir_lock();
    let before_tmp = leftovers(&fallback_dir()).len();
    let dir = TempDir::new();
    let sub = dir.join("locked");
    fs::create_dir(&sub).unwrap();
    let path = sub.join("a.txt");
    fs::write(&path, "old").unwrap();
    set_mode(&sub, 0o555);
    let before = ino(&path);

    let plan = Options::new().plan(&path).unwrap();
    let report = saveguard::save(&path, "new").unwrap();
    assert_eq!(report.method, Method::Overwrote);
    assert_eq!(report.reasons, vec![Reason::DirectoryNotWritable]);
    assert_eq!((plan.method, plan.reasons), (report.method, report.reasons));
    assert_eq!(read(&path), "new");
    assert_eq!(ino(&path), before);
    assert_eq!(leftovers(&fallback_dir()).len(), before_tmp);
}

/// Where saves stage when the directory is read-only: somewhere that survives a reboot.
fn fallback_dir() -> std::path::PathBuf {
    let var_tmp = std::path::Path::new("/var/tmp");
    if var_tmp.is_dir() {
        var_tmp.into()
    } else {
        std::env::temp_dir()
    }
}

#[test]
fn replace_fails_in_a_read_only_directory_rather_than_overwrite() {
    if is_root() {
        return skip("root can write to a read-only directory");
    }
    let dir = TempDir::new();
    let sub = dir.join("locked");
    fs::create_dir(&sub).unwrap();
    let path = sub.join("a.txt");
    fs::write(&path, "old").unwrap();
    set_mode(&sub, 0o555);
    let err = Options::new()
        .strategy(Strategy::Replace)
        .save(&path, "new")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert_eq!(read(&path), "old");
}

#[test]
fn a_read_only_file_is_left_alone() {
    if is_root() {
        return skip("root can write a read-only file");
    }
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    set_mode(&path, 0o444);
    let err = saveguard::save(&path, "new").unwrap_err();
    assert!(matches!(err, Error::ReadOnly { .. }), "{err}");
    assert_eq!(read(&path), "old");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn a_write_only_file_is_overwritten() {
    if is_root() {
        return skip("root can read anything");
    }
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    set_mode(&path, 0o200);
    let report = saveguard::save(&path, "new").unwrap();
    // Its extended attributes can't be read to be copied, so a replacement might lose them.
    assert_eq!(report.method, Method::Overwrote, "{report}");
    set_mode(&path, 0o600);
    assert_eq!(read(&path), "new");
}

#[test]
fn a_fifo_is_not_a_file() {
    let dir = TempDir::new();
    let path = dir.join("fifo");
    let c = common::unix::cpath(&path);
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let err = saveguard::save(&path, "x").unwrap_err();
    assert!(matches!(err, Error::NotAFile { .. }), "{err}");
}

#[test]
fn create_new_refuses_a_symlink_even_one_to_nothing() {
    let dir = TempDir::new();
    let link = dir.join("link.txt");
    symlink("elsewhere.txt", &link).unwrap();
    let err = Options::new()
        .create_new(true)
        .save(&link, "x")
        .unwrap_err();
    assert!(matches!(err, Error::Exists { .. }), "{err}");
    assert!(!dir.join("elsewhere.txt").exists());
}

#[test]
fn replacing_a_link_gives_the_mode_of_a_new_file() {
    let Some(umask) = umask() else {
        return skip("can't read the umask");
    };
    let dir = TempDir::new();
    let link = dir.join("link.txt");
    symlink("elsewhere.txt", &link).unwrap();
    Options::new()
        .follow_symlinks(false)
        .mode(0o644)
        .save(&link, "x")
        .unwrap();
    assert_eq!(mode(&link), 0o644 & !umask);
}

/// Two saves overwriting the same file in place must take turns, or the file ends up with the
/// start of one and the end of the other.
#[test]
fn overwrites_in_place_take_turns() {
    let dir = TempDir::new();
    let path = Arc::new(dir.join("a.txt"));
    fs::write(&*path, "old").unwrap();
    fs::hard_link(&*path, dir.join("b.txt")).unwrap();
    // Big enough that the copies overlap, and of different lengths so a mixture can't hide.
    let a = vec![b'a'; 12 << 20];
    let b = vec![b'b'; 9 << 20];
    for _ in 0..12 {
        let start = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [a.clone(), b.clone()]
            .into_iter()
            .map(|contents| {
                let (path, start) = (Arc::clone(&path), Arc::clone(&start));
                thread::spawn(move || {
                    let mut w = Options::new()
                        .durability(Durability::None)
                        .open(&*path)
                        .unwrap();
                    w.write_all(&contents).unwrap();
                    start.wait();
                    assert_eq!(w.commit().unwrap().method, Method::Overwrote);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let now = fs::read(&*path).unwrap();
        assert!(
            now == a || now == b,
            "the file is a mixture of the two saves"
        );
    }
}

/// The overwrite is of the file that was inspected, or nothing: if something else is at the path
/// by the time of the commit (here another program replaced the file; in an attack, a directory on
/// the path became a symlink), it's a conflict.
#[test]
fn a_different_file_at_the_path_is_not_overwritten() {
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    fs::hard_link(&path, dir.join("b.txt")).unwrap();
    let mut w = Options::new().open(&path).unwrap();
    assert_eq!(w.method(), Method::Overwrote);
    w.write_all(b"new").unwrap();
    let other = dir.join("other.txt");
    fs::write(&other, "someone else's").unwrap();
    fs::rename(&other, &path).unwrap();
    let err = w.commit().unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }), "{err}");
    assert_eq!(read(&path), "someone else's");
    assert_eq!(read(&dir.join("b.txt")), "old");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn setgid_is_kept_for_a_writer_in_the_group_unless_group_executable() {
    if is_root() {
        return skip("root keeps setgid either way");
    }
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    set_mode(&path, 0o2644);
    let report = saveguard::save(&path, "new").unwrap();
    assert!(report.lost.is_empty(), "{report}");
    assert_eq!(mode(&path), 0o2644);
    set_mode(&path, 0o2755);
    let report = saveguard::save(&path, "newer").unwrap();
    assert_eq!(report.lost, vec![Lost::SetId]);
    assert_eq!(mode(&path), 0o755);
}

#[test]
fn forced_replace_of_an_unreadable_file_says_what_it_may_have_lost() {
    if is_root() {
        return skip("root can read anything");
    }
    let dir = TempDir::new();
    let path = dir.join("a.txt");
    fs::write(&path, "old").unwrap();
    set_mode(&path, 0o200);
    let report = Options::new()
        .strategy(Strategy::Replace)
        .save(&path, "new")
        .unwrap();
    assert_eq!(report.method, Method::Replaced);
    assert_eq!(report.lost, vec![Lost::UnreadableXattrs]);
}

#[test]
fn our_own_link_in_a_shared_directory_is_followed() {
    let dir = TempDir::new();
    let shared = dir.join("shared");
    fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o1777);
    fs::write(dir.join("real.txt"), "old").unwrap();
    symlink("../real.txt", shared.join("link.txt")).unwrap();
    fs::write(shared.join("own.txt"), "old").unwrap();
    saveguard::save(shared.join("link.txt"), "new").unwrap();
    assert_eq!(read(&dir.join("real.txt")), "new");
    saveguard::save(shared.join("own.txt"), "new").unwrap();
    assert_eq!(read(&shared.join("own.txt")), "new");
}
