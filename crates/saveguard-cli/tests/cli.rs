//! The command line tool, and through it the situations that need a mount namespace to set up:
//! a file bind-mounted the way Docker does it, and a disk that fills up.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_saveguard");

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "saveguard-cli-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn saveguard(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The tool may finish (say, with an error) before reading its input.
    if let Err(e) = child.stdin.take().unwrap().write_all(input) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn write_saves_standard_input() {
    let dir = TempDir::new();
    let path = dir.0.join("a.txt");
    let out = saveguard(&["write", path.to_str().unwrap()], b"hello\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(fs::read_to_string(&path).unwrap(), "hello\n");
    assert_eq!(
        text(&out.stderr),
        format!("saveguard: created {}\n", path.display())
    );
    let out = saveguard(&["write", "-q", path.to_str().unwrap()], b"again\n");
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    assert_eq!(fs::read_to_string(&path).unwrap(), "again\n");
}

/// Like `sponge`: `sort FILE | saveguard write FILE` must not truncate FILE before it is read.
#[test]
fn the_input_can_be_the_file_itself() {
    let dir = TempDir::new();
    let path = dir.0.join("a.txt");
    fs::write(&path, "b\na\n").unwrap();
    let out = Command::new(BIN)
        .args(["write", path.to_str().unwrap()])
        .stdin(fs::File::open(&path).unwrap())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(fs::read_to_string(&path).unwrap(), "b\na\n");
}

#[test]
fn plan_says_what_write_would_do() {
    let dir = TempDir::new();
    let path = dir.0.join("a.txt");
    fs::write(&path, "x").unwrap();
    fs::hard_link(&path, dir.0.join("b.txt")).unwrap();
    let out = saveguard(&["plan", path.to_str().unwrap()], b"");
    assert!(out.status.success());
    assert_eq!(
        text(&out.stdout),
        format!(
            "would overwrite {} in place (the file has 2 hard links)\n",
            path.display()
        )
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "x");
}

#[test]
fn bad_usage_exits_with_2() {
    for args in [
        &["frob"][..],
        &["write"],
        &["write", "--strategy", "fast", "x"],
        &["write", "a", "b"],
    ] {
        let out = saveguard(args, b"");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn failures_exit_with_1_and_say_why() {
    let dir = TempDir::new();
    let path = dir.0.join("a.txt");
    fs::write(&path, "x").unwrap();
    let out = saveguard(&["write", "--new", path.to_str().unwrap()], b"y");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        format!("saveguard: {} already exists\n", path.display())
    );
}

/// Runs a shell script as root in new user and mount namespaces, or returns `None` where the
/// system doesn't allow that (some distributions and CI runners turn it off).
#[cfg(target_os = "linux")]
fn in_namespace(dir: &std::path::Path, script: &str) -> Option<Output> {
    in_namespace_with(&["-rm"], dir, script)
}

/// The same with other `unshare` options, such as `--map-auto` for more users than one.
#[cfg(target_os = "linux")]
fn in_namespace_with(options: &[&str], dir: &std::path::Path, script: &str) -> Option<Output> {
    let works = Command::new("unshare")
        .args(options)
        .arg("true")
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !works {
        eprintln!(
            "skipped: `unshare {}` isn't available here",
            options.join(" ")
        );
        return None;
    }
    let out = Command::new("unshare")
        .args(options)
        .args(["sh", "-c", script])
        .env("BIN", BIN)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "script failed\nstdout:\n{}\nstderr:\n{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    Some(out)
}

/// `sed -i` in a Docker container on a bind-mounted file fails with "Device or resource busy",
/// because it renames a new file over a mount point.
#[cfg(target_os = "linux")]
#[test]
fn a_bind_mounted_file_is_overwritten_in_place() {
    let dir = TempDir::new();
    let script = r#"
        set -e
        printf 'old\n' > host
        : > mounted
        mount --bind host mounted
        printf 'x\n' > tmp
        if mv tmp mounted 2>/dev/null; then echo 'mv: replaced'; else echo 'mv: refused'; fi
        if "$BIN" write -q --strategy replace mounted </dev/null 2>/dev/null; then
            echo 'replace: replaced'
        else
            echo 'replace: refused'
        fi
        printf 'new\n' | "$BIN" write mounted
        cat host
    "#;
    let Some(out) = in_namespace(&dir.0, script) else {
        return;
    };
    assert_eq!(
        text(&out.stdout),
        "mv: refused\nreplace: refused\nnew\n",
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("overwrote mounted in place (the file is a mount point)"),
        "{}",
        text(&out.stderr)
    );
}

/// When the disk is full, the file must be left as it was, whichever way it would have been saved.
#[cfg(target_os = "linux")]
#[test]
fn a_full_disk_leaves_the_file_as_it_was() {
    let dir = TempDir::new();
    // 64 KiB of space. `plain` would be replaced and `linked` overwritten in place; the first
    // write can't even be staged. The second can (8 KiB + 40 KiB), but growing `linked` to
    // 40 KiB in place wouldn't fit, which must be found before `linked` is touched.
    let script = r#"
        set -e
        mkdir small
        mount -t tmpfs -o size=64k tmpfs small
        head -c 8192 /dev/urandom > small/plain
        cp small/plain small/linked
        ln small/linked small/other-name
        cp small/plain before
        if head -c 300000 /dev/zero | "$BIN" write -q small/plain 2>/dev/null; then echo 'plain: saved'; else echo 'plain: refused'; fi
        if head -c 40960 /dev/zero | "$BIN" write -q small/linked 2>err; then echo 'linked: saved'; else echo 'linked: refused'; fi
        cmp -s before small/plain && echo 'plain: unchanged'
        cmp -s before small/linked && echo 'linked: unchanged'
        ls -A small
        cat err >&2
    "#;
    let Some(out) = in_namespace(&dir.0, script) else {
        return;
    };
    assert_eq!(
        text(&out.stdout),
        "plain: refused\nlinked: refused\nplain: unchanged\nlinked: unchanged\nlinked\nother-name\nplain\n",
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("No space left on device"),
        "{}",
        text(&out.stderr)
    );
}

/// In a directory like /tmp, another user can leave a symlink pointing at one of your files and
/// wait for you to save through it. The kernel refuses to follow such a link
/// (`fs.protected_symlinks`), and since saveguard follows links itself, it must refuse too; the
/// same goes for writing to a file another user left there (`fs.protected_regular`).
#[cfg(target_os = "linux")]
#[test]
fn a_link_planted_in_a_shared_directory_is_not_followed() {
    let dir = TempDir::new();
    let script = r#"
        set -e
        # A namespace where only root is mapped (no /etc/subuid range) has no second user.
        touch probe
        if ! chown 1:1 probe 2>/dev/null; then echo 'no second user'; exit 0; fi
        rm probe
        mkdir shared victim
        chmod 1777 shared
        printf 'precious\n' > victim/precious.txt
        ln -s "$PWD/victim/precious.txt" shared/report.txt
        ln -s "$PWD/victim/planted.txt" shared/new.txt
        printf 'theirs\n' > shared/theirs.txt
        chmod 666 shared/theirs.txt
        chown -h 1:1 shared/report.txt shared/new.txt shared/theirs.txt
        if printf 'clobbered\n' | "$BIN" write shared/report.txt 2>>err; then echo 'link: followed'; else echo 'link: refused'; fi
        if printf 'planted\n' | "$BIN" write --new shared/new.txt 2>>err; then echo 'new: created'; else echo 'new: refused'; fi
        if printf 'mine\n' | "$BIN" write shared/theirs.txt 2>>err; then echo 'file: written'; else echo 'file: refused'; fi
        cat victim/precious.txt shared/theirs.txt
        ls victim
        cat err >&2
    "#;
    let Some(out) = in_namespace_with(&["--map-auto", "--map-root-user"], &dir.0, script) else {
        return;
    };
    if text(&out.stdout) == "no second user\n" {
        eprintln!("skipped: the user namespace has no second user to plant the link");
        return;
    }
    assert_eq!(
        text(&out.stdout),
        "link: refused\nnew: refused\nfile: refused\nprecious\ntheirs\nprecious.txt\n",
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr)
            .contains("is in a sticky, world-writable directory and belongs to another user"),
        "{}",
        text(&out.stderr)
    );
}
