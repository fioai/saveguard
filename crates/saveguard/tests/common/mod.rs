#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

/// A directory under the system's temporary directory, removed (permissions and all) on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "saveguard-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.0.join(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        make_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Tests make directories read-only; undo that so the tree can be removed.
#[cfg(unix)]
fn make_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                make_writable(&entry.path());
            }
        }
    }
}

/// Staged files left behind in `dir`.
pub fn leftovers(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".saveguard-"))
        .collect()
}

/// For tests that look at what's left in the system's temporary directory, where saves stage
/// their contents when the target's own directory is read-only.
pub fn temp_dir_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

/// Whether a command ran and succeeded; false if it isn't installed.
pub fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

pub fn skip(why: &str) {
    eprintln!("skipped: {why}");
}

#[cfg(unix)]
pub mod unix {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    pub fn ino(path: &Path) -> u64 {
        fs::metadata(path).unwrap().ino()
    }

    pub fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    pub fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    pub fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    pub fn cpath(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    /// The process's umask, without changing it (Linux 4.7 and later).
    pub fn umask() -> Option<u32> {
        let status = fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("Umask:"))?;
        u32::from_str_radix(line.split_whitespace().nth(1)?, 8).ok()
    }

    /// A group this process is in other than its own, to give a file.
    pub fn other_group() -> Option<u32> {
        let mut groups = vec![0 as libc::gid_t; 64];
        let n = unsafe { libc::getgroups(64, groups.as_mut_ptr()) };
        let own = unsafe { libc::getegid() };
        groups[..n.max(0) as usize]
            .iter()
            .copied()
            .find(|&g| g != own)
    }

    pub fn chgrp(path: &Path, gid: u32) {
        let r = unsafe { libc::chown(cpath(path).as_ptr(), libc::uid_t::MAX, gid) };
        assert_eq!(r, 0, "chgrp: {}", std::io::Error::last_os_error());
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    use super::unix::cpath;

    pub fn set_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
        let name = std::ffi::CString::new(name).unwrap();
        let r = unsafe {
            libc::setxattr(
                cpath(path).as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn get_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let name = std::ffi::CString::new(name).unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let n = unsafe {
            libc::getxattr(
                cpath(path).as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    pub const FS_NODUMP_FL: libc::c_int = 0x40;

    pub fn flags(path: &Path) -> io::Result<libc::c_int> {
        let file = File::open(path)?;
        let mut flags: libc::c_int = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } == 0 {
            Ok(flags)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn set_flags(path: &Path, flags: libc::c_int) -> io::Result<()> {
        let file = File::open(path)?;
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
