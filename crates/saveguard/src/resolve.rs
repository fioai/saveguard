use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{sys, Error, Result};

/// Linux gives up after 40 links too.
const MAX_HOPS: usize = 40;

/// The file a save writes to, and the directory it's in.
pub(crate) struct Target {
    pub file: PathBuf,
    pub dir: PathBuf,
}

/// Follows `path` through every symlink to the file it finally names, which may not exist yet.
///
/// Every hop is followed, not just the first: when a link points at another link, the file to
/// write, and the directory where its replacement must be made, are at the end of the chain. A
/// writer that stops after one hop puts its temporary file next to the middle link, which may be
/// somewhere read-only (a Nix store) or may get the middle link replaced by a plain file.
///
/// Following links by hand skips the kernel's own check on links in shared directories like
/// `/tmp`, so each hop is checked here instead ([`sys::trusted`]).
pub(crate) fn resolve(path: &Path, follow: bool) -> Result<Target> {
    let mut file = path.to_path_buf();
    if follow {
        let mut hops = 0;
        loop {
            match fs::symlink_metadata(&file) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    hops += 1;
                    if hops > MAX_HOPS {
                        return Err(Error::SymlinkLoop { path: path.into() });
                    }
                    if !sys::trusted(&file, &meta) {
                        return Err(Error::Untrusted { path: file });
                    }
                    let link = fs::read_link(&file)
                        .map_err(|e| Error::io("read the symlink", &file, e))?;
                    file = match file.parent() {
                        Some(dir) if link.is_relative() => dir.join(link),
                        _ => link,
                    };
                }
                Ok(_) => break,
                // A link to a file that doesn't exist yet: saving creates it.
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(e) => return Err(Error::io("inspect", &file, e)),
            }
        }
    }
    let dir = match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok(Target { file, dir })
}
