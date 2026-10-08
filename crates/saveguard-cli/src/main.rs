//! `saveguard write FILE` saves standard input to FILE without wrecking it, and
//! `saveguard plan FILE` says how that would go.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use saveguard::{Durability, Options, Strategy};

const USAGE: &str = "\
Usage:
  saveguard write [options] FILE   Save standard input to FILE
  saveguard plan [options] FILE    Say how FILE would be saved, without writing it

FILE is replaced atomically when nothing about it would be lost, and otherwise
overwritten in place (hard links, mount points, an owner or attributes a new
file couldn't have). Symlinks are followed to the file they point to. The input
is read in full before FILE is touched, so `cmd FILE | saveguard write FILE` works.

Options:
  --strategy auto|replace|overwrite   How to put the new contents in place (auto)
  --no-follow     Replace a symlink at FILE instead of the file it points to
  --no-sync       Don't wait for the contents to reach the disk
  --mode OCTAL    Permissions for a file that doesn't exist yet (666, less the umask)
  --new           Fail if FILE already exists
  -q, --quiet     Don't say what was done
  -h, --help      Show this
  -V, --version   Show the version";

enum Command {
    Write,
    Plan,
}

struct Args {
    command: Command,
    file: PathBuf,
    options: Options,
    quiet: bool,
}

enum Parsed {
    Run(Args),
    Exit(ExitCode),
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1).collect()) {
        Ok(Parsed::Run(args)) => run(args),
        Ok(Parsed::Exit(code)) => code,
        Err(message) => {
            eprintln!("saveguard: {message}\nTry 'saveguard --help'.");
            ExitCode::from(2)
        }
    }
}

fn parse(args: Vec<OsString>) -> Result<Parsed, String> {
    let mut command = None;
    let mut file = None;
    let mut options = Options::new();
    let mut quiet = false;
    let mut only_files = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg.to_str().unwrap_or("");
        if only_files || !text.starts_with('-') || text == "-" {
            if command.is_none() {
                command = Some(match text {
                    "write" => Command::Write,
                    "plan" => Command::Plan,
                    _ => return Err(format!("unknown command '{}'", arg.to_string_lossy())),
                });
            } else if file.is_none() {
                file = Some(PathBuf::from(arg));
            } else {
                return Err("give one FILE".into());
            }
            continue;
        }
        match text {
            "--" => only_files = true,
            "-h" | "--help" => {
                println!(
                    "saveguard {}: save files without wrecking them\n\n{USAGE}",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(Parsed::Exit(ExitCode::SUCCESS));
            }
            "-V" | "--version" => {
                println!("saveguard {}", env!("CARGO_PKG_VERSION"));
                return Ok(Parsed::Exit(ExitCode::SUCCESS));
            }
            "-q" | "--quiet" => quiet = true,
            "--no-follow" => {
                options.follow_symlinks(false);
            }
            "--no-sync" => {
                options.durability(Durability::None);
            }
            "--new" => {
                options.create_new(true);
            }
            "--strategy" => {
                let value = args.next().ok_or("--strategy needs a value")?;
                options.strategy(match value.to_str() {
                    Some("auto") => Strategy::Auto,
                    Some("replace") => Strategy::Replace,
                    Some("overwrite") => Strategy::Overwrite,
                    _ => return Err("--strategy is auto, replace or overwrite".into()),
                });
            }
            "--mode" => {
                let value = args.next().ok_or("--mode needs a value")?;
                let mode = value
                    .to_str()
                    .and_then(|v| u32::from_str_radix(v, 8).ok())
                    .filter(|&m| m <= 0o7777)
                    .ok_or("--mode takes octal permissions, like 644")?;
                options.mode(mode);
            }
            _ => return Err(format!("unknown option '{text}'")),
        }
    }
    let command = command.ok_or("give a command: write or plan")?;
    let file = file.ok_or("give a FILE")?;
    Ok(Parsed::Run(Args {
        command,
        file,
        options,
        quiet,
    }))
}

fn run(args: Args) -> ExitCode {
    let result = match args.command {
        Command::Plan => args.options.plan(&args.file).map(|plan| println!("{plan}")),
        Command::Write => write(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("saveguard: {e}");
            ExitCode::FAILURE
        }
    }
}

fn write(args: &Args) -> saveguard::Result<()> {
    let mut writer = args.options.open(&args.file)?;
    if let Err(e) = io::copy(&mut io::stdin().lock(), &mut writer) {
        return Err(saveguard::Error::Io {
            action: "read standard input for",
            path: args.file.clone(),
            source: e,
        });
    }
    let report = writer.commit()?;
    if !args.quiet {
        eprintln!("saveguard: {report}");
    }
    Ok(())
}
