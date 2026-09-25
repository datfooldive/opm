#[cfg(not(target_os = "linux"))]
compile_error!("opm supports Linux only");

mod appimage;
mod elf;
mod manager;
mod squashfs;

use std::process::exit;

const USAGE: &str = "\
OPM — AppImage manager

Usage:
  opm <command> [argument]

Commands:
  install <file>  Install an AppImage
  uninstall <id> Remove installed AppImage and all managed files
  list           Show installed AppImages
  info <file>    Print AppImage metadata as JSON
  help           Show this help

Options:
  -h, --help     Show this help

Examples:
  opm install /path/to/MyApp.AppImage
  opm list
  opm uninstall MyApp

Metadata is read directly from the AppImage's squashfs image; nothing inside it is run.";

fn usage_error() -> ! {
    println!("{USAGE}");
    exit(2)
}

fn report(result: Result<String, String>) {
    match result {
        Ok(message) => println!("{message}"),
        Err(message) => {
            eprintln!("{message}");
            exit(1)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    let (command, argument) = match args.as_slice() {
        [command] => (command.as_str(), None),
        [command, argument] => (command.as_str(), Some(argument.as_str())),
        _ => usage_error(),
    };

    match (command, argument) {
        ("help", None) => println!("{USAGE}"),
        ("list", None) => {
            if let Err(message) = manager::list_installed() {
                eprintln!("{message}");
                exit(1)
            }
        }
        ("install", Some(file)) => report(manager::install_appimage(file)),
        ("uninstall", Some(id)) => report(manager::uninstall_appimage(id)),
        ("info", Some(file)) => {
            if let Err(message) = appimage::print_info(file) {
                eprintln!("{message}");
                exit(1)
            }
        }
        ("help" | "list" | "install" | "uninstall" | "info", _) => usage_error(),
        _ => {
            eprintln!("unknown command: {command}");
            usage_error()
        }
    }
}
