# OPM

Simple Linux AppImage manager written in Rust.

## Requirements

- Linux
- [Rust](https://www.rust-lang.org/) 1.88+ (to build)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/datfooldive/opm/main/install.sh | sh
```

Installs latest x86_64 Linux release to `~/.local/bin/opm`. Set `OPM_INSTALL_DIR` to use another directory.

## Build

```sh
cargo build --release   # binary at target/release/opm
```

Or with Make, which copies the binary to `./opm`:

```sh
make          # release build
make native   # CPU-specific build
```

## Usage

```text
opm install <file>   Install an AppImage
opm uninstall <id>  Remove an installed AppImage and its managed files
opm list            List installed AppImages
opm info <file>     Print AppImage metadata as JSON
opm help            Show help
```

Example:

```sh
./opm install /path/to/MyApp.AppImage
./opm list
./opm uninstall MyApp
```

Metadata is read directly from the AppImage's embedded squashfs image, so nothing inside the AppImage is ever executed. Only type 2 AppImages are supported.
