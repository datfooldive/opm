# OPM

Simple Linux AppImage manager written in Odin.

## Requirements

- Linux
- [Odin](https://odin-lang.org/) and Make (to build)
- `bubblewrap` (`bwrap`)

## Build

```sh
make
```

For a CPU-specific build:

```sh
make native
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

Metadata extraction runs inside a Bubblewrap sandbox; AppImage payload is not launched normally.
