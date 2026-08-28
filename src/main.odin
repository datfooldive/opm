#+build linux
package main

import "core:flags"
import "core:fmt"
import "core:os"

Command :: enum {
	install,
	uninstall,
	list,
	info,
	help,
}

CLI_Options :: struct {
	command:  Command `args:"pos=0,required" usage:"Command to run."`,
	argument: string  `args:"pos=1" usage:"File or installed AppImage ID."`,
}

usage :: proc() {
	fmt.println(
		`OPM — AppImage manager

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

Metadata inspection is sandboxed with bubblewrap; AppImage payload is not launched.`,
	)
}

main :: proc() {
	if len(os.args) == 1 {usage();os.exit(2)}

	options: CLI_Options
	if err := flags.parse(&options, os.args[1:], .Unix); err != nil {
		if _, help := err.(flags.Help_Request); help {usage();return}
		flags.print_errors(CLI_Options, err, os.args[0], .Unix)
		usage()
		os.exit(2)
	}

	argument_required := options.command == .install ||
	                     options.command == .uninstall ||
	                     options.command == .info
	if (options.argument != "") != argument_required {usage();os.exit(2)}

	switch options.command {
	case .help:
		usage()
	case .list:
		if !list_installed() {os.exit(1)}
	case .install:
		message, ok := install_appimage(options.argument);fmt.println(message);if !ok {os.exit(1)}
	case .uninstall:
		message, ok := uninstall_appimage(options.argument);fmt.println(message);if !ok {os.exit(1)}
	case .info:
		if !print_info(options.argument) {os.exit(1)}
	}
}
