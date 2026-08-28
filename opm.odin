#+build linux
package main

import "base:runtime"
import "core:crypto/sha2"
import "core:encoding/endian"
import "core:encoding/hex"
import "core:encoding/ini"
import "core:encoding/json"
import "core:encoding/xml"
import "core:flags"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:sort"
import "core:strconv"
import "core:strings"

AppImage_Info :: struct {
	path:               string,
	appimage_type:      int,
	id:                 string,
	name:               string,
	summary:            string,
	description:        string,
	version:            string,
	architecture:       string,
	icon:               string,
	categories:         []string,
	keywords:           []string,
	mime_types:         []string,
	homepage:           string,
	project_license:    string,
	update_information: string,
	signature_status:   string,
	sha256:             string,
	size:               i64,
	metadata_quality:   string,
}

Elf_Info :: struct {
	appimage_type:      int,
	architecture:       string,
	update_information: string,
	signature_status:   string,
}

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

owned :: proc(s: string) -> string {
	return strings.clone(s)
}

trim_nul :: proc(data: []byte) -> string {
	n := 0
	for n < len(data) && data[n] != 0 {n += 1}
	return strings.trim_space(string(data[:n]))
}

split_list :: proc(value: string) -> []string {
	result: [dynamic]string
	remaining := value
	for raw in strings.split_iterator(&remaining, ";") {
		item := strings.trim_space(raw)
		if item != "" && !slice.contains(result[:], item) {append(&result, owned(item))}
	}
	return result[:]
}

collapse_space :: proc(value: string) -> string {
	b := strings.builder_make()
	space := false
	for c in transmute([]byte)value {
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			space = b.buf != nil && len(b.buf) > 0
		} else {
			if space {_ = strings.write_byte(&b, ' ');space = false}
			_ = strings.write_byte(&b, c)
		}
	}
	return strings.to_string(b)
}

native_arch :: proc(machine: u16) -> string {
	switch machine {
	case 3:
		return "i386"
	case 40:
		return "arm"
	case 62:
		return "x86_64"
	case 183:
		return "aarch64"
	case 243:
		return "riscv64"
	}
	return fmt.aprintf("elf-machine-%d", machine)
}

read_section :: proc(f: ^os.File, offset, size, file_size: u64) -> ([]byte, bool) {
	if size == 0 ||
	   size > 1024 * 1024 ||
	   offset > file_size ||
	   size > file_size - offset {return nil, false}
	data := make([]byte, int(size))
	n, err := os.read_at(f, data, i64(offset))
	if n != len(data) || err != nil {delete(data);return nil, false}
	return data, true
}

inspect_elf :: proc(path: string, file_size: u64) -> (Elf_Info, bool) {
	result := Elf_Info {
		signature_status = "absent",
	}
	f, err := os.open(path)
	if err != nil {return result, false}
	defer os.close(f)

	header: [64]byte
	n, read_err := os.read_at(f, header[:], 0)
	if n < 20 ||
	   (read_err != nil && n < len(header)) ||
	   header[0] != 0x7f ||
	   string(header[1:4]) != "ELF" {return result, false}
	if header[8] != 'A' ||
	   header[9] != 'I' ||
	   (header[10] != 1 && header[10] != 2) {return result, false}
	result.appimage_type = int(header[10])

	order := endian.Byte_Order.Little
	if header[5] == 2 {order = .Big} else if header[5] != 1 {return result, false}
	machine, ok := endian.get_u16(header[18:20], order)
	if !ok {return result, false}
	result.architecture = native_arch(machine)

	if result.appimage_type == 1 {
		buf: [512]byte
		if got, _ := os.read_at(f, buf[:], 33651);
		   got > 0 {result.update_information = owned(trim_nul(buf[:got]))}
		return result, true
	}

	class := header[4]
	shoff, shentsize, shnum, shstrndx: u64
	if class == 2 {
		shoff, ok = endian.get_u64(header[40:48], order);if !ok {return result, true}
		v16, _ := endian.get_u16(header[58:60], order);shentsize = u64(v16)
		v16, _ = endian.get_u16(header[60:62], order);shnum = u64(v16)
		v16, _ = endian.get_u16(header[62:64], order);shstrndx = u64(v16)
	} else if class == 1 {
		v32, _ := endian.get_u32(header[32:36], order);shoff = u64(v32)
		v16, _ := endian.get_u16(header[46:48], order);shentsize = u64(v16)
		v16, _ = endian.get_u16(header[48:50], order);shnum = u64(v16)
		v16, _ = endian.get_u16(header[50:52], order);shstrndx = u64(v16)
	} else {return result, true}
	if shnum == 0 ||
	   shnum > 4096 ||
	   shstrndx >= shnum ||
	   shentsize < 40 ||
	   shoff > file_size ||
	   shnum * shentsize > file_size - shoff {return result, true}

	headers, headers_ok := read_section(f, shoff, shnum * shentsize, file_size)
	if !headers_ok {return result, true}
	defer delete(headers)
	section_values :: proc(
		h: []byte,
		class: byte,
		order: endian.Byte_Order,
	) -> (
		name: u32,
		offset, size: u64,
		ok: bool,
	) {
		name, ok = endian.get_u32(h[0:4], order);if !ok {return}
		if class == 2 {
			offset, ok = endian.get_u64(h[24:32], order);if !ok {return}
			size, ok = endian.get_u64(h[32:40], order)
		} else {
			v, valid := endian.get_u32(h[16:20], order);offset, ok = u64(v), valid;if !ok {return}
			v, valid = endian.get_u32(h[20:24], order);size, ok = u64(v), valid
		}
		return
	}
	_, names_offset, names_size, names_ok := section_values(
		headers[shstrndx * shentsize:(shstrndx + 1) * shentsize],
		class,
		order,
	)
	if !names_ok {return result, true}
	names, names_read := read_section(f, names_offset, names_size, file_size)
	if !names_read {return result, true}
	defer delete(names)

	for i: u64 = 0; i < shnum; i += 1 {
		name_offset, offset, size, valid := section_values(
			headers[i * shentsize:(i + 1) * shentsize],
			class,
			order,
		)
		if !valid || u64(name_offset) >= u64(len(names)) {continue}
		name := trim_nul(names[name_offset:])
		if name != ".upd_info" && name != ".sha256_sig" {continue}
		data, data_ok := read_section(f, offset, size, file_size)
		if !data_ok {continue}
		if name == ".upd_info" {
			result.update_information = owned(trim_nul(data))
		} else {
			for c in data {if c != 0 {result.signature_status = "present";break}}
		}
		delete(data)
	}
	return result, true
}

sha256_file :: proc(path: string) -> (string, bool) {
	f, err := os.open(path)
	if err != nil {return "", false}
	defer os.close(f)
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	buf: [128 * 1024]byte
	for {
		n, read_err := os.read(f, buf[:])
		if n > 0 {sha2.update(&ctx, buf[:n])}
		if read_err != nil {
			if read_err != .EOF {return "", false}
			break
		}
		if n == 0 {break}
	}
	digest: [sha2.DIGEST_SIZE_256]byte
	sha2.final(&ctx, digest[:])
	encoded, encode_err := hex.encode(digest[:])
	if encode_err != nil {return "", false}
	return string(encoded), true
}

run_extract :: proc(appimage, work_dir, prefix: string) -> bool {
	command := []string {
		"bwrap",
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--ro-bind",
		"/usr",
		"/usr",
		"--ro-bind",
		"/lib",
		"/lib",
		"--ro-bind",
		"/lib64",
		"/lib64",
		"--ro-bind",
		appimage,
		"/app.AppImage",
		"--bind",
		work_dir,
		"/work",
		"--chdir",
		"/work",
		"--tmpfs",
		"/tmp",
		"--proc",
		"/proc",
		"--dev",
		"/dev",
		"/app.AppImage",
		"--appimage-extract",
		prefix,
	}
	state, stdout, stderr, err := os.process_exec({command = command}, context.temp_allocator)
	_ = stdout;_ = stderr
	return err == nil && state.success && state.exit_code == 0
}

extract_metadata :: proc(appimage, work_dir: string) -> bool {
	prefixes := []string {
		"*.desktop",
		".DirIcon",
		"*.png",
		"*.svg",
		"*.svgz",
		"usr/share/icons/hicolor",
		"usr/share/metainfo",
		"usr/share/appdata",
	}
	ok := false
	for prefix in prefixes {if run_extract(appimage, work_dir, prefix) {ok = true}}
	return ok
}

desktop_value :: proc(section: map[string]string, key: string) -> string {
	lang := os.get_env("LANG", context.temp_allocator)
	if lang != "" {
		if dot := strings.index_byte(lang, '.'); dot >= 0 {lang = lang[:dot]}
		if at := strings.index_byte(lang, '@'); at >= 0 {lang = lang[:at]}
		localized := fmt.tprintf("%s[%s]", key, lang)
		if value, found := section[localized]; found {return value}
		if underscore := strings.index_byte(lang, '_'); underscore >= 0 {
			localized = fmt.tprintf("%s[%s]", key, lang[:underscore])
			if value, found := section[localized]; found {return value}
		}
	}
	return section[key]
}

parse_desktop :: proc(path: string, info: ^AppImage_Info) -> (icon_id: string, ok: bool) {
	data, err := os.read_entire_file(path, context.temp_allocator)
	if err != nil {return "", false}
	m, map_err := ini.load_map_from_string(string(data), context.temp_allocator)
	if map_err != nil {return "", false}
	section, found := m["Desktop Entry"]
	if !found {return "", false}
	if value := desktop_value(section, "Name"); value != "" {info.name = owned(value)}
	if value := desktop_value(section, "Comment"); value != "" {info.summary = owned(value)}
	if value := section["X-AppImage-Version"]; value != "" {info.version = owned(value)}
	info.categories = split_list(section["Categories"])
	info.keywords = split_list(desktop_value(section, "Keywords"))
	info.mime_types = split_list(section["MimeType"])
	return owned(section["Icon"]), true
}

xml_text_into :: proc(doc: ^xml.Document, id: xml.Element_ID, b: ^strings.Builder) {
	for value in doc.elements[id].value {
		switch v in value {
		case string:
			_ = strings.write_string(b, v)
		case xml.Element_ID:
			xml_text_into(doc, v, b)
		}
	}
}

xml_text :: proc(doc: ^xml.Document, id: xml.Element_ID) -> string {
	b := strings.builder_make()
	xml_text_into(doc, id, &b)
	return collapse_space(strings.to_string(b))
}

child_text :: proc(doc: ^xml.Document, parent: xml.Element_ID, name: string) -> string {
	id, found := xml.find_child_by_ident(doc, parent, name)
	if !found {return ""}
	return xml_text(doc, id)
}

parse_appstream :: proc(path: string, info: ^AppImage_Info) -> bool {
	data, err := os.read_entire_file(path, context.temp_allocator)
	if err != nil {return false}
	doc, parse_err := xml.parse_bytes(data, xml.Options{flags = {.Ignore_Unsupported}})
	if doc != nil {defer xml.destroy(doc)}
	if parse_err != .None || doc == nil || doc.element_count == 0 {return false}
	root := xml.Element_ID(0)
	if value := child_text(doc, root, "id"); value != "" {info.id = value}
	if info.name == "" {if value := child_text(doc, root, "name"); value != "" {info.name = value}}
	if value := child_text(doc, root, "summary"); value != "" {info.summary = value}
	if value := child_text(doc, root, "description"); value != "" {info.description = value}
	if value := child_text(doc, root, "project_license");
	   value != "" {info.project_license = value}
	for nth := 0;; nth += 1 {
		url_id, found := xml.find_child_by_ident(doc, root, "url", nth)
		if !found {break}
		kind, _ := xml.find_attribute_val_by_key(doc, url_id, "type")
		if kind == "homepage" {info.homepage = xml_text(doc, url_id);break}
	}
	if releases, found := xml.find_child_by_ident(doc, root, "releases"); found {
		if release, release_found := xml.find_child_by_ident(doc, releases, "release");
		   release_found {
			if value, value_found := xml.find_attribute_val_by_key(doc, release, "version");
			   value_found && value != "" {info.version = owned(value)}
		}
	}
	return true
}

root_desktop :: proc(root: string) -> string {
	entries, err := os.read_all_directory_by_path(root, context.temp_allocator)
	if err != nil {return ""}
	for entry in entries {if entry.type == .Regular &&
		   strings.has_suffix(entry.name, ".desktop") {return owned(entry.fullpath)}}
	return ""
}

first_appstream :: proc(root: string) -> string {
	dirs := []string{"usr/share/metainfo", "usr/share/appdata"}
	for dir_name in dirs {
		dir := filepath.join({root, dir_name}, context.temp_allocator) or_continue
		entries, err := os.read_all_directory_by_path(dir, context.temp_allocator)
		if err != nil {continue}
		for entry in entries {
			if entry.type == .Regular &&
			   (strings.has_suffix(entry.name, ".xml") ||
					   strings.has_suffix(entry.name, ".appdata")) {return owned(entry.fullpath)}
		}
	}
	return ""
}

icon_score :: proc(path, icon_id: string) -> int {
	base := filepath.base(path)
	stem := filepath.stem(base)
	if icon_id != "" && stem != icon_id {return -1}
	ext := strings.to_lower(filepath.ext(path), context.temp_allocator)
	score := 0
	if ext == ".svg" ||
	   ext == ".svgz" {score = 100000} else if ext == ".png" {score = 1000} else {return -1}
	parts := path
	for part in strings.split_iterator(&parts, "/") {
		if x := strings.index_byte(part, 'x'); x > 0 {
			if size, valid := strconv.parse_int(part[:x]); valid {score += size}
		}
	}
	return score
}

find_icon :: proc(root, icon_id: string) -> string {
	best: string
	best_score := -1
	icons, join_err := filepath.join({root, "usr/share/icons/hicolor"}, context.temp_allocator)
	if join_err != nil {return ""}
	walker := filepath.walker_create(icons)
	defer filepath.walker_destroy(&walker)
	for entry in filepath.walker_walk(&walker) {
		if entry.type != .Regular {continue}
		score := icon_score(entry.fullpath, icon_id)
		if score > best_score {delete(best);best = owned(entry.fullpath);best_score = score}
	}
	if best != "" {return best}
	entries, err := os.read_all_directory_by_path(root, context.temp_allocator)
	if err == nil {
		for entry in entries {
			score := icon_score(entry.fullpath, icon_id)
			if score > best_score {delete(best);best = owned(entry.fullpath);best_score = score}
		}
	}
	if best != "" {return best}
	dir_icon, dir_icon_err := filepath.join({root, ".DirIcon"}, context.temp_allocator)
	if dir_icon_err != nil {return ""}
	if _, err := os.stat(dir_icon, context.temp_allocator); err == nil {return owned(dir_icon)}
	return ""
}

internal_path :: proc(root, path: string) -> string {
	if strings.has_prefix(path, root) {
		start := len(root)
		if start < len(path) && (path[start] == '/' || path[start] == '\\') {start += 1}
		return owned(path[start:])
	}
	return owned(path)
}

inspect_appimage :: proc(path, icon_out: string) -> (AppImage_Info, string, bool) {
	info := AppImage_Info {
		path             = owned(path),
		signature_status = "absent",
	}
	absolute, abs_err := filepath.abs(path)
	if abs_err != nil {return info, "cannot resolve AppImage path", false}
	file_info, stat_err := os.stat(absolute, context.temp_allocator)
	if stat_err != nil ||
	   file_info.type != .Regular {return info, "AppImage is not a regular file", false}
	info.size = file_info.size
	elf, valid := inspect_elf(absolute, u64(file_info.size))
	if !valid {return info, "invalid or unsupported AppImage ELF header", false}
	info.appimage_type = elf.appimage_type
	info.architecture = elf.architecture
	info.update_information = elf.update_information
	info.signature_status = elf.signature_status
	if digest, hash_ok := sha256_file(absolute); hash_ok {info.sha256 = digest}

	work_dir, temp_err := os.make_directory_temp("", "opm-info-*", context.allocator)
	if temp_err != nil {return info, "cannot create temporary directory", false}
	defer {os.remove_all(work_dir);delete(work_dir)}
	if !extract_metadata(
		absolute,
		work_dir,
	) {return info, "metadata extraction failed (bubblewrap and host-native AppImage runtime required)", false}
	root, root_err := filepath.join({work_dir, "squashfs-root"}, context.temp_allocator)
	if root_err != nil {return info, "cannot build extraction path", false}

	desktop := root_desktop(root)
	icon_id: string
	if desktop != "" {
		defer delete(desktop)
		icon_id, _ = parse_desktop(desktop, &info)
		info.id = owned(filepath.stem(desktop))
		info.metadata_quality = "desktop"
	}
	appstream := first_appstream(root)
	if appstream != "" {
		defer delete(appstream)
		if parse_appstream(appstream, &info) {info.metadata_quality = "appstream"}
	}
	if info.name == "" {
		info.name = owned(filepath.stem(absolute))
		info.metadata_quality = "filename"
	}
	if info.description == "" && info.summary != "" {info.description = owned(info.summary)}

	icon_path := find_icon(root, icon_id)
	if icon_path != "" {
		defer delete(icon_path)
		info.icon = internal_path(root, icon_path)
		if icon_out != "" {
			if err := os.copy_file(icon_out, icon_path);
			   err != nil {return info, fmt.aprintf("cannot write icon: %v", err), false}
			info.icon = owned(icon_out)
		}
	}
	return info, "", true
}

safe_id :: proc(value: string) -> string {
	b := strings.builder_make()
	last_dash := false
	for c in transmute([]byte)value {
		valid :=
			c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' ||
			c == '.' ||
			c == '_' ||
			c == '-'
		if valid {
			_ = strings.write_byte(&b, c)
			last_dash = c == '-'
		} else if !last_dash {
			_ = strings.write_byte(&b, '-')
			last_dash = true
		}
	}
	result := strings.trim(strings.to_string(b), "-.")
	if result == "" {return "appimage"}
	return result
}

manager_paths :: proc(
	id: string,
) -> (
	app_dir, desktop_dir, data_dir, app_path, desktop_path, icon_path, manifest_path: string,
	ok: bool,
) {
	home, home_err := os.user_home_dir(context.allocator)
	if home_err != nil {return}
	defer delete(home)
	data_home, data_err := os.user_data_dir(context.allocator)
	if data_err != nil {return}
	defer delete(data_home)
	err: runtime.Allocator_Error
	app_dir, err = filepath.join({home, ".opm", "appimages"});if err != nil {return}
	desktop_dir, err = filepath.join({data_home, "applications"});if err != nil {return}
	data_dir, err = filepath.join({data_home, "opm", id});if err != nil {return}
	app_path, err = filepath.join({app_dir, fmt.tprintf("%s.AppImage", id)});if err != nil {return}
	desktop_path, err = filepath.join(
		{desktop_dir, fmt.tprintf("opm-%s.desktop", id)},
	);if err != nil {return}
	icon_path, err = filepath.join({data_dir, "icon"});if err != nil {return}
	manifest_path, err = filepath.join({data_dir, "manifest.json"});if err != nil {return}
	ok = true
	return
}

desktop_text :: proc(value: string) -> string {
	b := strings.builder_make()
	for c in transmute([]byte)value {
		switch c {
		case '\\':
			_ = strings.write_string(&b, "\\\\")
		case '\n', '\r', '\t':
			_ = strings.write_byte(&b, ' ')
		case:
			_ = strings.write_byte(&b, c)
		}
	}
	return strings.to_string(b)
}

exec_quote :: proc(value: string) -> string {
	b := strings.builder_make()
	_ = strings.write_byte(&b, '"')
	for c in transmute([]byte)value {
		switch c {
		case '"', '\\', '`', '$':
			_ = strings.write_byte(&b, '\\');_ = strings.write_byte(&b, c)
		case '%':
			_ = strings.write_string(&b, "%%")
		case:
			_ = strings.write_byte(&b, c)
		}
	}
	_ = strings.write_byte(&b, '"')
	return strings.to_string(b)
}

desktop_entry :: proc(info: ^AppImage_Info, app_path, icon_path: string) -> string {
	b := strings.builder_make()
	_ = strings.write_string(&b, "[Desktop Entry]\nType=Application\n")
	_ = fmt.sbprintf(&b, "Name=%s\nExec=%s %%U\n", desktop_text(info.name), exec_quote(app_path))
	if info.summary != "" {_ = fmt.sbprintf(&b, "Comment=%s\n", desktop_text(info.summary))}
	if icon_path != "" {_ = fmt.sbprintf(&b, "Icon=%s\n", desktop_text(icon_path))}
	if len(info.categories) >
	   0 {_ = fmt.sbprintf(&b, "Categories=%s;\n", strings.join(info.categories, ";", context.temp_allocator))}
	if len(info.mime_types) >
	   0 {_ = fmt.sbprintf(&b, "MimeType=%s;\n", strings.join(info.mime_types, ";", context.temp_allocator))}
	_ = strings.write_string(&b, "Terminal=false\nX-AppImage-Managed=true\n")
	return strings.to_string(b)
}

same_path :: proc(a, b: string) -> bool {
	aa, ae := filepath.abs(a)
	bb, be := filepath.abs(b)
	return ae == nil && be == nil && aa == bb
}

move_file :: proc(source, destination: string) -> os.Error {
	if err := os.rename(source, destination); err == nil {return nil}
	os.copy_file(destination, source) or_return
	os.remove(source) or_return
	return nil
}

rollback_install :: proc(source, destination, desktop_path, data_dir: string, moved: bool) {
	_ = os.remove(desktop_path)
	_ = os.remove_all(data_dir)
	if moved && os.exists(destination) {_ = move_file(destination, source)}
}

refresh_desktop_database :: proc(desktop_dir: string) {
	command := []string{"update-desktop-database", desktop_dir}
	_, _, _, _ = os.process_exec({command = command}, context.temp_allocator)
}

install_appimage :: proc(source: string) -> (string, bool) {
	absolute, abs_err := filepath.abs(source)
	if abs_err != nil {return "cannot resolve AppImage path", false}
	info, message, inspected := inspect_appimage(absolute, "")
	if !inspected {return message, false}
	id := safe_id(info.id)
	app_dir, desktop_dir, data_dir, app_path, desktop_path, icon_path, manifest_path, paths_ok :=
		manager_paths(id)
	if !paths_ok {return "cannot resolve install directories", false}
	if ext := strings.to_lower(filepath.ext(info.icon), context.temp_allocator);
	   ext == ".png" ||
	   ext == ".svg" ||
	   ext == ".svgz" {icon_path = fmt.aprintf("%s%s", icon_path, ext)}
	if os.exists(app_path) ||
	   os.exists(desktop_path) ||
	   os.exists(data_dir) {return fmt.aprintf("already installed: %s", id), false}
	if same_path(absolute, app_path) {return "source is already managed", false}
	if err := os.make_directory_all(app_dir);
	   err != nil && err != .Exist {return fmt.aprintf("cannot create %s: %v", app_dir, err), false}
	if err := os.make_directory_all(desktop_dir);
	   err != nil && err != .Exist {return fmt.aprintf("cannot create %s: %v", desktop_dir, err), false}
	if err := os.make_directory_all(data_dir);
	   err != nil && err != .Exist {return fmt.aprintf("cannot create %s: %v", data_dir, err), false}
	moved := false
	defer if !moved {rollback_install(absolute, app_path, desktop_path, data_dir, os.exists(app_path))}
	if err := move_file(absolute, app_path);
	   err != nil {return fmt.aprintf("cannot move AppImage: %v", err), false}
	if err := os.chmod(app_path, os.Permissions_Read_All + {.Write_User, .Execute_User});
	   err != nil {return fmt.aprintf("cannot make AppImage executable: %v", err), false}

	installed_info, installed_message, installed_ok := inspect_appimage(app_path, icon_path)
	if !installed_ok {return installed_message, false}
	installed_info.path = owned(app_path)
	if !os.exists(icon_path) {delete(installed_info.icon);installed_info.icon = ""}
	manifest, marshal_err := json.marshal(
		installed_info,
		{pretty = true, use_spaces = true, spaces = 2},
	)
	if marshal_err != nil {return fmt.aprintf("cannot encode manifest: %v", marshal_err), false}
	if err := os.write_entire_file(manifest_path, manifest);
	   err != nil {return fmt.aprintf("cannot write manifest: %v", err), false}
	entry := desktop_entry(&installed_info, app_path, installed_info.icon)
	if err := os.write_entire_file(desktop_path, entry);
	   err != nil {return fmt.aprintf("cannot write desktop shortcut: %v", err), false}
	refresh_desktop_database(desktop_dir)
	moved = true
	return fmt.aprintf(
			"installed %s\nAppImage: %s\nDesktop: %s",
			installed_info.name,
			app_path,
			desktop_path,
		),
		true
}

Installed_App :: struct {
	id:   string,
	info: AppImage_Info,
}

compare_installed :: proc(a, b: Installed_App) -> int {
	return sort.compare_strings(a.id, b.id)
}

list_installed :: proc() -> bool {
	data_home, data_err := os.user_data_dir(context.temp_allocator)
	if data_err != nil {fmt.eprintf("cannot resolve data directory: %v\n", data_err);return false}
	root, join_err := filepath.join({data_home, "opm"}, context.temp_allocator)
	if join_err != nil {fmt.eprintln("cannot resolve manager data directory");return false}
	entries, read_err := os.read_all_directory_by_path(root, context.temp_allocator)
	if read_err == .Not_Exist {fmt.println("No installed AppImages.");return true}
	if read_err != nil {fmt.eprintf("cannot read installed apps: %v\n", read_err);return false}

	apps: [dynamic]Installed_App
	for entry in entries {
		if entry.type != .Directory {continue}
		manifest_path, err := filepath.join({entry.fullpath, "manifest.json"}, context.temp_allocator)
		if err != nil {continue}
		data, file_err := os.read_entire_file(manifest_path, context.temp_allocator)
		if file_err != nil {fmt.eprintf("warning: cannot read %s: %v\n", manifest_path, file_err);continue}
		info: AppImage_Info
		if json_err := json.unmarshal(data, &info, json.DEFAULT_SPECIFICATION, context.temp_allocator); json_err != nil {
			fmt.eprintf("warning: invalid manifest %s: %v\n", manifest_path, json_err)
			continue
		}
		append(&apps, Installed_App{id = entry.name, info = info})
	}
	if len(apps) == 0 {fmt.println("No installed AppImages.");return true}
	sort.quick_sort_proc(apps[:], compare_installed)
	fmt.println("ID\tNAME\tVERSION\tARCHITECTURE\tPATH")
	for app in apps {fmt.printfln("%s\t%s\t%s\t%s\t%s", app.id, app.info.name, app.info.version, app.info.architecture, app.info.path)}
	return true
}

uninstall_appimage :: proc(raw_id: string) -> (string, bool) {
	id := safe_id(raw_id)
	if id != raw_id {return "invalid installed ID", false}
	_, _, data_dir, app_path, desktop_path, _, _, paths_ok := manager_paths(id)
	if !paths_ok {return "cannot resolve install directories", false}
	if !os.exists(app_path) &&
	   !os.exists(desktop_path) &&
	   !os.exists(data_dir) {return fmt.aprintf("not installed: %s", id), false}
	failures := 0
	if err := os.remove(desktop_path);
	   err != nil &&
	   err != .Not_Exist {fmt.eprintf("cannot remove %s: %v\n", desktop_path, err);failures += 1}
	if err := os.remove(app_path);
	   err != nil &&
	   err != .Not_Exist {fmt.eprintf("cannot remove %s: %v\n", app_path, err);failures += 1}
	if err := os.remove_all(data_dir);
	   err != nil &&
	   err != .Not_Exist {fmt.eprintf("cannot remove %s: %v\n", data_dir, err);failures += 1}
	refresh_desktop_database(filepath.dir(desktop_path))
	if failures > 0 {return "uninstall incomplete", false}
	return fmt.aprintf("uninstalled %s", id), true
}

print_info :: proc(path: string) -> bool {
	info, message, ok := inspect_appimage(path, "")
	if !ok {fmt.eprintln(message);return false}
	data, err := json.marshal(info, {pretty = true, use_spaces = true, spaces = 2})
	if err != nil {fmt.eprintf("cannot encode metadata: %v\n", err);return false}
	fmt.println(string(data))
	return true
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

	switch options.command {
	case .help:
		if options.argument != "" {usage();os.exit(2)}
		usage()
	case .list:
		if options.argument != "" {usage();os.exit(2)}
		if !list_installed() {os.exit(1)}
	case .install:
		if options.argument == "" {usage();os.exit(2)}
		message, ok := install_appimage(options.argument);fmt.println(message);if !ok {os.exit(1)}
	case .uninstall:
		if options.argument == "" {usage();os.exit(2)}
		message, ok := uninstall_appimage(options.argument);fmt.println(message);if !ok {os.exit(1)}
	case .info:
		if options.argument == "" {usage();os.exit(2)}
		if !print_info(options.argument) {os.exit(1)}
	}
}
