#+build linux
package main

import "core:crypto/sha2"
import "core:encoding/hex"
import "core:encoding/ini"
import "core:encoding/json"
import "core:encoding/xml"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:slice"
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

is_icon_extension :: proc(ext: string) -> bool {
	return ext == ".png" || ext == ".svg" || ext == ".svgz"
}

icon_score :: proc(path, icon_id: string) -> int {
	base := filepath.base(path)
	stem := filepath.stem(base)
	if icon_id != "" && stem != icon_id {return -1}
	ext := strings.to_lower(filepath.ext(path), context.temp_allocator)
	if !is_icon_extension(ext) {return -1}
	score := 1000
	if ext != ".png" {score = 100000}
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
			destination := icon_out
			if ext := strings.to_lower(filepath.ext(icon_path), context.temp_allocator); is_icon_extension(ext) {
				destination = fmt.aprintf("%s%s", icon_out, ext)
			}
			if err := os.copy_file(destination, icon_path);
			   err != nil {return info, fmt.aprintf("cannot write icon: %v", err), false}
			info.icon = owned(destination)
		}
	}
	return info, "", true
}

print_info :: proc(path: string) -> bool {
	info, message, ok := inspect_appimage(path, "")
	if !ok {fmt.eprintln(message);return false}
	data, err := json.marshal(info, {pretty = true, use_spaces = true, spaces = 2})
	if err != nil {fmt.eprintf("cannot encode metadata: %v\n", err);return false}
	fmt.println(string(data))
	return true
}
