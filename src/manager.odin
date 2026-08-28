#+build linux
package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:sort"
import "core:strings"

Manager_Paths :: struct {
	app_dir:      string,
	desktop_dir:  string,
	data_dir:     string,
	app_path:     string,
	desktop_path: string,
	icon_path:    string,
	manifest_path:string,
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

manager_data_paths :: proc() -> (data_home, data_root: string, ok: bool) {
	home, data_err := os.user_data_dir(context.temp_allocator)
	if data_err != nil {return}
	root, join_err := filepath.join({home, "opm"}, context.temp_allocator)
	return home, root, join_err == nil
}

manager_paths :: proc(id: string) -> (p: Manager_Paths, ok: bool) {
	home, home_err := os.user_home_dir(context.temp_allocator)
	if home_err != nil {return}
	data_home, data_root, data_ok := manager_data_paths()
	if !data_ok {return}
	join :: proc(parts: []string, ok: ^bool) -> string {
		if !ok^ {return ""}
		path, err := filepath.join(parts, context.temp_allocator)
		if err != nil {ok^ = false}
		return path
	}
	ok = true
	p.app_dir = join({home, ".opm", "appimages"}, &ok)
	p.desktop_dir = join({data_home, "applications"}, &ok)
	p.data_dir = join({data_root, id}, &ok)
	p.app_path = join({p.app_dir, fmt.tprintf("%s.AppImage", id)}, &ok)
	p.desktop_path = join({p.desktop_dir, fmt.tprintf("opm-%s.desktop", id)}, &ok)
	p.icon_path = join({p.data_dir, "icon"}, &ok)
	p.manifest_path = join({p.data_dir, "manifest.json"}, &ok)
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

rollback_install :: proc(source: string, p: ^Manager_Paths, moved: bool) {
	_ = os.remove(p.desktop_path)
	_ = os.remove_all(p.data_dir)
	if moved && os.exists(p.app_path) {_ = move_file(p.app_path, source)}
}

make_directories :: proc(paths: ..string) -> (string, bool) {
	for path in paths {
		if err := os.make_directory_all(path); err != nil && err != .Exist {
			return fmt.aprintf("cannot create %s: %v", path, err), false
		}
	}
	return "", true
}

remove_managed :: proc(path: string, recursive := false) -> bool {
	err := os.remove(path) if !recursive else os.remove_all(path)
	if err == nil || err == .Not_Exist {return true}
	fmt.eprintf("cannot remove %s: %v\n", path, err)
	return false
}

refresh_desktop_database :: proc(desktop_dir: string) {
	command := []string{"update-desktop-database", desktop_dir}
	_, _, _, _ = os.process_exec({command = command}, context.temp_allocator)
}

install_appimage :: proc(source: string) -> (string, bool) {
	absolute, abs_err := filepath.abs(source)
	if abs_err != nil {return "cannot resolve AppImage path", false}
	stage_dir, temp_err := os.make_directory_temp("", "opm-install-*", context.allocator)
	if temp_err != nil {return "cannot create temporary directory", false}
	defer {os.remove_all(stage_dir);delete(stage_dir)}
	icon_base, join_err := filepath.join({stage_dir, "icon"}, context.temp_allocator)
	if join_err != nil {return "cannot build temporary icon path", false}
	info, message, inspected := inspect_appimage(absolute, icon_base)
	if !inspected {return message, false}
	id := safe_id(info.id)
	p, paths_ok := manager_paths(id)
	if !paths_ok {return "cannot resolve install directories", false}
	staged_icon := info.icon
	if ext := strings.to_lower(filepath.ext(staged_icon), context.temp_allocator); is_icon_extension(ext) {
		p.icon_path = fmt.aprintf("%s%s", p.icon_path, ext)
	}
	if os.exists(p.app_path) ||
	   os.exists(p.desktop_path) ||
	   os.exists(p.data_dir) {return fmt.aprintf("already installed: %s", id), false}
	if same_path(absolute, p.app_path) {return "source is already managed", false}
	if message, ok := make_directories(p.app_dir, p.desktop_dir, p.data_dir); !ok {return message, false}
	moved := false
	defer if !moved {rollback_install(absolute, &p, os.exists(p.app_path))}
	if err := move_file(absolute, p.app_path);
	   err != nil {return fmt.aprintf("cannot move AppImage: %v", err), false}
	if err := os.chmod(p.app_path, os.Permissions_Read_All + {.Write_User, .Execute_User});
	   err != nil {return fmt.aprintf("cannot make AppImage executable: %v", err), false}

	info.path = owned(p.app_path)
	if staged_icon != "" {
		if err := os.rename(staged_icon, p.icon_path);
		   err != nil {return fmt.aprintf("cannot write icon: %v", err), false}
		delete(info.icon)
		info.icon = owned(p.icon_path)
	}
	manifest, marshal_err := json.marshal(
		info,
		{pretty = true, use_spaces = true, spaces = 2},
	)
	if marshal_err != nil {return fmt.aprintf("cannot encode manifest: %v", marshal_err), false}
	if err := os.write_entire_file(p.manifest_path, manifest);
	   err != nil {return fmt.aprintf("cannot write manifest: %v", err), false}
	entry := desktop_entry(&info, p.app_path, info.icon)
	if err := os.write_entire_file(p.desktop_path, entry);
	   err != nil {return fmt.aprintf("cannot write desktop shortcut: %v", err), false}
	refresh_desktop_database(p.desktop_dir)
	moved = true
	return fmt.aprintf(
			"installed %s\nAppImage: %s\nDesktop: %s",
			info.name,
			p.app_path,
			p.desktop_path,
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
	_, data_root, paths_ok := manager_data_paths()
	if !paths_ok {fmt.eprintln("cannot resolve manager data directory");return false}
	entries, read_err := os.read_all_directory_by_path(data_root, context.temp_allocator)
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
	p, paths_ok := manager_paths(id)
	if !paths_ok {return "cannot resolve install directories", false}
	if !os.exists(p.app_path) &&
	   !os.exists(p.desktop_path) &&
	   !os.exists(p.data_dir) {return fmt.aprintf("not installed: %s", id), false}
	ok := remove_managed(p.desktop_path)
	ok = remove_managed(p.app_path) && ok
	ok = remove_managed(p.data_dir, true) && ok
	refresh_desktop_database(p.desktop_dir)
	if !ok {return "uninstall incomplete", false}
	return fmt.aprintf("uninstalled %s", id), true
}
