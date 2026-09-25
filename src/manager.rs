use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::appimage::{AppImageInfo, Icon, inspect_appimage};

struct ManagerPaths {
    app_dir: PathBuf,
    desktop_dir: PathBuf,
    data_dir: PathBuf,
    app_path: PathBuf,
    desktop_path: PathBuf,
    icon_path: PathBuf,
    manifest_path: PathBuf,
}

fn safe_id(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in value.bytes() {
        if c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' {
            out.push(c as char);
            last_dash = c == b'-';
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let result = out.trim_matches(['-', '.']);
    if result.is_empty() { "appimage".into() } else { result.into() }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

fn manager_data_paths() -> Option<(PathBuf, PathBuf)> {
    let data_home = match std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home_dir()?.join(".local/share"),
    };
    let root = data_home.join("opm");
    Some((data_home, root))
}

fn manager_paths(id: &str) -> Option<ManagerPaths> {
    let home = home_dir()?;
    let (data_home, data_root) = manager_data_paths()?;
    let app_dir = home.join(".opm/appimages");
    let desktop_dir = data_home.join("applications");
    let data_dir = data_root.join(id);
    Some(ManagerPaths {
        app_path: app_dir.join(format!("{id}.AppImage")),
        desktop_path: desktop_dir.join(format!("opm-{id}.desktop")),
        icon_path: data_dir.join("icon"),
        manifest_path: data_dir.join("manifest.json"),
        app_dir,
        desktop_dir,
        data_dir,
    })
}

fn desktop_text(value: &str) -> String {
    value.replace('\\', "\\\\").replace(['\n', '\r', '\t'], " ")
}

fn exec_quote(value: &str) -> String {
    let mut out = String::from('"');
    for c in value.chars() {
        match c {
            '"' | '\\' | '`' | '$' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn desktop_entry(info: &AppImageInfo, app_path: &str, icon_path: &str) -> String {
    let mut entry = String::from("[Desktop Entry]\nType=Application\n");
    entry += &format!("Name={}\nExec={} %U\n", desktop_text(&info.name), exec_quote(app_path));
    if !info.summary.is_empty() {
        entry += &format!("Comment={}\n", desktop_text(&info.summary));
    }
    if !icon_path.is_empty() {
        entry += &format!("Icon={}\n", desktop_text(icon_path));
    }
    if !info.categories.is_empty() {
        entry += &format!("Categories={};\n", info.categories.join(";"));
    }
    if !info.mime_types.is_empty() {
        entry += &format!("MimeType={};\n", info.mime_types.join(";"));
    }
    entry + "Terminal=false\nX-AppImage-Managed=true\n"
}

fn move_file(source: &Path, destination: &Path) -> io::Result<()> {
    if fs::rename(source, destination).is_ok() {
        return Ok(());
    }
    fs::copy(source, destination)?;
    fs::remove_file(source)
}

fn rollback_install(source: &Path, p: &ManagerPaths) {
    let _ = fs::remove_file(&p.desktop_path);
    let _ = fs::remove_dir_all(&p.data_dir);
    if p.app_path.exists() {
        let _ = move_file(&p.app_path, source);
    }
}

fn remove_managed(path: &Path, recursive: bool) -> bool {
    let result = if recursive { fs::remove_dir_all(path) } else { fs::remove_file(path) };
    match result {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => true,
        Err(e) => {
            eprintln!("cannot remove {}: {e}", path.display());
            false
        }
    }
}

fn refresh_desktop_database(desktop_dir: &Path) {
    let _ = Command::new("update-desktop-database").arg(desktop_dir).output();
}

fn any_exists(p: &ManagerPaths) -> bool {
    p.app_path.exists() || p.desktop_path.exists() || p.data_dir.exists()
}

pub fn install_appimage(source: &str) -> Result<String, String> {
    let absolute = std::path::absolute(source).map_err(|_| "cannot resolve AppImage path")?;
    let (mut info, icon) = inspect_appimage(&absolute.to_string_lossy())?;
    let id = safe_id(&info.id);
    let mut p = manager_paths(&id).ok_or("cannot resolve install directories")?;
    if let Some(ext) = icon.as_ref().and_then(|i| i.ext.as_ref()) {
        p.icon_path.as_mut_os_string().push(ext);
    }
    if any_exists(&p) {
        return Err(format!("already installed: {id}"));
    }
    if fs::canonicalize(&absolute).ok() == fs::canonicalize(&p.app_path).ok() {
        return Err("source is already managed".into());
    }
    for dir in [&p.app_dir, &p.desktop_dir, &p.data_dir] {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }

    if let Err(message) = install_files(&absolute, &p, &mut info, icon.as_ref()) {
        rollback_install(&absolute, &p);
        return Err(message);
    }
    refresh_desktop_database(&p.desktop_dir);
    Ok(format!(
        "installed {}\nAppImage: {}\nDesktop: {}",
        info.name,
        p.app_path.display(),
        p.desktop_path.display()
    ))
}

fn install_files(source: &Path, p: &ManagerPaths, info: &mut AppImageInfo, icon: Option<&Icon>) -> Result<(), String> {
    move_file(source, &p.app_path).map_err(|e| format!("cannot move AppImage: {e}"))?;
    fs::set_permissions(&p.app_path, fs::Permissions::from_mode(0o744))
        .map_err(|e| format!("cannot make AppImage executable: {e}"))?;

    info.path = p.app_path.to_string_lossy().into_owned();
    if let Some(icon) = icon {
        fs::write(&p.icon_path, &icon.data).map_err(|e| format!("cannot write icon: {e}"))?;
        info.icon = p.icon_path.to_string_lossy().into_owned();
    }
    let manifest = serde_json::to_string_pretty(info).map_err(|e| format!("cannot encode manifest: {e}"))?;
    fs::write(&p.manifest_path, manifest).map_err(|e| format!("cannot write manifest: {e}"))?;
    let entry = desktop_entry(info, &info.path, &info.icon);
    fs::write(&p.desktop_path, entry).map_err(|e| format!("cannot write desktop shortcut: {e}"))?;
    Ok(())
}

pub fn list_installed() -> Result<(), String> {
    let (_, data_root) = manager_data_paths().ok_or("cannot resolve manager data directory")?;
    let entries = match fs::read_dir(&data_root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("No installed AppImages.");
            return Ok(());
        }
        Err(e) => return Err(format!("cannot read installed apps: {e}")),
    };

    let mut apps: Vec<(String, AppImageInfo)> = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let manifest_path = entry.path().join("manifest.json");
        let data = match fs::read(&manifest_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("warning: cannot read {}: {e}", manifest_path.display());
                continue;
            }
        };
        match serde_json::from_slice(&data) {
            Ok(info) => apps.push((entry.file_name().to_string_lossy().into_owned(), info)),
            Err(e) => eprintln!("warning: invalid manifest {}: {e}", manifest_path.display()),
        }
    }
    if apps.is_empty() {
        println!("No installed AppImages.");
        return Ok(());
    }
    apps.sort_by(|a, b| a.0.cmp(&b.0));

    let width = |header: &str, field: fn(&(String, AppImageInfo)) -> &str| {
        apps.iter().map(|a| field(a).chars().count()).fold(header.len(), usize::max)
    };
    let id_w = width("ID", |a| &a.0);
    let name_w = width("NAME", |a| &a.1.name);
    let version_w = width("VERSION", |a| &a.1.version);
    let arch_w = width("ARCHITECTURE", |a| &a.1.architecture);
    println!("{:<id_w$}  {:<name_w$}  {:<version_w$}  {:<arch_w$}  PATH", "ID", "NAME", "VERSION", "ARCHITECTURE");
    for (id, info) in &apps {
        println!(
            "{id:<id_w$}  {:<name_w$}  {:<version_w$}  {:<arch_w$}  {}",
            info.name, info.version, info.architecture, info.path
        );
    }
    Ok(())
}

pub fn uninstall_appimage(raw_id: &str) -> Result<String, String> {
    let id = safe_id(raw_id);
    if id != raw_id {
        return Err("invalid installed ID".into());
    }
    let p = manager_paths(&id).ok_or("cannot resolve install directories")?;
    if !any_exists(&p) {
        return Err(format!("not installed: {id}"));
    }
    let mut ok = remove_managed(&p.desktop_path, false);
    ok = remove_managed(&p.app_path, false) && ok;
    ok = remove_managed(&p.data_dir, true) && ok;
    refresh_desktop_database(&p.desktop_dir);
    if !ok {
        return Err("uninstall incomplete".into());
    }
    Ok(format!("uninstalled {id}"))
}
