use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::elf::inspect_elf;
use crate::squashfs::Image;

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppImageInfo {
    pub path: String,
    pub appimage_type: i32,
    pub id: String,
    pub name: String,
    pub summary: String,
    pub description: String,
    pub version: String,
    pub architecture: String,
    pub icon: String,
    #[serde(deserialize_with = "null_as_empty")]
    pub categories: Vec<String>,
    #[serde(deserialize_with = "null_as_empty")]
    pub keywords: Vec<String>,
    #[serde(deserialize_with = "null_as_empty")]
    pub mime_types: Vec<String>,
    pub homepage: String,
    pub project_license: String,
    pub update_information: String,
    pub signature_status: String,
    pub sha256: String,
    pub size: i64,
    pub metadata_quality: String,
}

fn null_as_empty<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::deserialize(d)?.unwrap_or_default())
}

pub fn trim_nul(data: &[u8]) -> String {
    let n = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..n]).trim().to_string()
}

pub fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn ext(path: &str) -> &str {
    let base = base_name(path);
    base.rfind('.').map_or("", |i| &base[i..])
}

pub fn stem(path: &str) -> &str {
    let base = base_name(path);
    &base[..base.len() - ext(path).len()]
}

pub fn is_icon_extension(ext: &str) -> bool {
    ext == ".png" || ext == ".svg" || ext == ".svgz"
}

pub fn icon_extension(path: &str) -> Option<String> {
    let ext = ext(path).to_lowercase();
    is_icon_extension(&ext).then_some(ext)
}

fn split_list(value: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for item in value.split(';').map(str::trim) {
        if !item.is_empty() && !result.iter().any(|r| r == item) {
            result.push(item.to_string());
        }
    }
    result
}

fn collapse_space(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn sha256_file(path: &str) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

type IniSection = HashMap<String, String>;

fn parse_ini(text: &str) -> HashMap<String, IniSection> {
    let mut sections: HashMap<String, IniSection> = HashMap::new();
    let mut current = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            current = rest.split(']').next().unwrap_or(rest).to_string();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            sections
                .entry(current.clone())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    sections
}

fn desktop_value<'a>(section: &'a IniSection, key: &str) -> &'a str {
    if let Ok(lang) = std::env::var("LANG") {
        let lang = lang.split(['.', '@']).next().unwrap_or("");
        if !lang.is_empty() {
            if let Some(value) = section.get(&format!("{key}[{lang}]")) {
                return value;
            }
            if let Some((short, _)) = lang.split_once('_')
                && let Some(value) = section.get(&format!("{key}[{short}]"))
            {
                return value;
            }
        }
    }
    section.get(key).map_or("", String::as_str)
}

fn parse_desktop(data: &[u8], info: &mut AppImageInfo) -> Option<String> {
    let sections = parse_ini(&String::from_utf8_lossy(data));
    let section = sections.get("Desktop Entry")?;
    let get = |key: &str| section.get(key).map_or("", String::as_str);
    let value = desktop_value(section, "Name");
    if !value.is_empty() {
        info.name = value.to_string();
    }
    let value = desktop_value(section, "Comment");
    if !value.is_empty() {
        info.summary = value.to_string();
    }
    if !get("X-AppImage-Version").is_empty() {
        info.version = get("X-AppImage-Version").to_string();
    }
    info.categories = split_list(get("Categories"));
    info.keywords = split_list(desktop_value(section, "Keywords"));
    info.mime_types = split_list(get("MimeType"));
    Some(get("Icon").to_string())
}

fn xml_text(node: roxmltree::Node) -> String {
    let text: String = node.descendants().filter_map(|n| n.text()).collect();
    collapse_space(&text)
}

fn parse_appstream(data: &[u8], info: &mut AppImageInfo) -> bool {
    let text = String::from_utf8_lossy(data);
    let options = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let Ok(doc) = roxmltree::Document::parse_with_options(&text, options) else {
        return false;
    };
    let root = doc.root_element();
    let children = |name: &'static str| {
        root.children().filter(move |n| n.is_element() && n.tag_name().name() == name)
    };
    let child_text = |name| children(name).next().map(xml_text).unwrap_or_default();

    let value = child_text("id");
    if !value.is_empty() {
        info.id = value;
    }
    if info.name.is_empty() {
        info.name = child_text("name");
    }
    for (name, field) in [
        ("summary", &mut info.summary),
        ("description", &mut info.description),
        ("project_license", &mut info.project_license),
    ] {
        let value = child_text(name);
        if !value.is_empty() {
            *field = value;
        }
    }
    if let Some(url) = children("url").find(|n| n.attribute("type") == Some("homepage")) {
        info.homepage = xml_text(url);
    }
    if let Some(version) = children("releases")
        .next()
        .and_then(|r| r.children().find(|n| n.is_element() && n.tag_name().name() == "release"))
        .and_then(|r| r.attribute("version"))
        .filter(|v| !v.is_empty())
    {
        info.version = version.to_string();
    }
    true
}

const METADATA_LIMIT: usize = 4 * 1024 * 1024;
const ICON_LIMIT: usize = 16 * 1024 * 1024;

fn root_desktop(image: &Image) -> Option<String> {
    ["", "usr/share/applications"]
        .iter()
        .flat_map(|dir| image.list(dir))
        .find(|p| p.ends_with(".desktop") && image.is_file(p))
        .cloned()
}

fn first_appstream(image: &Image) -> Option<String> {
    ["usr/share/metainfo", "usr/share/appdata"]
        .iter()
        .flat_map(|dir| image.list(dir))
        .find(|p| (p.ends_with(".xml") || p.ends_with(".appdata")) && image.is_file(p))
        .cloned()
}

fn icon_score(path: &str, icon_id: &str) -> i64 {
    if !icon_id.is_empty() && stem(path) != icon_id {
        return -1;
    }
    let Some(ext) = icon_extension(path) else { return -1 };
    let mut score = if ext == ".png" { 1000 } else { 100000 };
    for part in path.split('/') {
        if let Some(x) = part.find('x')
            && x > 0
            && let Ok(size) = part[..x].parse::<i64>()
        {
            score += size;
        }
    }
    score
}

fn best_icon<'a>(candidates: impl IntoIterator<Item = &'a String>, icon_id: &str) -> Option<&'a String> {
    let mut best = None;
    let mut best_score = -1;
    for path in candidates {
        let score = icon_score(path, icon_id);
        if score > best_score {
            best = Some(path);
            best_score = score;
        }
    }
    best
}

fn find_icon(image: &Image, icon_id: &str) -> Option<String> {
    let mut themed = Vec::new();
    image.walk_files("usr/share/icons/hicolor", &mut themed);
    best_icon(&themed, icon_id)
        .or_else(|| best_icon(image.list("").iter().filter(|p| image.is_file(p)), icon_id))
        .cloned()
        .or_else(|| image.is_file(".DirIcon").then(|| ".DirIcon".to_string()))
}

pub struct Icon {
    pub ext: Option<String>,
    pub data: Vec<u8>,
}

pub fn inspect_appimage(path: &str) -> Result<(AppImageInfo, Option<Icon>), String> {
    let mut info = AppImageInfo {
        path: path.to_string(),
        signature_status: "absent".into(),
        ..Default::default()
    };
    let absolute = std::path::absolute(path).map_err(|_| "cannot resolve AppImage path")?;
    let absolute = absolute.to_string_lossy().into_owned();
    let meta = fs::metadata(&absolute)
        .ok()
        .filter(|m| m.is_file())
        .ok_or("AppImage is not a regular file")?;
    info.size = meta.len() as i64;

    let elf = inspect_elf(&absolute, meta.len()).ok_or("invalid or unsupported AppImage ELF header")?;
    if elf.appimage_type == 1 {
        return Err("type 1 AppImages are not supported".into());
    }
    let offset = elf.payload_offset.ok_or("cannot locate AppImage squashfs image")?;
    info.appimage_type = elf.appimage_type;
    info.architecture = elf.architecture;
    info.update_information = elf.update_information;
    info.signature_status = elf.signature_status;
    if let Some(digest) = sha256_file(&absolute) {
        info.sha256 = digest;
    }

    let image = Image::open(&absolute, offset)?;

    let mut icon_id = String::new();
    if let Some(desktop) = root_desktop(&image)
        && let Some(data) = image.read(&desktop, METADATA_LIMIT)
        && let Some(icon) = parse_desktop(&data, &mut info)
    {
        icon_id = icon;
        info.id = stem(&desktop).to_string();
        info.metadata_quality = "desktop".into();
    }
    if let Some(appstream) = first_appstream(&image)
        && let Some(data) = image.read(&appstream, METADATA_LIMIT)
        && parse_appstream(&data, &mut info)
    {
        info.metadata_quality = "appstream".into();
    }
    if info.name.is_empty() {
        info.name = stem(&absolute).to_string();
        info.metadata_quality = "filename".into();
    }
    if info.id.is_empty() {
        info.id = info.name.clone();
    }
    if info.description.is_empty() && !info.summary.is_empty() {
        info.description = info.summary.clone();
    }

    let mut icon = None;
    if let Some(icon_path) = find_icon(&image, &icon_id) {
        let data = image
            .read(&icon_path, ICON_LIMIT)
            .ok_or_else(|| format!("cannot read icon {icon_path}"))?;
        icon = Some(Icon { ext: icon_extension(&icon_path), data });
        info.icon = icon_path;
    }
    Ok((info, icon))
}

pub fn print_info(path: &str) -> Result<(), String> {
    let (info, _) = inspect_appimage(path)?;
    let json = serde_json::to_string_pretty(&info).map_err(|e| format!("cannot encode metadata: {e}"))?;
    println!("{json}");
    Ok(())
}
