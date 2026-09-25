use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};

use backhand::{FilesystemReader, InnerNode, Node, SquashfsFileReader};

pub struct Image<'b> {
    fs: FilesystemReader<'b>,
    index: HashMap<String, usize>,
    children: HashMap<String, Vec<String>>,
}

type ImageNode = Node<SquashfsFileReader>;

fn split_parent(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

impl Image<'_> {
    pub fn open(path: &str, offset: u64) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("cannot open AppImage: {e}"))?;
        let fs = FilesystemReader::from_reader_with_offset(BufReader::new(file), offset)
            .map_err(|e| format!("cannot read AppImage squashfs image: {e}"))?;
        let mut index = HashMap::new();
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        for (i, node) in fs.files().enumerate() {
            let path = node.fullpath.to_string_lossy().trim_start_matches('/').to_string();
            if !path.is_empty() {
                let (parent, _) = split_parent(&path);
                children.entry(parent.to_string()).or_default().push(path.clone());
            }
            index.insert(path, i);
        }
        for list in children.values_mut() {
            list.sort();
        }
        Ok(Image { fs, index, children })
    }

    fn node(&self, path: &str) -> Option<&ImageNode> {
        self.index.get(path).and_then(|&i| self.fs.root.nodes.get(i))
    }

    fn resolve(&self, path: &str) -> Option<&ImageNode> {
        let mut pending: Vec<String> = path.split('/').rev().map(String::from).collect();
        let mut current: Vec<String> = Vec::new();
        let mut hops = 0;
        while let Some(component) = pending.pop() {
            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    current.pop();
                    continue;
                }
                _ => current.push(component),
            }
            let node = self.node(&current.join("/"))?;
            if let InnerNode::Symlink(link) = &node.inner {
                hops += 1;
                if hops > 40 {
                    return None;
                }
                current.pop();
                let target = link.link.to_string_lossy();
                if target.starts_with('/') {
                    current.clear();
                }
                pending.extend(target.split('/').rev().map(String::from));
            }
        }
        self.node(&current.join("/"))
    }

    pub fn is_file(&self, path: &str) -> bool {
        self.resolve(path).is_some_and(|n| matches!(n.inner, InnerNode::File(_)))
    }

    pub fn list(&self, dir: &str) -> &[String] {
        self.children.get(dir).map_or(&[], Vec::as_slice)
    }

    pub fn walk_files(&self, dir: &str, out: &mut Vec<String>) {
        let entries = self.list(dir);
        out.extend(entries.iter().filter(|p| self.is_file(p)).cloned());
        for sub in entries {
            if matches!(self.node(sub).map(|n| &n.inner), Some(InnerNode::Dir(_))) {
                self.walk_files(sub, out);
            }
        }
    }

    pub fn read(&self, path: &str, limit: usize) -> Option<Vec<u8>> {
        let InnerNode::File(file) = &self.resolve(path)?.inner else { return None };
        if file.file_len() > limit {
            return None;
        }
        let mut data = Vec::with_capacity(file.file_len());
        self.fs.file(file).reader().take(limit as u64).read_to_end(&mut data).ok()?;
        Some(data)
    }
}

