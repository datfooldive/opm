use std::fs::File;
use std::os::unix::fs::FileExt;

use crate::appimage::trim_nul;

pub struct ElfInfo {
    pub appimage_type: i32,
    pub architecture: String,
    pub update_information: String,
    pub signature_status: String,
    pub payload_offset: Option<u64>,
}

fn native_arch(machine: u16) -> String {
    match machine {
        3 => "i386".into(),
        40 => "arm".into(),
        62 => "x86_64".into(),
        183 => "aarch64".into(),
        243 => "riscv64".into(),
        _ => format!("elf-machine-{machine}"),
    }
}

#[derive(Clone, Copy)]
struct Reader {
    big_endian: bool,
}

impl Reader {
    fn u16(self, b: &[u8]) -> u64 {
        let b = [b[0], b[1]];
        (if self.big_endian { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) }) as u64
    }

    fn u32(self, b: &[u8]) -> u64 {
        let b = b[..4].try_into().unwrap();
        (if self.big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }) as u64
    }

    fn u64(self, b: &[u8]) -> u64 {
        let b = b[..8].try_into().unwrap();
        if self.big_endian { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) }
    }
}

fn read_section(f: &File, offset: u64, size: u64, file_size: u64) -> Option<Vec<u8>> {
    if size == 0 || size > 1024 * 1024 || offset > file_size || size > file_size - offset {
        return None;
    }
    let mut data = vec![0; size as usize];
    f.read_exact_at(&mut data, offset).ok()?;
    Some(data)
}

pub fn inspect_elf(path: &str, file_size: u64) -> Option<ElfInfo> {
    let f = File::open(path).ok()?;
    let mut header = [0u8; 64];
    f.read_exact_at(&mut header, 0).ok()?;
    if &header[0..4] != b"\x7fELF" {
        return None;
    }
    if header[8] != b'A' || header[9] != b'I' || (header[10] != 1 && header[10] != 2) {
        return None;
    }
    let r = match header[5] {
        1 => Reader { big_endian: false },
        2 => Reader { big_endian: true },
        _ => return None,
    };
    let mut result = ElfInfo {
        appimage_type: header[10] as i32,
        architecture: native_arch(r.u16(&header[18..20]) as u16),
        update_information: String::new(),
        signature_status: "absent".into(),
        payload_offset: None,
    };

    if result.appimage_type == 1 {
        let mut buf = [0u8; 512];
        if let Ok(got) = f.read_at(&mut buf, 33651)
            && got > 0
        {
            result.update_information = trim_nul(&buf[..got]);
        }
        return Some(result);
    }

    let class = header[4];
    let (shoff, shentsize, shnum, shstrndx) = match class {
        2 => (r.u64(&header[40..48]), r.u16(&header[58..60]), r.u16(&header[60..62]), r.u16(&header[62..64])),
        1 => (r.u32(&header[32..36]), r.u16(&header[46..48]), r.u16(&header[48..50]), r.u16(&header[50..52])),
        _ => return Some(result),
    };
    if shnum == 0
        || shnum > 4096
        || shstrndx >= shnum
        || shentsize < 40
        || shoff > file_size
        || shnum * shentsize > file_size - shoff
    {
        return Some(result);
    }
    result.payload_offset = Some(shoff + shnum * shentsize);
    let Some(headers) = read_section(&f, shoff, shnum * shentsize, file_size) else {
        return Some(result);
    };
    let section = |i: u64| -> (u64, u64, u64) {
        let h = &headers[(i * shentsize) as usize..((i + 1) * shentsize) as usize];
        if class == 2 {
            (r.u32(&h[0..4]), r.u64(&h[24..32]), r.u64(&h[32..40]))
        } else {
            (r.u32(&h[0..4]), r.u32(&h[16..20]), r.u32(&h[20..24]))
        }
    };
    let (_, names_offset, names_size) = section(shstrndx);
    let Some(names) = read_section(&f, names_offset, names_size, file_size) else {
        return Some(result);
    };

    for i in 0..shnum {
        let (name_offset, offset, size) = section(i);
        if name_offset >= names.len() as u64 {
            continue;
        }
        let name = trim_nul(&names[name_offset as usize..]);
        if name != ".upd_info" && name != ".sha256_sig" {
            continue;
        }
        let Some(data) = read_section(&f, offset, size, file_size) else {
            continue;
        };
        if name == ".upd_info" {
            result.update_information = trim_nul(&data);
        } else if data.iter().any(|&c| c != 0) {
            result.signature_status = "present".into();
        }
    }
    Some(result)
}
