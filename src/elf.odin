#+build linux
package main

import "core:encoding/endian"
import "core:fmt"
import "core:os"

Elf_Info :: struct {
	appimage_type:      int,
	architecture:       string,
	update_information: string,
	signature_status:   string,
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
