"""Mach-O and fat Mach-O parsing and cryptid patching."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .errors import MachOError

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = b"\xca\xfe\xba\xbe"
FAT_MAGIC_64 = b"\xca\xfe\xba\xbf"
FAT_CIGAM = b"\xbe\xba\xfe\xca"
FAT_CIGAM_64 = b"\xbf\xba\xfe\xca"

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_ID_DYLIB = 0xD
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

DYLIB_COMMANDS = {
    LC_ID_DYLIB,
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}


@dataclass(frozen=True, slots=True)
class MachOSlice:
    """A thin Mach-O slice within a file."""

    offset: int
    size: int
    cputype: int | None = None
    cpusubtype: int | None = None


@dataclass(frozen=True, slots=True)
class EncryptionCommand:
    """LC_ENCRYPTION_INFO or LC_ENCRYPTION_INFO_64 details."""

    slice_offset: int
    command_offset: int
    cryptoff: int
    cryptsize: int
    cryptid: int
    cryptid_file_offset: int
    command: int


@dataclass(frozen=True, slots=True)
class DylibRef:
    """Dylib load-command reference."""

    command: int
    name: str


@dataclass(frozen=True, slots=True)
class MachOAnalysis:
    """Parsed Mach-O summary."""

    is_macho: bool
    is_fat: bool = False
    slices: list[MachOSlice] = field(default_factory=list)
    encryption: list[EncryptionCommand] = field(default_factory=list)
    dylibs: list[DylibRef] = field(default_factory=list)

    @property
    def encrypted(self) -> bool:
        return any(cmd.cryptid != 0 for cmd in self.encryption)

    @property
    def imported_dylibs(self) -> list[str]:
        return [
            ref.name
            for ref in self.dylibs
            if ref.command in {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LOAD_UPWARD_DYLIB}
        ]

    @property
    def exported_dylibs(self) -> list[str]:
        return [ref.name for ref in self.dylibs if ref.command in {LC_ID_DYLIB, LC_REEXPORT_DYLIB}]


def _read_c_string(data: bytes | bytearray, offset: int, limit: int) -> str:
    if offset < 0 or offset >= limit:
        return ""
    end = offset
    while end < limit and data[end] != 0:
        end += 1
    return data[offset:end].decode("utf-8", errors="replace")


def _fat_slices(data: bytes | bytearray) -> list[MachOSlice] | None:
    magic = bytes(data[:4])
    if magic not in {FAT_MAGIC, FAT_MAGIC_64, FAT_CIGAM, FAT_CIGAM_64}:
        return None

    is_64 = magic in {FAT_MAGIC_64, FAT_CIGAM_64}
    endian = ">" if magic in {FAT_MAGIC, FAT_MAGIC_64} else "<"
    if len(data) < 8:
        raise MachOError("Fat Mach-O header is truncated.")
    nfat_arch = struct.unpack_from(f"{endian}I", data, 4)[0]
    entry_size = 32 if is_64 else 20
    header_size = 8 + (nfat_arch * entry_size)
    if header_size > len(data):
        raise MachOError("Fat Mach-O architecture table is truncated.")

    slices: list[MachOSlice] = []
    for index in range(nfat_arch):
        off = 8 + (index * entry_size)
        cputype, cpusubtype = struct.unpack_from(f"{endian}II", data, off)
        if is_64:
            slice_off, slice_size = struct.unpack_from(f"{endian}QQ", data, off + 8)
        else:
            slice_off, slice_size = struct.unpack_from(f"{endian}II", data, off + 8)
        if slice_off + slice_size > len(data):
            raise MachOError(
                f"Fat Mach-O slice {index} exceeds file bounds "
                f"({slice_off}+{slice_size}>{len(data)})."
            )
        slices.append(MachOSlice(slice_off, slice_size, cputype, cpusubtype))
    return slices


def _parse_thin(
    data: bytes | bytearray, macho_slice: MachOSlice
) -> tuple[list[EncryptionCommand], list[DylibRef]]:
    base = macho_slice.offset
    if base + 28 > len(data):
        raise MachOError("Mach-O header is truncated.")

    magic = struct.unpack_from("<I", data, base)[0]
    if magic in {MH_CIGAM, MH_CIGAM_64}:
        raise MachOError("Big-endian Mach-O slices are not supported.")
    if magic not in {MH_MAGIC, MH_MAGIC_64}:
        raise MachOError(f"Unsupported Mach-O magic at offset {base}: 0x{magic:08x}.")

    is_64 = magic == MH_MAGIC_64
    header_size = 32 if is_64 else 28
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, base + 20)[0]
    commands_start = base + header_size
    commands_end = commands_start + sizeofcmds
    if commands_end > base + macho_slice.size or commands_end > len(data):
        raise MachOError("Mach-O load-command region exceeds file bounds.")

    encryptions: list[EncryptionCommand] = []
    dylibs: list[DylibRef] = []
    cursor = commands_start
    for index in range(ncmds):
        if cursor + 8 > commands_end:
            raise MachOError(f"Load command {index} is truncated.")
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > commands_end:
            raise MachOError(f"Load command {index} has invalid size {cmdsize}.")

        if cmd in {LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64}:
            if cursor + 20 > commands_end:
                raise MachOError("LC_ENCRYPTION_INFO is truncated.")
            cryptoff, cryptsize, cryptid = struct.unpack_from("<III", data, cursor + 8)
            if cryptoff + cryptsize > macho_slice.size:
                raise MachOError("LC_ENCRYPTION_INFO encrypted range exceeds Mach-O slice bounds.")
            encryptions.append(
                EncryptionCommand(
                    slice_offset=base,
                    command_offset=cursor,
                    cryptoff=cryptoff,
                    cryptsize=cryptsize,
                    cryptid=cryptid,
                    cryptid_file_offset=cursor + 16,
                    command=cmd,
                )
            )

        if cmd in DYLIB_COMMANDS and cursor + 24 <= commands_end:
            name_offset = struct.unpack_from("<I", data, cursor + 8)[0]
            name = _read_c_string(data, cursor + name_offset, cursor + cmdsize)
            if name:
                dylibs.append(DylibRef(command=cmd, name=name))

        cursor += cmdsize

    return encryptions, dylibs


def parse_macho(data: bytes | bytearray) -> MachOAnalysis:
    """Parse a thin or fat Mach-O file."""

    if len(data) < 4:
        return MachOAnalysis(is_macho=False)

    slices = _fat_slices(data)
    is_fat = slices is not None
    if slices is None:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic not in {MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64}:
            return MachOAnalysis(is_macho=False)
        slices = [MachOSlice(0, len(data))]

    encryption: list[EncryptionCommand] = []
    dylibs: list[DylibRef] = []
    for macho_slice in slices:
        slice_encryption, slice_dylibs = _parse_thin(data, macho_slice)
        encryption.extend(slice_encryption)
        dylibs.extend(slice_dylibs)
    return MachOAnalysis(
        is_macho=True, is_fat=is_fat, slices=slices, encryption=encryption, dylibs=dylibs
    )


def patch_cryptid(data: bytes | bytearray) -> tuple[bytes, list[EncryptionCommand]]:
    """Return bytes with every Mach-O cryptid patched to 0."""

    patched = bytearray(data)
    analysis = parse_macho(patched)
    if not analysis.is_macho:
        raise MachOError("Input is not a Mach-O file.")
    changed: list[EncryptionCommand] = []
    for command in analysis.encryption:
        if command.cryptid != 0:
            struct.pack_into("<I", patched, command.cryptid_file_offset, 0)
            changed.append(command)
    return bytes(patched), changed


def patch_cryptid_file(path: Path) -> list[EncryptionCommand]:
    """Patch a Mach-O file in place and return the commands that changed."""

    original = path.read_bytes()
    patched, changed = patch_cryptid(original)
    if changed:
        path.write_bytes(patched)
    return changed


def analyse_file(path: Path) -> MachOAnalysis:
    """Parse a file if it is Mach-O."""

    return parse_macho(path.read_bytes())
