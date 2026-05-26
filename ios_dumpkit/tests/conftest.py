from __future__ import annotations

import plistlib
import struct
from pathlib import Path

import pytest

from ios_dumpkit.macho import LC_ENCRYPTION_INFO_64, LC_LOAD_DYLIB


def make_macho64(*, cryptid: int = 1, dylib: str | None = None, entitlements: bytes = b"") -> bytes:
    commands = bytearray()
    commands += struct.pack("<IIIIII", LC_ENCRYPTION_INFO_64, 24, 0x100, 0x20, cryptid, 0)
    if dylib:
        name = dylib.encode() + b"\x00"
        cmdsize = 24 + len(name)
        if cmdsize % 8:
            cmdsize += 8 - (cmdsize % 8)
        command = bytearray(struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 0, 0, 0))
        command += name
        command += b"\x00" * (cmdsize - len(command))
        commands += command
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        1 + (1 if dylib else 0),
        len(commands),
        0,
        0,
    )
    data = bytearray(header + commands)
    if len(data) < 0x120:
        data += b"\x00" * (0x120 - len(data))
    data[0x100:0x120] = b"A" * 0x20
    data += entitlements
    return bytes(data)


def make_fat_macho64(thin: bytes) -> bytes:
    offset = 0x100
    header = struct.pack(">IIiiIII", 0xCAFEBABE, 1, 0x0100000C, 0, offset, len(thin), 12)
    return header + (b"\x00" * (offset - len(header))) + thin


@pytest.fixture
def app_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "Example App.app"
    bundle.mkdir()
    info = {
        "CFBundleIdentifier": "com.example.app",
        "CFBundleDisplayName": "Example App",
        "CFBundleExecutable": "Example",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "456",
        "MinimumOSVersion": "15.0",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example", "example-auth"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False},
    }
    with (bundle / "Info.plist").open("wb") as handle:
        plistlib.dump(info, handle)
    entitlements = plistlib.dumps(
        {
            "keychain-access-groups": ["TEAM.com.example.app"],
            "com.apple.developer.associated-domains": ["applinks:example.com"],
            "com.apple.security.application-groups": ["group.com.example"],
        }
    )
    (bundle / "Example").write_bytes(
        make_macho64(cryptid=0, dylib="/usr/lib/libobjc.A.dylib", entitlements=entitlements)
    )
    return bundle
