from __future__ import annotations

import struct

from ios_dumpkit.macho import parse_macho, patch_cryptid

from .conftest import make_fat_macho64, make_macho64


def test_macho_cryptid_patching() -> None:
    original = make_macho64(cryptid=1)
    patched, changed = patch_cryptid(original)

    assert len(changed) == 1
    assert struct.unpack_from("<I", patched, changed[0].cryptid_file_offset)[0] == 0
    assert not parse_macho(patched).encrypted


def test_fat_macho_cryptid_patching() -> None:
    fat = make_fat_macho64(make_macho64(cryptid=1))
    patched, changed = patch_cryptid(fat)

    assert len(changed) == 1
    assert not parse_macho(patched).encrypted


def test_dylib_imports_are_extracted() -> None:
    analysis = parse_macho(
        make_macho64(cryptid=0, dylib="/System/Library/Frameworks/UIKit.framework/UIKit")
    )

    assert analysis.imported_dylibs == ["/System/Library/Frameworks/UIKit.framework/UIKit"]
