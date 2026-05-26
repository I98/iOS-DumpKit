"""Best-effort readable analysis artifacts for dumped iOS bundles."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .macho import MachOAnalysis, MachOError, analyse_file

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
}
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
MAX_STRINGS_PER_FILE = 200_000


@dataclass(slots=True)
class BinaryArtifact:
    """Analysis artifact summary for one binary."""

    relative_path: str
    macho: bool
    encrypted: bool = False
    imported_dylibs: list[str] = field(default_factory=list)
    exported_dylibs: list[str] = field(default_factory=list)
    strings_path: str | None = None
    macho_json_path: str | None = None
    symbols_path: str | None = None
    disassembly_path: str | None = None
    warning: str | None = None


def _safe_artifact_name(relative_path: str, suffix: str) -> str:
    safe = relative_path.replace("/", "__").replace(" ", "_")
    safe = re.sub(r"[^A-Za-z0-9_.@+-]", "_", safe)
    return f"{safe}{suffix}"


def _is_macho_file(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] in MACHO_MAGICS
    except OSError:
        return False


def _binary_paths(bundle_path: Path) -> list[Path]:
    return sorted(
        path for path in bundle_path.rglob("*") if path.is_file() and _is_macho_file(path)
    )


def _extract_ascii_strings(path: Path) -> list[str]:
    data = path.read_bytes()
    strings = [
        match.group().decode("utf-8", errors="replace") for match in PRINTABLE_RE.finditer(data)
    ]
    return strings[:MAX_STRINGS_PER_FILE]


def _analysis_to_json(analysis: MachOAnalysis) -> dict[str, Any]:
    return {
        "is_macho": analysis.is_macho,
        "is_fat": analysis.is_fat,
        "encrypted": analysis.encrypted,
        "slices": [asdict(item) for item in analysis.slices],
        "encryption": [asdict(item) for item in analysis.encryption],
        "imported_dylibs": analysis.imported_dylibs,
        "exported_dylibs": analysis.exported_dylibs,
    }


def _run_optional_tool(command: list[str], output_path: Path, timeout: float = 30.0) -> bool:
    if not shutil.which(command[0]):
        return False
    if output_path.exists():
        output_path.unlink()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return False
    if result.returncode != 0:
        return False
    output = result.stdout.strip()
    if not output.strip():
        return False
    if "ERROR: Missing bin header" in output:
        return False
    output_path.write_text(output + "\n", encoding="utf-8", errors="replace")
    return True


def _write_optional_symbols(binary: Path, destination: Path) -> Path | None:
    tools = [
        ["llvm-nm", "-m", str(binary)],
        ["llvm-nm", str(binary)],
        ["rabin2", "-s", str(binary)],
        ["nm", str(binary)],
    ]
    for command in tools:
        if _run_optional_tool(command, destination):
            return destination
    return None


def _write_optional_disassembly(binary: Path, destination: Path) -> Path | None:
    tools = [
        ["llvm-objdump", "--macho", "--demangle", "--disassemble", str(binary)],
        ["llvm-objdump", "--disassemble", str(binary)],
        ["rabin2", "-d", str(binary)],
    ]
    for command in tools:
        if _run_optional_tool(command, destination, timeout=120.0):
            return destination
    return None


def write_static_analysis_artifacts(bundle_path: Path, output_dir: Path) -> list[BinaryArtifact]:
    """Write strings, Mach-O summaries, and optional symbol/disassembly artifacts."""

    analysis_dir = output_dir / "analysis"
    macho_dir = analysis_dir / "macho"
    strings_dir = analysis_dir / "strings"
    symbols_dir = analysis_dir / "symbols"
    disassembly_dir = analysis_dir / "disassembly"
    for directory in (macho_dir, strings_dir, symbols_dir, disassembly_dir):
        directory.mkdir(parents=True, exist_ok=True)

    artifacts: list[BinaryArtifact] = []
    for binary in _binary_paths(bundle_path):
        relative = binary.relative_to(bundle_path).as_posix()
        artifact = BinaryArtifact(relative_path=relative, macho=True)
        try:
            analysis = analyse_file(binary)
            artifact.encrypted = analysis.encrypted
            artifact.imported_dylibs = analysis.imported_dylibs
            artifact.exported_dylibs = analysis.exported_dylibs

            macho_json = macho_dir / _safe_artifact_name(relative, ".macho.json")
            macho_json.write_text(
                json.dumps(_analysis_to_json(analysis), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            artifact.macho_json_path = macho_json.relative_to(output_dir).as_posix()

            strings_path = strings_dir / _safe_artifact_name(relative, ".strings.txt")
            strings_path.write_text(
                "\n".join(_extract_ascii_strings(binary)) + "\n",
                encoding="utf-8",
                errors="replace",
            )
            artifact.strings_path = strings_path.relative_to(output_dir).as_posix()

            symbols_path = symbols_dir / _safe_artifact_name(relative, ".symbols.txt")
            if _write_optional_symbols(binary, symbols_path):
                artifact.symbols_path = symbols_path.relative_to(output_dir).as_posix()

            disassembly_path = disassembly_dir / _safe_artifact_name(relative, ".disasm.txt")
            if _write_optional_disassembly(binary, disassembly_path):
                artifact.disassembly_path = disassembly_path.relative_to(output_dir).as_posix()
        except (MachOError, OSError) as exc:
            artifact.warning = str(exc)
        artifacts.append(artifact)

    manifest = analysis_dir / "manifest.json"
    manifest.write_text(
        json.dumps([asdict(item) for item in artifacts], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return artifacts


def _method_line(method: str) -> str:
    text = method.strip()
    if not text:
        return ""
    if text.endswith(";"):
        return text
    return f"{text};"


def _safe_header_name(class_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.$+-]", "_", class_name) + ".h"


def _header_for_class(payload: dict[str, Any]) -> str:
    class_name = str(payload.get("name") or "UnknownClass")
    superclass = str(payload.get("superclass") or "NSObject")
    protocols = [str(item) for item in payload.get("protocols", []) if item]
    suffix = f" <{', '.join(protocols)}>" if protocols else ""
    lines = [
        "// Generated by ios-dumpkit-ng from Objective-C runtime metadata.",
        "// This is an interface reconstruction, not original source code.",
        "",
        f"@interface {class_name} : {superclass}{suffix}",
    ]
    methods = [_method_line(str(item)) for item in payload.get("methods", [])]
    methods = [item for item in methods if item]
    if methods:
        lines.extend(methods)
    lines.append("@end")
    lines.append("")
    return "\n".join(lines)


def write_objc_runtime_artifacts(payload: dict[str, Any], output_dir: Path) -> int:
    """Write Objective-C runtime class metadata and reconstructed headers."""

    objc_dir = output_dir / "analysis" / "objc"
    headers_dir = objc_dir / "headers"
    headers_dir.mkdir(parents=True, exist_ok=True)

    classes = list(payload.get("classes") or [])
    (objc_dir / "objc_classes.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for item in classes:
        if not isinstance(item, dict):
            continue
        class_name = str(item.get("name") or "UnknownClass")
        (headers_dir / _safe_header_name(class_name)).write_text(
            _header_for_class(item),
            encoding="utf-8",
        )
    return len(classes)
