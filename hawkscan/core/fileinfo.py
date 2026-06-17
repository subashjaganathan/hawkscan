"""File identification: hashing and type detection by magic bytes.

Type detection here is deliberately self-contained (no python-magic / libmagic
dependency) so HawkScan runs anywhere with just the stdlib. It is good enough
to route a file to the right analyzer; deeper analyzers re-verify the format.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileInfo:
    path: Path
    size: int
    md5: str
    sha1: str
    sha256: str
    file_type: str            # coarse category, e.g. "pe", "elf", "pdf", "office-ooxml"
    description: str           # human label
    extension: str
    magic_hex: str             # first bytes as hex, for the report
    ext_mismatch: bool = False  # extension disagrees with detected type
    data: dict = field(default_factory=dict)


# (offset, magic_bytes, file_type, description)
_MAGIC_SIGNATURES: list[tuple[int, bytes, str, str]] = [
    (0, b"MZ", "pe", "Windows PE executable (EXE/DLL/SYS)"),
    (0, b"\x7fELF", "elf", "Linux/Unix ELF executable"),
    (0, b"\xfe\xed\xfa\xce", "macho", "Mach-O executable (32-bit BE)"),
    (0, b"\xfe\xed\xfa\xcf", "macho", "Mach-O executable (64-bit BE)"),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O executable (64-bit LE)"),
    (0, b"\xce\xfa\xed\xfe", "macho", "Mach-O executable (32-bit LE)"),
    (0, b"\xca\xfe\xba\xbe", "macho", "Mach-O universal/fat binary"),
    (0, b"%PDF", "pdf", "PDF document"),
    (0, b"PK\x03\x04", "zip", "ZIP archive (or OOXML/JAR/APK)"),
    (0, b"PK\x05\x06", "zip", "ZIP archive (empty)"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "OLE2 compound file (legacy Office/MSI)"),
    (0, b"Rar!\x1a\x07", "rar", "RAR archive"),
    (0, b"\x1f\x8b", "gzip", "GZIP compressed data"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (0, b"BZh", "bzip2", "BZIP2 compressed data"),
    (0, b"\xfd7zXZ\x00", "xz", "XZ compressed data"),
    (0, b"\x4d\x53\x43\x46", "cab", "Microsoft Cabinet archive"),
    (0, b"#!", "script", "Script with shebang"),
    (0, b"<?php", "script", "PHP script"),
    (0, b"\xff\xd8\xff", "image", "JPEG image"),
    (0, b"\x89PNG\r\n\x1a\n", "image", "PNG image"),
    (0, b"GIF8", "image", "GIF image"),
]

_SCRIPT_EXTS = {
    ".ps1": "PowerShell script",
    ".psm1": "PowerShell module",
    ".bat": "Windows batch script",
    ".cmd": "Windows batch script",
    ".vbs": "VBScript",
    ".vbe": "Encoded VBScript",
    ".js": "JavaScript",
    ".jse": "Encoded JScript",
    ".wsf": "Windows Script File",
    ".hta": "HTML Application",
    ".sh": "Shell script",
    ".py": "Python script",
    ".pl": "Perl script",
    ".rb": "Ruby script",
    ".lnk": "Windows shortcut",
}

# Categories each detected type is plausibly compatible with, for ext mismatch.
_EXT_TYPE_MAP: dict[str, set[str]] = {
    ".exe": {"pe"}, ".dll": {"pe"}, ".sys": {"pe"}, ".scr": {"pe"}, ".com": {"pe"},
    ".so": {"elf"}, ".elf": {"elf"}, ".bin": {"elf", "pe", "macho", "data"},
    ".pdf": {"pdf"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"}, ".docm": {"zip"},
    ".xlsm": {"zip"}, ".pptm": {"zip"}, ".jar": {"zip"}, ".apk": {"zip"},
    ".zip": {"zip"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msi": {"ole"},
    ".rar": {"rar"}, ".gz": {"gzip"}, ".7z": {"7z"}, ".cab": {"cab"},
    # Documents/images: should NOT be executables. Listing their benign types
    # means a PE/ELF/Mach-O wearing one of these extensions trips ext_mismatch.
    ".jpg": {"image"}, ".jpeg": {"image"}, ".png": {"image"}, ".gif": {"image"},
    ".txt": {"text"}, ".csv": {"text"}, ".log": {"text"}, ".json": {"text"},
    ".rtf": {"text", "ole"}, ".htm": {"text"}, ".html": {"text"},
}


def hash_file(path: Path, chunk_size: int = 1 << 20) -> tuple[str, str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head:
        return False
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(head) > 0.90


def detect_type(head: bytes, extension: str) -> tuple[str, str]:
    """Return (file_type, description) from magic bytes, with text fallback."""
    for offset, magic, ftype, desc in _MAGIC_SIGNATURES:
        if head[offset : offset + len(magic)] == magic:
            # 0xCAFEBABE is shared by Mach-O fat binaries AND Java .class files.
            # Disambiguate by extension (and Java's version word at offset 4-7).
            if ftype == "macho" and magic == b"\xca\xfe\xba\xbe":
                if extension == ".class":
                    return "java-class", "Java compiled class file"
            # OOXML/JAR/APK are ZIP under the hood; refine by extension.
            if ftype == "zip":
                if extension in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
                    return "office-ooxml", "Office Open XML document"
                if extension == ".apk":
                    return "apk", "Android application package"
                if extension == ".jar":
                    return "jar", "Java archive"
            return ftype, desc

    # No magic match: distinguish text/script from opaque data.
    if extension in _SCRIPT_EXTS:
        return "script", _SCRIPT_EXTS[extension]
    if _looks_like_text(head):
        return "text", "Plain text / source"
    return "data", "Unknown binary data"


def inspect(path: Path) -> FileInfo:
    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as fh:
        head = fh.read(4096)

    md5, sha1, sha256 = hash_file(path)
    extension = path.suffix.lower()
    file_type, description = detect_type(head, extension)

    # Extension/type disagreement is a classic masquerading signal.
    ext_mismatch = False
    if extension in _EXT_TYPE_MAP:
        compatible = _EXT_TYPE_MAP[extension]
        # office-ooxml/apk/jar all originate from zip magic.
        normalized = "zip" if file_type in {"office-ooxml", "apk", "jar"} else file_type
        if normalized not in compatible and file_type not in {"text", "data"}:
            ext_mismatch = True

    return FileInfo(
        path=path,
        size=size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        file_type=file_type,
        description=description,
        extension=extension,
        magic_hex=head[:16].hex(" "),
        ext_mismatch=ext_mismatch,
    )
