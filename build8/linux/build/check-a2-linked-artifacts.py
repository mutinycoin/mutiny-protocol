#!/usr/bin/env python3
"""Linked EXE/PDB A2 TEST producer exclusion; graph/provenance remain separate."""
import pathlib
import stat
import sys

sys.dont_write_bytecode = True
MARKERS = (
    "generate_protected_local_synthetic_a2_native_fixture",
    "BUILD8_A2_LOCAL_SOFTWARE_FIXTURE",
    "PUBLIC TEST VALUE A2 ONLY",
    "MUTINY-BUILD8-PUBLIC-A2-NATIVE-LIFECYCLE-V1",
    "LOCAL SYNTHETIC A2 fixture created",
    "local_synthetic_fixture_generator",
)


def inspect(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ValueError("artifact must be a regular non-reparse file")
    patterns = [(label, encoding, label.encode(encoding))
                for label in MARKERS for encoding in ("ascii", "utf-16le")]
    overlap = max(len(pattern) for _, _, pattern in patterns) - 1
    found = set()
    with path.open("rb") as stream:
        opened = __import__("os").fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError("artifact changed during open")
        tail = b""
        while block := stream.read(4 * 1024 * 1024):
            content = tail + block
            for label, encoding, pattern in patterns:
                if pattern in content:
                    found.add((label, encoding))
            tail = content[-overlap:]
        after_open = __import__("os").fstat(stream.fileno())
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after_open) or identity(before) != identity(after):
        raise ValueError("artifact changed during scan")
    if not stat.S_ISREG(after.st_mode) or getattr(after, "st_file_attributes", 0) & 0x400:
        raise ValueError("artifact replaced by nonregular/reparse file")
    return sorted(found)


def main():
    if len(sys.argv) < 2:
        print("FAIL A2 artifact input required")
        return 1
    failed = False
    for arg in sys.argv[1:]:
        path = pathlib.Path(arg)
        try:
            found = inspect(path)
        except (OSError, ValueError) as error:
            print(f"FAIL A2 artifact {path.name}: {error}")
            failed = True
            continue
        for label, encoding in found:
            print(f"FAIL A2 artifact {path.name}: forbidden complete {encoding} marker {label}")
        failed |= bool(found)
        if not found:
            print(f"PASS A2 linked-artifact markers absent: {path.name}")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
