from Registry import Registry
import sys
import struct
import binascii
from datetime import datetime


def filetime_to_dt(filetime):
    if filetime == 0:
        return "Never"
    try:
        return datetime.utcfromtimestamp(
            (filetime - 116444736000000000) / 10000000
        )
    except:
        return "Invalid Timestamp"


def parse_v_value(v_data):
    try:
        # ---- Username extraction (correct modern offsets) ----
        name_offset = struct.unpack("<I", v_data[0x0C:0x10])[0] + 0xCC
        name_length = struct.unpack("<I", v_data[0x10:0x14])[0]

        username = v_data[name_offset:name_offset + name_length].decode("utf-16le")

        # ---- LM hash ----
        lm_offset = struct.unpack("<I", v_data[0x9C:0xA0])[0] + 0xCC
        lm_length = struct.unpack("<I", v_data[0xA0:0xA4])[0]
        lm_hash = v_data[lm_offset:lm_offset + lm_length] if lm_length > 0 else b''

        # ---- NT hash ----
        nt_offset = struct.unpack("<I", v_data[0xA8:0xAC])[0] + 0xCC
        nt_length = struct.unpack("<I", v_data[0xAC:0xB0])[0]
        nt_hash = v_data[nt_offset:nt_offset + nt_length] if nt_length > 0 else b''

        return username, lm_hash, nt_hash

    except:
        return "UNKNOWN", b'', b''


def parse_f_value(f_data):
    try:
        last_logon = struct.unpack("<Q", f_data[8:16])[0]
        pwd_last_set = struct.unpack("<Q", f_data[24:32])[0]
        acct_flags = struct.unpack("<I", f_data[56:60])[0]
        return last_logon, pwd_last_set, acct_flags
    except:
        return 0, 0, 0


def decode_account_flags(flags):
    meanings = []

    if flags & 0x0001:
        meanings.append("Account Disabled")
    if flags & 0x0010:
        meanings.append("Password Not Required")
    if flags & 0x10000:
        meanings.append("Password Never Expires")
    if flags & 0x200:
        meanings.append("Account Locked")

    if not meanings:
        meanings.append("Normal Account")

    return ", ".join(meanings)


def dump_sam(sam_path):
    reg = Registry.Registry(sam_path)
    users_key = reg.open("SAM\\Domains\\Account\\Users")

    print("\n================ SAM FORENSIC REPORT ================\n")

    for rid_key in users_key.subkeys():

        if rid_key.name().upper() == "NAMES":
            continue

        rid_hex = rid_key.name()
        rid = int(rid_hex, 16)

        print(f"RID                 : {rid} (0x{rid_hex})")

        try:
            print(f"Key LastWrite Time  : {rid_key.timestamp()}")

            v_data = rid_key.value("V").value()
            username, lm_hash, nt_hash = parse_v_value(v_data)

            print(f"Username            : {username}")
            print(f"Encrypted LM Hash   : {binascii.hexlify(lm_hash).decode() if lm_hash else 'None'}")
            print(f"Encrypted NT Hash   : {binascii.hexlify(nt_hash).decode() if nt_hash else 'None'}")

            f_data = rid_key.value("F").value()
            last_logon, pwd_last_set, acct_flags = parse_f_value(f_data)

            print(f"Last Logon          : {filetime_to_dt(last_logon)}")
            print(f"Password Last Set   : {filetime_to_dt(pwd_last_set)}")
            print(f"Account Flags       : 0x{acct_flags:X}")
            print(f"Flag Meaning        : {decode_account_flags(acct_flags)}")

        except Exception as e:
            print(f"[!] Error reading user data: {e}")

        print("-" * 60)

    print("\n================ END OF REPORT ================\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <SAM file>")
        sys.exit(1)

    dump_sam(sys.argv[1])