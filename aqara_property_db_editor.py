#!/usr/bin/env python3
"""
pbl_dat_dump.py - Python version of pbl_dat_dump utility
Dumps data from PBL database files
"""

import argparse
import os
import struct
import sys
import tempfile
import ctypes
from ctypes import c_char_p, c_int, c_void_p, c_char, c_size_t, c_long, byref, create_string_buffer

# Load the PBL library
try:
    pbl_lib = ctypes.CDLL("./libpbl.so")
except OSError:
    print("Error: Could not load PBL library. Make sure libpbl.so is in the current directory.", file=sys.stderr)
    sys.exit(1)

# Constants from the C program
PBLKEYLENGTH = 255  # Assuming this value, check actual value in pbl.h
PROPERTY_MAGIC_BYTE = 0xFF
PROPERTY_DB_BUFSIZ = 4096
PARTITION_MAGIC = b"ft1d"

# AES key and IV for decryption
AES_KEY = b"oeUQdaDUw4i98shj"
AES_IV  = bytes([0x43, 0x67, 0x31, 0x88, 0xAF, 0xBC, 0xA5, 0x77,
                 0x56, 0x2E, 0x17, 0x99, 0x6D, 0x09, 0x3D, 0x28])

# PBL constants for iteration
PBLFIRST = 1
PBLNEXT = 2
PBL_ERROR_NOT_FOUND = 1

# Setup error handling
pbl_errno = c_int.in_dll(pbl_lib, "pbl_errno")
pbl_errstr = c_char_p.in_dll(pbl_lib, "pbl_errstr")

# Define function signatures
pbl_lib.pblKfOpen.argtypes = [c_char_p, c_int, c_void_p]
pbl_lib.pblKfOpen.restype = c_void_p

pbl_lib.pblKfClose.argtypes = [c_void_p]
pbl_lib.pblKfClose.restype = c_int

pbl_lib.pblKfGetAbs.argtypes = [c_void_p, c_long,
                                c_void_p, ctypes.POINTER(c_size_t)]
pbl_lib.pblKfGetAbs.restype = c_long

pbl_lib.pblKfGetRel.argtypes = [c_void_p, c_long,
                                c_void_p, ctypes.POINTER(c_size_t)]
pbl_lib.pblKfGetRel.restype = c_long

pbl_lib.pblKfRead.argtypes = [c_void_p, c_void_p, c_long]
pbl_lib.pblKfRead.restype = c_long

pbl_lib.pblIsamOpen.argtypes = [c_char_p, c_int, c_void_p, c_int, ctypes.POINTER(c_char_p), ctypes.POINTER(c_int)]
pbl_lib.pblIsamOpen.restype = c_void_p

pbl_lib.pblIsamClose.argtypes = [c_void_p]
pbl_lib.pblIsamClose.restype = c_int

pbl_lib.pblIsamGet.argtypes = [c_void_p, c_int, c_int, c_void_p]
pbl_lib.pblIsamGet.restype = c_int

pbl_lib.pblIsamReadKey.argtypes = [c_void_p, c_int, c_void_p]
pbl_lib.pblIsamReadKey.restype = c_int

pbl_lib.pblIsamReadDatalen.argtypes = [c_void_p]
pbl_lib.pblIsamReadDatalen.restype = c_long

pbl_lib.pblIsamReadData.argtypes = [c_void_p, c_void_p, c_long]
pbl_lib.pblIsamReadData.restype = c_long

def print_help():
    """Print usage help message"""
    print("Usage: pbl_dat_dump.py [options] <filename>")
    print("Options:")
    print("  -k             (Aqara M2 Hub) Treat file as a PBL key file")
    # print("  -i             Treat file as a PBL ISAM file")
    print("  -p             (Aqara M3 Hub) Treat file as a property database file")
    print("  -r             (Aqara M3 Hub) Treat file as a raw partition image containing the database")
    print("  -h             Show this help")

def format_byte_display(byte_data, max_length=32):
    """Format byte data for display, showing printable chars and hex for others"""
    result = ""
    for i in range(min(len(byte_data), max_length)):
        if 32 <= byte_data[i] <= 126:
            result += chr(byte_data[i])
        else:
            result += f"\\x{byte_data[i]:02x}"
    
    if len(byte_data) > max_length:
        result += "..."
    
    return result

def kf_first(kf_handle):
    key_buf = create_string_buffer(PBLKEYLENGTH)
    key_len = c_size_t(PBLKEYLENGTH)
    data_len = pbl_lib.pblKfGetAbs(kf_handle, 0, key_buf, byref(key_len))
    return data_len, bytes(key_buf[:key_len.value])

def kf_next(kf_handle):
    key_buf = create_string_buffer(PBLKEYLENGTH)
    key_len = c_size_t(PBLKEYLENGTH)
    data_len = pbl_lib.pblKfGetRel(kf_handle, 1, key_buf, byref(key_len))
    return data_len, bytes(key_buf[:key_len.value])

def kf_prev(kf_handle):
    key_buf = create_string_buffer(PBLKEYLENGTH)
    key_len = c_size_t(PBLKEYLENGTH)
    data_len = pbl_lib.pblKfGetRel(kf_handle, -1, key_buf, byref(key_len))
    return data_len, bytes(key_buf[:key_len.value])


def dump_keyfile(filename):
    """Dump content of a PBL key file"""
    # Open key file
    kf = pbl_lib.pblKfOpen(filename.encode('utf-8'), 0, None)
    if not kf:
        print(f"Error opening key file: {pbl_errstr.value.decode()}", file=sys.stderr)
        return
    
    print(f"# PBL Key File: {filename}")
    print("# %-20s | %-8s | %s" % ("Key", "Data Len", "Data (first 32 bytes)"))
    print("# %s" % ("------------------------------------------------------------"))
    
    # Create buffer for key
    key_buffer = create_string_buffer(PBLKEYLENGTH)
    keylen = c_size_t(PBLKEYLENGTH)
    
    # Get first record
    datalen = pbl_lib.pblKfGetAbs(kf, key_buffer, byref(keylen))
    if datalen < 0:
        if pbl_errno.value == PBL_ERROR_NOT_FOUND:
            print("# File is empty")
        else:
            print(f"Error getting first record: {pbl_errstr.value.decode()}", file=sys.stderr)
        pbl_lib.pblKfClose(kf)
        return
    
    # Iterate through records
    while datalen >= 0:
        # Get key data as bytes
        key_bytes = bytes(key_buffer[:keylen.value])
        
        # Format key for display (up to 20 chars)
        key_str = format_byte_display(key_bytes, 20).ljust(20)
        
        print(f"  {key_str} | {datalen:8d} | ", end='')
        
        # Read and display data
        if datalen > 0:
            data_buffer = create_string_buffer(datalen)
            if pbl_lib.pblKfRead(kf, data_buffer, datalen) != datalen:
                print(f"Error reading data: {pbl_errstr.value.decode()}", file=sys.stderr)
                break
            
            data_bytes = bytes(data_buffer)
            data_str = format_byte_display(data_bytes)
            print(data_str)
        else:
            print()
        
        # Get next record
        keylen = c_size_t(PBLKEYLENGTH)
        datalen = pbl_lib.pblKfGetRel(kf, key_buffer, byref(keylen))
    
    if pbl_errno.value != PBL_ERROR_NOT_FOUND:
        print(f"Error during iteration: {pbl_errstr.value.decode()}", file=sys.stderr)
    
    pbl_lib.pblKfClose(kf)

def dump_isamfile(filename):
    """Dump content of a PBL ISAM file"""
    # Default index file name
    keyfilenames = (c_char_p * 1)(b"index0")
    keydup = (c_int * 1)(1)  # Allow duplicate keys
    
    # Open ISAM file
    isam = pbl_lib.pblIsamOpen(filename.encode('utf-8'), 0, None, 1, keyfilenames, keydup)
    if not isam:
        print(f"Error opening ISAM file: {pbl_errstr.value.decode()}", file=sys.stderr)
        return
    
    print(f"# PBL ISAM File: {filename}")
    print("# %-20s | %-8s | %s" % ("Key (Index 0)", "Data Len", "Data (first 32 bytes)"))
    print("# %s" % ("------------------------------------------------------------"))
    
    # Create buffer for key
    key_buffer = create_string_buffer(PBLKEYLENGTH)
    
    # Get first record
    if pbl_lib.pblIsamGet(isam, PBLFIRST, 0, key_buffer) < 0:
        if pbl_errno.value == PBL_ERROR_NOT_FOUND:
            print("# File is empty")
        else:
            print(f"Error getting first record: {pbl_errstr.value.decode()}", file=sys.stderr)
        pbl_lib.pblIsamClose(isam)
        return
    
    # Iterate through records
    while True:
        # Read the key for index 0
        if pbl_lib.pblIsamReadKey(isam, 0, key_buffer) < 0:
            print(f"Error reading key: {pbl_errstr.value.decode()}", file=sys.stderr)
            break
        
        # Format key for display
        key_str = ""
        i = 0
        while i < 20 and key_buffer[i] != 0:
            if 32 <= key_buffer[i] <= 126:
                key_str += chr(key_buffer[i])
            else:
                key_str += f"\\x{key_buffer[i]:02x}"
            i += 1
        
        key_str = key_str.ljust(20)
        
        # Get data length
        datalen = pbl_lib.pblIsamReadDatalen(isam)
        if datalen < 0:
            print(f"Error getting data length: {pbl_errstr.value.decode()}", file=sys.stderr)
            break
        
        print(f"  {key_str} | {datalen:8d} | ", end='')
        
        # Read and display data
        if datalen > 0:
            data_buffer = create_string_buffer(datalen)
            if pbl_lib.pblIsamReadData(isam, data_buffer, datalen) != datalen:
                print(f"Error reading data: {pbl_errstr.value.decode()}", file=sys.stderr)
                continue
            
            data_bytes = bytes(data_buffer)
            data_str = format_byte_display(data_bytes)
            print(data_str)
        else:
            print()
        
        # Get next record
        if pbl_lib.pblIsamGet(isam, PBLNEXT, 0, key_buffer) < 0:
            if pbl_errno.value != PBL_ERROR_NOT_FOUND:
                print(f"Error during iteration: {pbl_errstr.value.decode()}", file=sys.stderr)
            break
    
    pbl_lib.pblIsamClose(isam)

from Crypto.Cipher import AES

def aes128_cbc_decrypt(data, key, iv):
    """Decrypt data using AES-128-CBC, removing PKCS#7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    pad_len = decrypted[-1]
    if pad_len > 16:
        return decrypted  # fallback: don't strip if looks wrong
    return decrypted[:-pad_len]

def custom_dump_propertydb(filename):
    """Custom parser for property database file with AES-128-CBC encrypted keys/values."""
    key = b"oeUQdaDUw4i98shj"
    iv = bytes([0x43, 0x67, 0x31, 0x88, 0xAF, 0xBC, 0xA5, 0x77, 0x56, 0x2E, 0x17, 0x99, 0x6D, 0x09, 0x3D, 0x28])
    with open(filename, "rb") as f:
        data = f.read()
    # (Debug hex/ASCII dump removed for cleaner output)

    # Try to decrypt the first 32 and 64 bytes after the header as a block
    from binascii import hexlify
    for n in (32, 48, 64):
        if len(data) >= 32 + n:
            enc_block = data[32:32+n]
            if len(enc_block) % 16 == 0:
                try:
                    dec_block = aes128_cbc_decrypt(enc_block, key, iv)
                    # print(f"# Decrypting first {n} bytes after header (hex): {hexlify(dec_block).decode()}")
                    # print(f"# Decrypting first {n} bytes after header (ASCII): {''.join(chr(b) if 32 <= b <= 126 else '.' for b in dec_block)}")
                    pass
                except Exception as e:
                    # print(f"# Decrypt error for first {n} bytes after header: {e}")
                    pass
            else:
                # print(f"# Skipping decryption for first {n} bytes (not multiple of 16)")
                pass
    # Heuristic: skip header (first 32 bytes), then try to parse records
    offset = 32
    print(f"# Custom Property Service Database: {filename}")
    print("# %-32s | %-8s | %s" % ("Property Name", "Value Len", "Property Value"))
    print("# %s" % ("-" * 80))
    while offset + 4 < len(data):
        # Try to parse a record: [key_len(2)][val_len(2)][key][val]
        key_len = int.from_bytes(data[offset:offset+2], "little")
        val_len = int.from_bytes(data[offset+2:offset+4], "little")
        offset += 4
        if key_len == 0 or val_len == 0 or offset + key_len + val_len > len(data):
            break
        enc_key = data[offset:offset+key_len]
        offset += key_len
        enc_val = data[offset:offset+val_len]
        offset += val_len
        try:
            dec_key = aes128_cbc_decrypt(enc_key, key, iv).decode(errors="replace")
        except Exception as e:
            dec_key = f"<decrypt error: {e}>"
        try:
            dec_val = aes128_cbc_decrypt(enc_val, key, iv).decode(errors="replace")
        except Exception as e:
            dec_val = f"<decrypt error: {e}>"
        print(f"  {dec_key:32} | {len(dec_val):8d} | {dec_val}")
    print("# End of custom dump.\n")

def dump_propertydb(db_path):
    kf = pbl_lib.pblKfOpen(db_path.encode('utf-8'), 1, None)
    if not kf:
        raise RuntimeError(pbl_errstr.value.decode())

    # position to the first *real* record (skip the 0xFF header slot)
    data_len, enc_key = kf_first(kf)
    if len(enc_key) == 1 and enc_key[0] == PROPERTY_MAGIC_BYTE:
        data_len, enc_key = kf_next(kf)

    while data_len >= 0:
        # pull encrypted value blob
        if data_len > 0:
            val_buf = create_string_buffer(data_len)
            if pbl_lib.pblKfRead(kf, val_buf, data_len) != data_len:
                raise RuntimeError(pbl_errstr.value.decode())
            enc_val = bytes(val_buf)
        else:
            enc_val = b""

        # decrypt key & value
        dec_key = aes128_cbc_decrypt(enc_key, AES_KEY, AES_IV)
        dec_val = aes128_cbc_decrypt(enc_val, AES_KEY, AES_IV) if enc_val else b""

        print(f"{dec_key.decode(errors='replace'):32} | {len(dec_val):6} | "
              f"{dec_val.decode(errors='replace')}")

        # advance to next record
        data_len, enc_key = kf_next(kf)

    pbl_lib.pblKfClose(kf)

def dump_raw_partition(filename):
    """Extract and dump property database from a raw partition image"""
    try:
        with open(filename, 'rb') as fp:
            # Read the 10-byte partition 
            header = fp.read(10)
            if len(header) != 10:
                print("Error reading header", file=sys.stderr)
                return
            
            # Check for the magic "ft1d" string
            if header[:4] != PARTITION_MAGIC:
                print(f"Not a valid partition image. Expected magic '{PARTITION_MAGIC.decode()}'.", file=sys.stderr)
                return
            
            # Extract database size from bytes 4-8 (little-endian uint32)
            db_size = struct.unpack("<I", header[4:8])[0]
            print(f"# Partition image: {filename}")
            print(f"# Database size: {db_size} bytes")
            
            if db_size == 0 or db_size > 10000000:  # Sanity check - 10MB limit
                print(f"Invalid database size: {db_size}", file=sys.stderr)
                return
            
            # Read only atabase content (excluding the header)
            db_content = fp.read(db_size)
            if len(db_content) != db_size:
                print("Error reading database content", file=sys.stderr)
                return

            # (Debug hex/ASCII dump removed for cleaner output)

            # Debug: Search for the magic string "1.00 Peter's B Tree" in the entire file
            magic = b"1.00 Peter's B Tree"
            found_any = False
            first_magic_offset = None
            start = 0
            while True:
                idx = db_content.find(magic, start)
                if idx == -1:
                    break
                print(f"# Found PBL magic string at offset {idx}: {db_content[idx:idx+len(magic)].decode(errors='replace')}")
                if first_magic_offset is None:
                    first_magic_offset = idx
                found_any = True
                start = idx + 1
            if not found_any:
                print("# PBL magic string not found in extracted database content.")

            # Brute-force: Try offsets around the magic string to find a valid PBL database
            if first_magic_offset is not None:
                found = False
                for offset in range(max(0, first_magic_offset - 65536), first_magic_offset + 65536):
                    db_content_for_propertydb = db_content[offset:]
                    fd, temp_db_file = tempfile.mkstemp()
                    try:
                        os.write(fd, db_content_for_propertydb)
                        os.close(fd)

                        # Try to open with pblKfOpen
                        kf = pbl_lib.pblKfOpen(temp_db_file.encode('utf-8'), 1, None)
                        if not kf:
                            kf = pbl_lib.pblKfOpen(temp_db_file.encode('utf-8'), 0, None)
                        if kf:
                            print(f"# SUCCESS: Opened property database at offset {offset}")
                            # print("# First 256 bytes of property database file (hex):")
                            # print(" ".join(f"{b:02x}" for b in db_content_for_propertydb[:256]))
                            # print("# First 256 bytes of property database file (ASCII):")
                            # print("".join(chr(b) if 32 <= b <= 126 else "." for b in db_content_for_propertydb[:256]))
                            pbl_lib.pblKfClose(kf)
                            # print(f"# Extracted database to temporary file: {temp_db_file}")
                            dump_propertydb(temp_db_file)
                            found = True
                            break
                    finally:
                        try:
                            os.unlink(temp_db_file)
                        except:
                            pass
                if not found:
                    print("# Brute-force search failed: Could not open property database at any tested offset.")
            else:
                # Fallback: try the whole content
                db_content_for_propertydb = db_content
                fd, temp_db_file = tempfile.mkstemp()
                try:
                    os.write(fd, db_content_for_propertydb)
                    os.close(fd)
                    # print("# First 256 bytes of property database file (hex):")
                    # print(" ".join(f"{b:02x}" for b in db_content_for_propertydb[:256]))
                    # print("# First 256 bytes of property database file (ASCII):")
                    # print("".join(chr(b) if 32 <= b <= 126 else "." for b in db_content_for_propertydb[:256]))
                    # print(f"# Extracted database to temporary file: {temp_db_file}")
                    dump_propertydb(temp_db_file)
                finally:
                    try:
                        os.unlink(temp_db_file)
                    except:
                        pass
    except Exception as e:
        print(f"Error processing file: {e}", file=sys.stderr)

def check_is_propertydb(filename):
    """Check if file is a property database"""
    # Open with the same flags that property_service uses
    kf = pbl_lib.pblKfOpen(filename.encode('utf-8'), 1, None)  # 1 = read-only mode
    if not kf:
        kf = pbl_lib.pblKfOpen(filename.encode('utf-8'), 0, None)
        if not kf:
            return False  # Can't open file as key file
    
    key_buffer = create_string_buffer(PBLKEYLENGTH)
    keylen = c_size_t(PBLKEYLENGTH)
    datalen = pbl_lib.pblKfGetAbs(kf, key_buffer, byref(keylen))
    
    is_propertydb = False
    if datalen >= 0 and keylen.value > 0 and key_buffer[0] == PROPERTY_MAGIC_BYTE:
        is_propertydb = True  # First record has the magic byte
    
    pbl_lib.pblKfClose(kf)
    return is_propertydb

def check_is_raw_partition(filename):
    """Check if file is a raw partition image"""
    try:
        with open(filename, 'rb') as fp:
            header = fp.read(4)
            return header == PARTITION_MAGIC
    except:
        return False

def main():
    """Main function to parse arguments and call appropriate dump function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Dump PBL database files', add_help=False)
    parser.add_argument('-k', action='store_true', help='Treat file as a PBL key file')
    parser.add_argument('-i', action='store_true', help='Treat file as a PBL ISAM file')
    parser.add_argument('-p', action='store_true', help='Treat file as a property database file')
    parser.add_argument('-r', action='store_true', help='Treat file as a raw partition image')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help')
    parser.add_argument('filename', nargs='?', help='File to dump')
    
    args = parser.parse_args()
    
    if args.help:
        print_help()
        return 0
    
    if not args.filename:
        print("No filename specified", file=sys.stderr)
        print_help()
        return 1
    
    is_keyfile = args.k
    is_isamfile = args.i
    is_propertydb = args.p
    is_raw_partition = args.r
    filename = args.filename
    
    # If no file type is specified, try to auto-detect
    if not any([is_keyfile, is_isamfile, is_propertydb, is_raw_partition]):
        # First check if it's a raw partition image
        if check_is_raw_partition(filename):
            is_raw_partition = True
        # Then try to detect if it's a property database
        elif check_is_propertydb(filename):
            is_propertydb = True
        else:
            # Try key file
            kf = pbl_lib.pblKfOpen(filename.encode('utf-8'), 0, None)
            if kf:
                pbl_lib.pblKfClose(kf)
                is_keyfile = True
            else:
                # Try ISAM file
                keyfilenames = (c_char_p * 1)(b"index0")
                keydup = (c_int * 1)(1)
                isam = pbl_lib.pblIsamOpen(filename.encode('utf-8'), 0, None, 0, None, None)
                if isam:
                    pbl_lib.pblIsamClose(isam)
                    is_isamfile = True
        
        if not any([is_keyfile, is_isamfile, is_propertydb, is_raw_partition]):
            print("Could not determine file type. Use -k, -i, -p, or -r to specify.", file=sys.stderr)
            return 1
    
    # Call the appropriate dump function
    if is_raw_partition:
        dump_raw_partition(filename)
    elif is_propertydb:
        dump_propertydb(filename)
    elif is_keyfile:
        dump_keyfile(filename)
    else:
        dump_isamfile(filename)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
