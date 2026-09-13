#!/usr/bin/env python3
# extract_keys.py — Extract trigger key table from XD07 1.06 updater
# Usage: python extract_keys.py <updater.exe>

import sys
import struct
import os

if len(sys.argv) < 2:
    print("Usage: python extract_keys.py <updater.exe>")
    print("Example: python extract_keys.py BDR-XD07BKXL_106.exe")
    sys.exit(1)

fname = sys.argv[1]
if not os.path.exists(fname):
    print(f"File not found: {fname}")
    sys.exit(1)

with open(fname, 'rb') as f:
    data = f.read()

print(f"File: {fname}")
print(f"Size: {len(data)} bytes (0x{len(data):X})")
print()

# Image base is 0x400000
# dword_5D4B38 is at VA 0x5D4B38
# File offset = VA - image_base = 0x5D4B38 - 0x400000 = 0x1D4B38
IMAGE_BASE  = 0x400000
TABLE_VA    = 0x5D4B38
TABLE_OFF   = TABLE_VA - IMAGE_BASE

# Also extract dword_5D40B0 directly
KEY_VA      = 0x5D40B0
KEY_OFF     = KEY_VA - IMAGE_BASE

# And the dword_5D4B38 table — read 16 entries (64 bytes)
print(f"=== Trigger key table at file offset 0x{TABLE_OFF:X} ===")
print(f"    (VA 0x{TABLE_VA:X} = dword_5D4B38[drive_index*4])")
print()

if TABLE_OFF + 64 > len(data):
    print("ERROR: Table offset exceeds file size!")
    print(f"  Table offset: 0x{TABLE_OFF:X}")
    print(f"  File size:    0x{len(data):X}")
else:
    for i in range(16):
        off = TABLE_OFF + i * 4
        key = struct.unpack_from('<I', data, off)[0]
        print(f"  Drive index {i:2d}: key = 0x{key:08X}  (bytes: {data[off]:02X} {data[off+1]:02X} {data[off+2]:02X} {data[off+3]:02X})")

print()
print(f"=== Raw bytes at table offset 0x{TABLE_OFF:X} ===")
chunk = data[TABLE_OFF:TABLE_OFF+64]
for i in range(0, len(chunk), 16):
    hex_str = ' '.join(f'{b:02X}' for b in chunk[i:i+16])
    print(f"  {TABLE_OFF+i:08X}: {hex_str}")

print()
print("=== Also checking dword_5D4B38 surrounding area ===")
# Check +/- 0x100 bytes around table for context
ctx_off = max(0, TABLE_OFF - 0x10)
ctx_end = min(len(data), TABLE_OFF + 0x80)
chunk2 = data[ctx_off:ctx_end]
print(f"  Context around 0x{TABLE_OFF:X}:")
for i in range(0, len(chunk2), 16):
    hex_str = ' '.join(f'{b:02X}' for b in chunk2[i:i+16])
    marker = ' <<<' if (ctx_off + i) == TABLE_OFF else ''
    print(f"  {ctx_off+i:08X}: {hex_str}{marker}")

print()
print("=== Searching for known keys in file ===")
# Search for known unlock keys we've found
known_keys = {
    0x6123789A: "Primary universal",
    0x5CF2E094: "Secondary",
    0xBE4B8754: "XD05 post-cutoff SAT8232",
    0x08A98AF2: "XD06U post-cutoff SAT8B30",
    0xA44F2F55: "XD08U SAT9331",
    0x426623FD: "BDR-UD04",
}
for key, desc in known_keys.items():
    kb = struct.pack('<I', key)
    pos = data.find(kb)
    if pos >= 0:
        print(f"  0x{key:08X} ({desc}): found at file offset 0x{pos:X}")
    else:
        print(f"  0x{key:08X} ({desc}): NOT FOUND")

print()
print("=== Searching for drive model strings near index table ===")
models = [b"XD07", b"XD06", b"XD05", b"XD08", b"UD04", b"BDR-S", b"AD07"]
for m in models:
    pos = 0
    while True:
        pos = data.find(m, pos)
        if pos < 0: break
        ctx = data[max(0,pos-4):pos+20]
        print(f"  '{m.decode()}' at 0x{pos:X}: {ctx.hex(' ').upper()}")
        pos += 1

print()
print("=== Looking for drive index mapping table ===")
# sub_407790 returns the drive index
# The model string table should be near 0x16F4C8
# Look for array of model strings with indices

# Find all "BDR-" strings
bdr_pos = []
pos = 0
while True:
    pos = data.find(b'BDR-', pos)
    if pos < 0: break
    name = data[pos:pos+12].split(b'\x00')[0].decode('ascii','replace')
    bdr_pos.append((pos, name))
    pos += 1

print(f"  Found {len(bdr_pos)} BDR- references")

# Focus on the model string table area around 0x16F4C8
TABLE2_OFF = 0x16F4C8 - 0x10
chunk3 = data[TABLE2_OFF:TABLE2_OFF+0x200]
print(f"\n  Model string area around 0x16F4C8:")
for i in range(0, len(chunk3), 16):
    hex_str = ' '.join(f'{b:02X}' for b in chunk3[i:i+16])
    try:
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk3[i:i+16])
    except:
        asc = ''
    print(f"  {TABLE2_OFF+i:08X}: {hex_str}  {asc}")

print()
print("=== XD06U model string area (0x1479EB) ===")
ctx_off2 = 0x1479EB - 0x20
chunk4 = data[ctx_off2:ctx_off2+0x200]
for i in range(0, len(chunk4), 16):
    hex_str = ' '.join(f'{b:02X}' for b in chunk4[i:i+16])
    asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk4[i:i+16])
    marker = ' <<<' if (ctx_off2+i) == 0x1479EB else ''
    print(f"  {ctx_off2+i:08X}: {hex_str}  {asc}{marker}")

print()
print("=== Done! ===")
