#!/usr/bin/env python3
"""
Pioneer Firmware Date Patcher
Patches the date stamp in a Pioneer firmware file to fool the drive's
version check into accepting older firmware as a newer version.

by cPix / Razor 1911 (c) 2026

Usage: python patch_firmware_date.py input.bin [output.bin]
       Default output: input_patched.bin

The date is stored as ASCII "YY/MM/DD" in the firmware header.
We replace it with a future date to bypass the downgrade check.
"""

import sys
import os
import binascii

FUTURE_DATE = b'28/01/01'  # January 1, 2028 — safely in the future

def patch_firmware(input_file, output_file=None):
    if output_file is None:
        base = os.path.splitext(input_file)[0]
        output_file = f"{base}_patched.bin"

    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    print(f"File    : {input_file}")
    print(f"Size    : {len(data)} bytes (0x{len(data):X})")
    print(f"CRC32   : {binascii.crc32(bytes(data))&0xFFFFFFFF:08X}")

    # Parse header for current date
    try:
        end = data.index(0x1A) if 0x1A in data[:600] else 400
        hdr = bytes(data[:end]).decode('ascii', errors='replace')
        current_date = ''
        for line in hdr.split('\r\n'):
            line = line.strip()
            if line.startswith('Generated Date :'):
                current_date = line[16:].strip().rstrip('\x00').strip()
                break
        print(f"Model   : ", end='')
        for line in hdr.split('\r\n'):
            if line.strip().startswith('ID :'):
                print(line.strip()[4:].strip().rstrip('\x00'))
                break
        print(f"Date    : {current_date}")
    except Exception as e:
        print(f"Header parse error: {e}")
        current_date = ''

    # Find and replace date in ASCII header
    # Format: "YY/MM/DD" e.g. "22/10/11"
    date_bytes = current_date.encode('ascii') if current_date else None
    
    patches = 0
    if date_bytes and len(date_bytes) >= 8:
        pos = 0
        while True:
            idx = data.find(date_bytes[:8], pos)
            if idx < 0:
                break
            print(f"\nFound date '{current_date[:8]}' at offset 0x{idx:08X}")
            print(f"Patching to '{FUTURE_DATE.decode()}'...")
            data[idx:idx+8] = FUTURE_DATE
            patches += 1
            pos = idx + 1
    
    if patches == 0:
        # Try to find any date pattern YY/MM/DD in header
        import re
        match = re.search(rb'\d\d/\d\d/\d\d', bytes(data[:600]))
        if match:
            idx = match.start()
            old_date = bytes(data[idx:idx+8])
            print(f"\nFound date '{old_date.decode()}' at offset 0x{idx:08X}")
            print(f"Patching to '{FUTURE_DATE.decode()}'...")
            data[idx:idx+8] = FUTURE_DATE
            patches += 1

    if patches == 0:
        print("\nERROR: Could not find date in firmware header!")
        return False

    new_crc = binascii.crc32(bytes(data)) & 0xFFFFFFFF
    print(f"\nPatched {patches} date(s)")
    print(f"New CRC32: {new_crc:08X}")

    with open(output_file, 'wb') as f:
        f.write(data)

    print(f"Saved to: {output_file}")
    print(f"\nReady to flash with:")
    print(f"  drivekit flashfw E --file2 {output_file}")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(input_file):
        print(f"File not found: {input_file}")
        sys.exit(1)
    
    success = patch_firmware(input_file, output_file)
    sys.exit(0 if success else 1)
