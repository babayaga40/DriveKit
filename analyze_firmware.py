#!/usr/bin/env python3
"""
Pioneer Firmware Analyzer
Scans extracted firmware files and generates a CSV + JSON report
by cPix / Razor 1911 (c) 2026

Usage: python analyze_firmware.py [extracted_folder]
       Default folder: .\extracted\
"""

import os
import sys
import json
import binascii
import csv

def parse_header(data):
    """Parse Pioneer firmware header (ASCII text terminated by 0x1A)"""
    result = {
        'model': '',
        'version': '',
        'platform': '',
        'kernel': '',
        'file_type': '',
        'date': '',
        'checksum': ''
    }

    # Find header end (0x1A terminator)
    try:
        end = data.index(0x1A) if 0x1A in data[:600] else 400
        hdr = data[:end].decode('ascii', errors='replace')
    except:
        return None

    # Must contain Pioneer identifier
    if 'PIONEER' not in hdr and 'pioneer' not in hdr.lower():
        return None

    for line in hdr.split('\r\n'):
        line = line.strip()
        if line.startswith('ID :'):
            result['model'] = line[4:].strip().rstrip('\x00').strip()
        elif line.startswith('Revision Level :'):
            result['version'] = line[16:].strip().rstrip('\x00').strip()
        elif line.startswith('Hardware Version :'):
            result['platform'] = line[18:].strip().rstrip('\x00').strip()
        elif line.startswith('Kernel Version :'):
            result['kernel'] = line[16:].strip().rstrip('\x00').strip()
        elif line.startswith('File Type :'):
            result['file_type'] = line[11:].strip().rstrip('\x00').strip()
        elif line.startswith('Generated Date :'):
            result['date'] = line[16:].strip().rstrip('\x00').strip()

    if not result['model']:
        return None

    result['checksum'] = f"{binascii.crc32(data)&0xFFFFFFFF:08X}"
    result['size'] = len(data)

    return result

def is_post_cutoff(date_str):
    """Check if firmware is post-cutoff (after December 2022)"""
    try:
        # Date format: YY/MM/DD
        parts = date_str.strip().split('/')
        if len(parts) == 3:
            year = int(parts[0])
            month = int(parts[1])
            # Post cutoff: December 2022 (22/12/xx) or later
            if year > 22: return True
            if year == 22 and month >= 12: return True
    except:
        pass
    return False

def scan_folder(folder):
    """Scan folder recursively for Pioneer firmware files"""
    entries = []
    seen_checksums = set()
    skipped_dvr = 0
    skipped_duplicate = 0
    skipped_unknown = 0
    total_files = 0

    print(f"Scanning: {folder}")
    print()

    for root, dirs, files in os.walk(folder):
        # Skip DVR folders
        if 'DVR' in root:
            skipped_dvr += 1
            continue

        for fname in files:
            fpath = os.path.join(root, fname)
            total_files += 1

            try:
                with open(fpath, 'rb') as f:
                    data = f.read()

                info = parse_header(data)
                if not info:
                    skipped_unknown += 1
                    continue

                # Skip duplicates by CRC32
                if info['checksum'] in seen_checksums:
                    skipped_duplicate += 1
                    continue
                seen_checksums.add(info['checksum'])

                info['filename'] = fname
                info['path'] = os.path.relpath(fpath, folder)
                info['post_cutoff'] = is_post_cutoff(info['date'])

                entries.append(info)

                status = "POST-CUTOFF!" if info['post_cutoff'] else "pre-cutoff"
                print(f"  [{info['file_type']:7s}] {info['model']:30s} v{info['version']:6s} "
                      f"{info['platform']:10s} {info['kernel']:8s} {info['date']:10s} "
                      f"{info['checksum']} [{status}]")

            except Exception as e:
                skipped_unknown += 1

    print()
    print(f"Results:")
    print(f"  Total files scanned : {total_files}")
    print(f"  Valid firmware files : {len(entries)}")
    print(f"  Unique by CRC32     : {len(seen_checksums)}")
    print(f"  Skipped (DVR)       : {skipped_dvr} folders")
    print(f"  Skipped (duplicate) : {skipped_duplicate}")
    print(f"  Skipped (unknown)   : {skipped_unknown}")
    print()

    kernels = [e for e in entries if 'Kernel' in e['file_type']]
    normals = [e for e in entries if 'Normal' in e['file_type']]
    pre = [e for e in entries if not e['post_cutoff']]
    post = [e for e in entries if e['post_cutoff']]
    print(f"  Kernel files        : {len(kernels)}")
    print(f"  Normal files        : {len(normals)}")
    print(f"  Pre-cutoff          : {len(pre)}")
    print(f"  Post-cutoff         : {len(post)}")

    return entries

def save_csv(entries, filename='firmware_analysis.csv'):
    """Save results to CSV"""
    fields = ['filename', 'model', 'version', 'platform', 'kernel',
              'file_type', 'date', 'checksum', 'size', 'post_cutoff', 'path']
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(entries)
    print(f"  Saved CSV: {filename}")

def save_json(entries, filename='firmware_analysis.json'):
    """Save results to JSON"""
    output = {
        'count': len(entries),
        'generated': '2026-09-09',
        'firmware': entries
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    print(f"  Saved JSON: {filename}")

def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else 'extracted'

    if not os.path.exists(folder):
        print(f"Folder not found: {folder}")
        print(f"Usage: python analyze_firmware.py [folder]")
        print(f"Run extract_firmware.bat first!")
        sys.exit(1)

    entries = scan_folder(folder)

    if entries:
        print("Saving results...")
        save_csv(entries)
        save_json(entries)
        print()
        print("Done! Import firmware_analysis.json into DriveBrowser or Supabase.")
    else:
        print("No firmware files found!")

if __name__ == '__main__':
    main()
