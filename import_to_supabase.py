#!/usr/bin/env python3
"""
Pioneer Firmware Supabase Importer
Imports firmware_analysis.json into Supabase compat_files table
by cPix / Razor 1911 (c) 2026

Usage: python import_to_supabase.py [firmware_analysis.json]

Install requests: pip install requests
"""

import json
import sys
import time

try:
    import requests
except ImportError:
    print("Install requests first: pip install requests")
    sys.exit(1)

# Supabase config
SB_URL = "https://eehuzsmqkqphsrpgxgkh.supabase.co"
SB_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVlaHV6c21xa3FwaHNycGd4Z2toIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg4Njk0NDksImV4cCI6MjEwNDQ0NTQ0OX0.FvD1LHy_3GIYPcKxFu8A8Y8zYXf_QlObvp2F-v3EVPI"

HEADERS = {
    "apikey": SB_KEY,
    "Authorization": f"Bearer {SB_KEY}",
    "Content-Type": "application/json",
    "Prefer": "resolution=merge-duplicates,return=minimal"
}

def platform_id(platform_str):
    """Extract hex platform ID from platform string e.g. 'SAT 9330' -> '0x9330'"""
    parts = platform_str.strip().split()
    for p in parts:
        try:
            val = int(p, 16)
            if 0x8000 <= val <= 0xFFFF:
                return f"0x{val:04X}"
        except:
            pass
    return ''

def import_firmware(entries):
    """Import firmware entries to Supabase compat_files table"""
    success = 0
    failed = 0
    skipped = 0

    print(f"Importing {len(entries)} firmware files to Supabase...")
    print()

    for i, e in enumerate(entries):
        # Build record - match exact compat_files table columns
        record = {
            "filename":      e.get('filename', ''),
            "model":         e.get('model', ''),
            "version":       e.get('version', ''),
            "file_type":     e.get('file_type', '').strip(),
            "platform":      e.get('platform', ''),
            "platform_id":   platform_id(e.get('platform', '')),
            "platform_name": e.get('platform', ''),
            "kernel":        e.get('kernel', '').strip(),
            "checksum":      e.get('checksum', '')
        }

        # Skip entries without filename or checksum
        if not record['filename'] or not record['checksum']:
            skipped += 1
            continue

        # POST to Supabase
        try:
            resp = requests.post(
                f"{SB_URL}/rest/v1/compat_files?on_conflict=checksum",
                headers=HEADERS,
                json=record,
                timeout=10
            )
            if resp.status_code in (200, 201, 204):
                success += 1
                print(f"  [{i+1:3d}/{len(entries)}] ✓ {record['filename']:35s} v{record['version']:6s} {record['file_type']:7s} {record['checksum']}")
            else:
                failed += 1
                print(f"  [{i+1:3d}/{len(entries)}] ✗ {record['filename']:35s} HTTP {resp.status_code}: {resp.text[:80]}")
        except Exception as ex:
            failed += 1
            print(f"  [{i+1:3d}/{len(entries)}] ✗ {record['filename']:35s} ERROR: {ex}")

        # Rate limiting — don't hammer Supabase
        time.sleep(0.1)

    print()
    print(f"Import complete!")
    print(f"  Success : {success}")
    print(f"  Failed  : {failed}")
    print(f"  Skipped : {skipped}")

def main():
    fname = sys.argv[1] if len(sys.argv) > 1 else 'firmware_analysis.json'

    try:
        with open(fname, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {fname}")
        print("Run analyze_firmware.py first!")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        sys.exit(1)

    entries = data.get('firmware', data) if isinstance(data, dict) else data
    print(f"Pioneer Firmware Supabase Importer")
    print(f"===================================")
    print(f"Loaded {len(entries)} entries from {fname}")
    print()

    # Show summary before importing
    kernels = sum(1 for e in entries if 'Kernel' in e.get('file_type',''))
    normals = sum(1 for e in entries if 'Normal' in e.get('file_type',''))
    pre = sum(1 for e in entries if not e.get('post_cutoff'))
    post = sum(1 for e in entries if e.get('post_cutoff'))
    print(f"  Kernel files  : {kernels}")
    print(f"  Normal files  : {normals}")
    print(f"  Pre-cutoff    : {pre}")
    print(f"  Post-cutoff   : {post}")
    print()

    confirm = input("Import to Supabase? [y/N]: ")
    if confirm.lower() != 'y':
        print("Cancelled.")
        sys.exit(0)

    print()
    import_firmware(entries)

if __name__ == '__main__':
    main()
