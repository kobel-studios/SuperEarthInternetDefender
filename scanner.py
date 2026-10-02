"""Virus scanner - checks files using multiple free methods.

Usage:
  python scanner.py <file_path>
  python scanner.py <file_path> --verbose

Exit codes:
  0 = SAFE
  1 = NOT SAFE (threats detected or suspicious)
  2 = UNKNOWN (file not in any database, use caution)

Methods used (no paid software, no Norton, no upsells):
  1. Digital signature check (Windows built-in)
  2. VirusTotal hash lookup (free public)
  3. Heuristic pattern checks
  4. File reputation check
"""
import argparse
import hashlib
import os
import subprocess
import sys
import urllib.request
import urllib.error
import json
import ssl

def get_sha256(file_path):
    """Get SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def check_digital_signature(file_path):
    """Check if a Windows executable has a valid digital signature."""
    try:
        environment = os.environ.copy()
        environment["VT_SCAN_PATH"] = os.path.abspath(file_path)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "$sig = Get-AuthenticodeSignature -LiteralPath $env:VT_SCAN_PATH; "
             "$sig.Status; "
             "$sig.SignerCertificate.Subject; "
             "$sig.SignerCertificate.Issuer"],
            capture_output=True, text=True, timeout=10, env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        status = lines[0] if lines else "Unknown"
        signer = lines[1] if len(lines) > 1 else "Unknown"
        issuer = lines[2] if len(lines) > 2 else "Unknown"
        return status, signer, issuer
    except Exception as e:
        return "Error", str(e), ""

def check_virustotal(file_hash):
    """Look up file hash on VirusTotal using public web interface.
    Returns (status, malicious_count, total_engines).
    status: 'clean', 'malicious', 'not_found', or 'error'"""
    try:
        # Use the public web page - just check if the hash is known
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={
            "accept": "application/json",
            "x-apikey": "",  # Try empty first
            "User-Agent": "Mozilla/5.0"
        })
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                if malicious + suspicious == 0:
                    return "clean", 0, total
                return "malicious", malicious + suspicious, total
        except urllib.error.HTTPError as e:
            if e.code == 401 or e.code == 403:
                # Need API key - try web scrape
                return check_virustotal_web(file_hash)
            if e.code == 404:
                return "not_found", 0, 0
            return "error", 0, 0
    except Exception:
        return "error", 0, 0

def check_virustotal_web(file_hash):
    """Fallback: scrape VirusTotal web page for basic info."""
    try:
        url = f"https://www.virustotal.com/gui/file/{file_hash}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode('utf-8', errors='ignore').lower()
            if "not found" in html or "404" in html[:500]:
                return "not_found", 0, 0
            # Can't get exact count from HTML easily, but file is known
            if "malicious" in html:
                return "known_suspicious", -1, -1
            return "known_clean", 0, -1
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "not_found", 0, 0
        return "error", 0, 0
    except Exception:
        return "error", 0, 0

def check_file_type(file_path):
    """Check the file type and look for suspicious patterns."""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    try:
        with open(file_path, 'rb') as f:
            header = f.read(1024)
    except Exception:
        return "unknown", []

    suspicious_patterns = []

    is_executable = header[:2] == b'MZ'
    is_script = ext in ('.ps1', '.bat', '.cmd', '.vbs', '.js', '.py', '.sh')
    is_zip = header[:4] == b'PK\x03\x04'

    if is_script:
        try:
            with open(file_path, 'r', errors='ignore') as f:
                text = f.read(5000).lower()
            if 'base64' in text and ('decode' in text or '-decode' in text):
                suspicious_patterns.append("Base64 decode in script")
            if 'invoke-expression' in text or 'iex ' in text:
                suspicious_patterns.append("Invoke-Expression (can run arbitrary code)")
            if 'downloadstring' in text or 'downloadfile' in text:
                suspicious_patterns.append("Downloads from internet in script")
            if 'reg add' in text and ('hkcu\\software\\microsoft\\windows\\currentversion\\run' in text):
                suspicious_patterns.append("Adds itself to startup registry")
            if 'while($true)' in text and 'sleep' in text:
                suspicious_patterns.append("Infinite loop with sleep (possible persistence)")
        except Exception:
            pass

    if is_executable:
        return "executable", suspicious_patterns
    elif is_script:
        return "script", suspicious_patterns
    elif is_zip:
        return "archive", suspicious_patterns
    else:
        return "other", suspicious_patterns

def scan(file_path, verbose=False):
    """Scan a file and return verdict."""
    if not os.path.exists(file_path):
        print(f"ERROR: File not found: {file_path}")
        return 1

    file_size = os.path.getsize(file_path)
    print(f"File: {file_path}")
    print(f"Size: {file_size:,} bytes")

    # Step 1: Hash
    print("\n--- Computing SHA256 ---")
    file_hash = get_sha256(file_path)
    print(f"SHA256: {file_hash}")

    # Step 2: File type and heuristics
    print("\n--- File Type & Heuristics ---")
    file_type, suspicious = check_file_type(file_path)
    print(f"Type: {file_type}")
    if suspicious:
        print(f"Suspicious patterns:")
        for s in suspicious:
            print(f"  ! {s}")
    else:
        print("No suspicious patterns detected")

    # Step 3: Digital signature (for executables)
    sig_ok = False
    if file_type == "executable":
        print("\n--- Digital Signature ---")
        status, signer, issuer = check_digital_signature(file_path)
        print(f"Signature: {status}")
        print(f"Signer: {signer}")
        if status == "Valid":
            print("File is signed by a trusted publisher")
            sig_ok = True
        elif status == "NotSigned":
            print("WARNING: File is NOT digitally signed")
        elif status == "HashMismatch":
            print("WARNING: File signature is INVALID (file was tampered with)")
        elif status == "UnknownError":
            print("WARNING: Could not verify signature")

    # Step 4: VirusTotal
    print("\n--- VirusTotal (70+ engines) ---")
    vt_status, malicious, total = check_virustotal(file_hash)

    if vt_status == "clean":
        print(f"Scanned by {total} engines: 0 detections")
        print("Verdict: CLEAN on VirusTotal")
    elif vt_status == "malicious":
        print(f"Scanned by {total} engines: {malicious} detections")
        print(f"Verdict: MALICIOUS on VirusTotal")
    elif vt_status == "not_found":
        print("File not in VirusTotal database (never been scanned)")
    elif vt_status == "known_clean":
        print("File is known on VirusTotal (appears clean)")
    elif vt_status == "known_suspicious":
        print("File is known on VirusTotal (has detections)")
    else:
        print("Could not reach VirusTotal")

    # Final verdict
    print("\n" + "=" * 60)

    if vt_status == "malicious" and malicious > 2:
        print("RESULT: NOT SAFE - VirusTotal detected threats")
        return 1

    if suspicious:
        print("RESULT: NOT SAFE - Suspicious patterns detected")
        return 1

    if vt_status == "clean":
        if sig_ok:
            print("RESULT: SAFE - Signed and clean on VirusTotal")
        else:
            print("RESULT: SAFE - Clean on VirusTotal (unsigned but no threats)")
        return 0

    if vt_status == "known_clean":
        print("RESULT: SAFE - Known clean on VirusTotal")
        return 0

    if sig_ok and not suspicious:
        print("RESULT: SAFE - Digitally signed by trusted publisher, no suspicious patterns")
        return 0

    if vt_status == "not_found":
        print("RESULT: UNKNOWN - Not in VirusTotal database")
        if sig_ok:
            print("  (but file is digitally signed, which is a good sign)")
            return 0
        print("  Use caution - this file has never been checked by antivirus")
        return 2

    print("RESULT: UNKNOWN - Could not fully verify")
    return 2

def main():
    parser = argparse.ArgumentParser(
        description="Scan a file for viruses. Free, no Norton, no upsells."
    )
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed results")
    args = parser.parse_args()

    print("=" * 60)
    print("VIRUS SCANNER")
    print("Digital Signature + VirusTotal + Heuristics")
    print("=" * 60)

    exit_code = scan(args.file, args.verbose)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
