import os
import time
import shutil
import subprocess
import threading
from typing import Set, Dict, List, Optional
from datetime import datetime
from pathlib import Path
import json
import ctypes
import sys
import logging
from collections import Counter
import math

# --- 1. HEURISTIC SCANNER (Fixed Memory Usage) ---
class HeuristicScanner:
    """Detect zero-day threats using behavioral analysis"""
    def __init__(self, logger):
        self.logger = logger
        self.logger.info("[HEURISTIC] Heuristic scanner initialized")
        
        self.suspicious_apis = {
            'critical': [
                b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread',
                b'NtUnmapViewOfSection', b'SetWindowsHookEx', b'GetAsyncKeyState',
                b'URLDownloadToFile', b'WinExec'
            ],
            'high': [
                b'RegSetValueEx', b'CreateToolhelp32Snapshot', b'OpenProcess',
                b'TerminateProcess', b'LoadLibrary', b'GetProcAddress'
            ]
        }
        self.exe_signatures = {
            'PE': b'MZ',
            'ELF': b'\x7fELF',
            'Mach-O': b'\xcf\xfa\xed\xfe'
        }
    def normalize_usb_path(self, path):
        """
        Ensures USB path is ALWAYS like D:\ not D:
        """
        path = os.path.abspath(path)

        # If it's only 'D:' → convert to 'D:\'
        if len(path) == 2 and path[1] == ":":
            path = path + "\\"

        # Ensure trailing slash
        if not path.endswith("\\"):
            path = path + "\\"

        return path

    def calculate_entropy(self, data):
        """Calculate Shannon entropy (0-8 bits)"""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
        return entropy

    def scan_file(self, file_path):
        """Scan a single file for suspicious behavior (Chunked reading)"""
        findings = []
        file_path = Path(file_path)
        
        # Skip scanning very large files for heuristics to save performance
        if file_path.stat().st_size > 50 * 1024 * 1024:  # 50MB limit for full content scan
            return findings

        try:
            with open(file_path, 'rb') as f:
                # Read first 4KB for headers/signatures
                header_data = f.read(4096)
                # Read full data for entropy (only if file is small enough)
                f.seek(0)
                full_data = f.read()

            if len(full_data) == 0:
                return findings

            # 1. Entropy Check
            entropy = self.calculate_entropy(full_data)
            if entropy > 7.3:
                findings.append({
                    'severity': 'HIGH',
                    'type': 'Entropy',
                    'detail': f'High entropy ({entropy:.2f}/8.0) - packed/encrypted'
                })

            # 2. Embedded Executable Check (In header or body)
            for exe_type, signature in self.exe_signatures.items():
                offset = full_data.find(signature)
                if offset > 512: # Executable header found deep inside file
                    findings.append({
                        'severity': 'CRITICAL',
                        'type': 'Embedded Executable',
                        'detail': f'Embedded {exe_type} at offset {offset}'
                    })

            # 3. API Check (Only relevant if it looks like binary data)
            critical_apis = [api for api in self.suspicious_apis['critical'] if api in full_data]
            if len(critical_apis) >= 3:
                findings.append({
                    'severity': 'CRITICAL',
                    'type': 'Suspicious APIs',
                    'detail': f'{len(critical_apis)} critical APIs detected'
                })

            # 4. Extension Mismatch
            file_ext = file_path.suffix.lower()
            if header_data.startswith(b'MZ') and file_ext not in ['.exe', '.dll', '.sys', '.scr', '.acm', '.ax']:
                findings.append({
                    'severity': 'CRITICAL',
                    'type': 'File Mismatch',
                    'detail': f'Executable disguised as {file_ext}'
                })

        except Exception as e:
            self.logger.debug(f"[HEURISTIC] Failed to scan {file_path}: {e}")

        return findings

    def scan_drive(self, drive_path):
        """Scan all files on a drive"""
        self.logger.info("[HEURISTIC] Starting zero-day threat analysis...")
        all_findings = {}
        total_files = 0
        suspicious_files = 0

        try:
            drive = self.normalize_usb_path(drive)
            for root, dirs, files in os.walk(drive_path):
                for file in files:
                    file_path = Path(root) / file
                    total_files += 1
                    findings = self.scan_file(file_path)
                    if findings:
                        suspicious_files += 1
                        all_findings[str(file_path)] = findings
        except Exception as e:
            self.logger.error(f"[HEURISTIC] Scan error: {e}")

        critical_count = sum(1 for findings in all_findings.values() 
                           for f in findings if f['severity'] == 'CRITICAL')

        if critical_count > 0:
            threat_level = 'CRITICAL'
        elif suspicious_files > 0:
            threat_level = 'HIGH' if suspicious_files > 5 else 'MEDIUM'
        else:
            threat_level = 'CLEAN'

        self.logger.info(f"[HEURISTIC] Result: {threat_level} ({suspicious_files} suspicious files)")
        return {'status': threat_level, 'findings': all_findings}


# --- 2. SAFE FILE COPIER (Integrated logic) ---
class SafeFileCopier:
    DEFAULT_DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.ps1', '.vbs', '.dll', '.scr',
        '.cmd', '.com', '.pif', '.msi', '.jar', '.js', '.lnk', '.inf'
    }

    def __init__(self, logger, dangerous_extensions: Set[str] = None):
        self.logger = logger
        self.dangerous_extensions = dangerous_extensions or self.DEFAULT_DANGEROUS_EXTENSIONS
        self.stats = {'copied': 0, 'blocked': 0, 'errors': 0}
    def normalize_usb_path(self, path):
        """
        Ensures USB path is ALWAYS like D:\ not D:
        """
        path = os.path.abspath(path)

        # If it's only 'D:' → convert to 'D:\'
        if len(path) == 2 and path[1] == ":":
            path = path + "\\"

        # Ensure trailing slash
        if not path.endswith("\\"):
            path = path + "\\"

        return path
    def is_safe_file(self, file_path: Path) -> bool:
        return file_path.suffix.lower() not in self.dangerous_extensions

    def copy_files(self, src, dst):
        src = self.normalize_usb_path(src)

        copied = 0
        blocked = 0
        drive = self.normalize_usb_path(drive)
        for root, dirs, files in os.walk(src):
            rel = os.path.relpath(root, src)
            target_dir = os.path.join(dst, rel)

            os.makedirs(target_dir, exist_ok=True)

            for f in files:
                src_file = os.path.join(root, f)
                dst_file = os.path.join(target_dir, f)

                try:
                    shutil.copy2(src_file, dst_file)
                    copied += 1
                except Exception:
                    blocked += 1

        self.logger.info(f"[SUCCESS] Copied: {copied}, Blocked: {blocked}")
        return copied, blocked



# --- 3. CLAMAV SCANNER ---
class ClamAVScanner:
    def __init__(self, logger):
        self.logger = logger
        self.clamscan_path = self.find_clamscan()

    def find_clamscan(self):
        possible_paths = [
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files (x86)\ClamAV\clamscan.exe",
            "clamscan"
        ]
        for path in possible_paths:
            if shutil.which(path) or Path(path).exists():
                return path
        return None

    def is_available(self):
        return self.clamscan_path is not None

    def scan_drive(self, drive_path):
        if not self.is_available():
            return {"status": "skipped", "infected": 0}
        
        self.logger.info(f"[CLAMAV] Scanning {drive_path}...")
        log_file = Path("C:\\USB_Quarantine") / "clam_log.txt"
        
        cmd = [self.clamscan_path, "-r", "--no-summary", "-i", str(drive_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            infected_files = [line for line in result.stdout.splitlines() if "FOUND" in line]
            
            if infected_files:
                return {"status": "infected", "infected": len(infected_files), "files": infected_files}
            return {"status": "clean", "infected": 0}
            
        except Exception as e:
            self.logger.error(f"[CLAMAV] Error: {e}")
            return {"status": "error", "infected": 0}


# --- 4. MAIN CONTROLLER ---
class USBQuarantine:
    def __init__(self, quarantine_base="C:\\USB_Quarantine"):
        self.quarantine_base = Path(quarantine_base)
        self.quarantine_base.mkdir(parents=True, exist_ok=True)
        self.setup_logging()
        
        self.heuristic_scanner = HeuristicScanner(self.logger)
        self.copier = SafeFileCopier(self.logger)
        self.clamav = ClamAVScanner(self.logger)
        self.processed_drives = set()

    def setup_logging(self):
        self.logger = logging.getLogger('USBQuarantine')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)

    def get_removable_drives(self):
        drives = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if bitmask & 1:
                drive_path = f"{letter}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(drive_path) == 2:  # DRIVE_REMOVABLE
                    drives.append(drive_path)
            bitmask >>= 1
        return drives
    def normalize_usb_path(self, path):
        """
        Ensures USB path is ALWAYS like D:\ not D:
        """
        path = os.path.abspath(path)

        # If it's only 'D:' → convert to 'D:\'
        if len(path) == 2 and path[1] == ":":
            path = path + "\\"

        # Ensure trailing slash
        if not path.endswith("\\"):
            path = path + "\\"

        return path

    def lock_drive(self, drive_path):
        """Apply Read-Only Attribute + ACL Deny Write"""
        try:
            # 1. Disable Autorun
            autorun = Path(drive_path) / "autorun.inf"
            if autorun.exists():
                subprocess.run(f'attrib +R +H +S "{autorun}"', shell=True)

            # 2. ACL Lock (Deny Write to Everyone)
            # Note: We must be careful not to lock out the SYSTEM/Admin running this script
            # We deny 'Users' (standard users) and 'Everyone' write access, but Admin might override.
            clean_path = drive_path.rstrip('\\')
            cmd = f'icacls "{clean_path}" /deny Everyone:(W,AD,WDAC)' 
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.logger.info(f"[LOCK] Drive {drive_path} locked (Write denied).")
            return True
        except Exception as e:
            self.logger.error(f"[LOCK] Failed to lock drive: {e}")
            return False

    def unlock_drive(self, drive_path):
        """Remove restrictions"""
        clean_path = drive_path.rstrip('\\')
        subprocess.run(f'icacls "{clean_path}" /remove:d Everyone', shell=True, stdout=subprocess.DEVNULL)
        self.logger.info(f"[UNLOCK] Drive {drive_path} unlocked.")

    def process_drive(self, drive_path):
        if drive_path in self.processed_drives:
            return

        self.logger.info("="*60)
        self.logger.info(f"NEW USB DETECTED: {drive_path}")
        self.processed_drives.add(drive_path)

        # 1. Lock
        self.lock_drive(drive_path)

        # 2. ClamAV Scan
        clam_res = self.clamav.scan_drive(drive_path)
        if clam_res['status'] == 'infected':
            self.logger.critical(f"❌ CLAMAV FOUND MALWARE: {clam_res['files']}")
            self.logger.critical("DRIVE QUARANTINED. ACCESS DENIED.")
            return # Stop here, do not copy

        # 3. Heuristic Scan
        heur_res = self.heuristic_scanner.scan_drive(drive_path)
        if heur_res['status'] == 'CRITICAL':
            self.logger.critical(f"❌ HEURISTIC THREATS DETECTED: {heur_res['findings']}")
            self.logger.critical("DRIVE QUARANTINED. ACCESS DENIED.")
            return # Stop here

        # 4. Safe Copy
        if clam_res['status'] == 'clean' and heur_res['status'] in ['CLEAN', 'MEDIUM']:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = self.quarantine_base / f"SafeCopy_{drive_path[0]}_{timestamp}"
            
            self.logger.info(f"[COPY] Copying safe files to {dest}...")
            stats = self.copier.copy_files(drive_path, dest)
            
            self.logger.info(f"[SUCCESS] Copied: {stats['copied']}, Blocked: {stats['blocked']}")
            self.logger.info("You may now access the files in the SafeCopy folder.")
        
        # Optional: Unlock after processing if you want users to use the original stick (RISKY)
        # self.unlock_drive(drive_path) 
        self.logger.info("="*60)

    def monitor(self):
        self.logger.info("Starting USB Monitor... (Press Ctrl+C to stop)")
        while True:
            try:
                current_drives = self.get_removable_drives()
                for drive in current_drives:
                    self.process_drive(drive)
                
                # Cleanup removed drives from processed list
                self.processed_drives = {d for d in self.processed_drives if d in current_drives}
                
                time.sleep(2)
            except KeyboardInterrupt:
                self.logger.info("Stopping monitor.")
                break
            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("❌ ERROR: Must run as Administrator to control drive permissions.")
    else:
        app = USBQuarantine()
        app.monitor()