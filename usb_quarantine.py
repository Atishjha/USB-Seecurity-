import os 
import time 
import shutil 
import subprocess
import threading 
from typing import Set, Dict, List
from datetime import datetime
from pathlib import Path
import json 
import ctypes
import sys 
import logging
from collections import Counter
import math
import traceback

class HeuristicScanner:
    def __init__(self,logger, *,max_file_size_mb=50,read_in_chunks=True, chunk_size=1024 * 512,enable_entropy=True,enable_api_scan=True,enable_embedded_exe_scan=True):
        self.logger = logger
        
        # Memory/scan tunables
        self.max_file_size_mb = max_file_size_mb
        self.read_in_chunks = read_in_chunks
        self.chunk_size = chunk_size
        self.enable_entropy = enable_entropy
        self.enable_api_scan = enable_api_scan
        self.enable_embedded_exe_scan = enable_embedded_exe_scan
        
         
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
        
        MAX_IN_MEMORY = 50 * 1024 * 1024   # 50 MB, files larger than this won't be fully read
        ENTROPY_SAMPLE_SIZE = 1 * 1024 * 1024  # 1 MB sample for entropy
        CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB chunk for chunked scanning
        RESULTS_DUMP = Path("heuristic_findings.jsonl")  # streaming output (JSONL)

    def calculate_entropy(self, data: bytes) -> float:
        """Shannon entropy for bytes-like object. Works on sample only."""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            p = count / total_bytes
            entropy -= p * math.log2(p)
        return entropy

    def _chunked_find_any(self, file_obj, signatures: list[bytes], chunk_size=None):
        """
        Search for any of signatures in the file by reading chunks with overlap.
        Returns set of signatures found and first offsets dict.
        """
        if chunk_size is None:
            chunk_size = self.CHUNK_SIZE
        found = set()
        first_offsets = {}
        # maximum signature length for overlap
        max_sig = max((len(s) for s in signatures), default=1)
        overlap = max_sig - 1

        file_obj.seek(0)
        offset = 0
        prev_tail = b""
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            block = prev_tail + chunk  # overlap
            for sig in signatures:
                if sig in block:
                    if sig not in found:
                        # compute approximate position (first occurrence)
                        pos_in_block = block.find(sig)
                        first_offsets[sig] = offset - len(prev_tail) + pos_in_block
                        found.add(sig)
            # prepare tail for next round
            prev_tail = chunk[-overlap:] if overlap > 0 else b""
            offset += len(chunk)
            # early exit if we found all signatures
            if len(found) == len(signatures):
                break
        return found, first_offsets

    def scan_file(self, file_path, collect_findings=True):
        """
        Safer scan_file:
         - Does not load files > MAX_IN_MEMORY fully.
         - Uses sampling for entropy.
         - Uses chunked search for signatures / suspicious APIs.
         - When collect_findings=False, it will stream to RESULTS_DUMP instead of returning big dict.
        """
        file_path = Path(file_path)
        findings = []

        try:
            # Skip unreadable / special files quickly
            if not file_path.exists() or not file_path.is_file():
                return findings

            file_size = file_path.stat().st_size

            # If file is tiny, read fully (cheap)
            read_full = file_size <= self.MAX_IN_MEMORY

            # Open once and use chunked processing
            with open(file_path, "rb") as f:
                # 1) Entropy on sample (first ENTROPY_SAMPLE_SIZE bytes + a tail sample if large)
                sample = f.read(self.ENTROPY_SAMPLE_SIZE)
                if file_size > self.ENTROPY_SAMPLE_SIZE * 2:
                    # also sample a chunk from near middle to improve detection for packed content
                    mid = file_size // 2
                    f.seek(mid)
                    sample += f.read(self.ENTROPY_SAMPLE_SIZE // 2)

                entropy = self.calculate_entropy(sample)
                if entropy > 7.3:
                    findings.append({
                        'severity': 'HIGH',
                        'type': 'Entropy',
                        'detail': f'High entropy ({entropy:.2f}/8.0) - likely packed/encrypted'
                    })

                # 2) Signature detection (PE/ELF/Mach-O) - check header + chunked search for embedded ones
                # Check header quickly
                f.seek(0)
                header = f.read(8)
                for exe_type, signature in self.exe_signatures.items():
                    if header.startswith(signature):
                        # If header indicates executable and extension mismatches, flag
                        file_ext = file_path.suffix.lower()
                        if exe_type == 'PE' and file_ext not in ['.exe', '.dll', '.sys', '.scr']:
                            findings.append({
                                'severity': 'CRITICAL',
                                'type': 'File Mismatch',
                                'detail': f'Executable header ({exe_type}) but extension {file_ext}'
                            })

                # For embedded executables or APIs, perform chunked search across file
                f.seek(0)
                signatures = list(self.exe_signatures.values())
                found_sigs, sig_offsets = self._chunked_find_any(f, signatures)
                for sig in found_sigs:
                    # map sig back to exe_type name
                    exe_type_name = next((k for k, v in self.exe_signatures.items() if v == sig), None)
                    pos = sig_offsets.get(sig, None)
                    # We only treat it as embedded if found beyond small header area
                    if pos is not None and pos > 512:
                        findings.append({
                            'severity': 'CRITICAL',
                            'type': 'Embedded Executable',
                            'detail': f'Embedded {exe_type_name} at offset {pos}'
                        })

                # 3) Suspicious APIs (byte sequences) - chunked search
                f.seek(0)
                critical_apis_found, _ = self._chunked_find_any(f, self.suspicious_apis.get('critical', []))
                if len(critical_apis_found) >= 3:
                    findings.append({
                        'severity': 'CRITICAL',
                        'type': 'Suspicious APIs',
                        'detail': f'{len(critical_apis_found)} critical API-like byte sequences detected'
                    })

                # 4) If required to do deeper checks that require full data, optionally use mmap (memory-efficient)
                if read_full and not findings:
                    # only read full content when file size is small and no findings yet (optional)
                    f.seek(0)
                    data = f.read()
                    # you can do extra checks on data here if needed

        except MemoryError:
            self.logger.error(f"[HEURISTIC] MemoryError scanning {file_path}. Skipped.")
            findings.append({
                'severity': 'ERROR',
                'type': 'MemoryError',
                'detail': 'Skipped due to memory constraints'
            })
        except Exception as e:
            self.logger.debug(f"[HEURISTIC] Failed to scan {file_path}: {e}")

        # Either return findings or stream to disk
        if collect_findings:
            return findings
        else:
            # Append result to file to avoid memory growth
            if findings:
                with open(self.RESULTS_DUMP, "a", encoding="utf-8") as out:
                    out.write(json.dumps({
                        "path": str(file_path),
                        "size": file_size,
                        "findings": findings
                    }, ensure_ascii=False) + "\n")
            return []


    def scan_drive(self, drive_path, collect_findings=True, max_files=None):
        """Scan all files on a drive with better error handling."""
        drive_path = Path(drive_path)
        self.logger.info(f"[HEURISTIC] Starting heuristic analysis of {drive_path}...")
        
        total_files = 0
        suspicious_files = 0
        all_findings = {} if collect_findings else None
        
        # Check drive accessibility
        if not drive_path.exists():
            self.logger.error(f"[HEURISTIC] Drive does not exist: {drive_path}")
            return self._empty_scan_result("Drive does not exist")
        
        if not drive_path.is_dir():
            self.logger.error(f"[HEURISTIC] Path is not a directory: {drive_path}")
            return self._empty_scan_result("Path is not a directory")
        
        try:
            # First, let's check what filesystem we're dealing with
            import win32api
            import win32file
            
            try:
                # Get filesystem type
                drive_info = win32api.GetVolumeInformation(str(drive_path))
                filesystem = drive_info[4]
                self.logger.info(f"[HEURISTIC] Filesystem: {filesystem}")
                
                # Different approaches for different filesystems
                if filesystem in ['FAT32', 'FAT', 'exFAT']:
                    self.logger.info("[HEURISTIC] FAT/exFAT filesystem detected - using alternative scanning")
            except ImportError:
                self.logger.debug("[HEURISTIC] win32api not available, using standard scanning")
            except Exception as e:
                self.logger.debug(f"[HEURISTIC] Could not determine filesystem: {e}")
            
            # Try different scanning methods
            files_scanned = 0
            
            # METHOD 1: os.walk with error handling
            self.logger.info("[HEURISTIC] Scanning with os.walk...")
            for root, dirs, files in os.walk(str(drive_path), onerror=self._handle_walk_error):
                # Convert to Path objects
                root_path = Path(root)
                
                # Skip system directories
                if self._is_system_directory(root_path):
                    self.logger.debug(f"[HEURISTIC] Skipping system directory: {root}")
                    continue
                
                for file in files:
                    try:
                        file_path = root_path / file
                        
                        # Skip system files
                        if self._is_system_file(file_path):
                            continue
                        
                        # Check file size before scanning
                        try:
                            file_size = file_path.stat().st_size
                            if file_size == 0:
                                continue
                        except:
                            continue
                        
                        total_files += 1
                        
                        # Scan the file
                        findings = self.scan_file(file_path, collect_findings)
                        if findings:
                            suspicious_files += 1
                            if collect_findings:
                                all_findings[str(file_path)] = findings
                        
                        # Log progress
                        if total_files % 100 == 0:
                            self.logger.info(f"[HEURISTIC] Scanned {total_files} files...")
                        
                        # Limit files for testing
                        if max_files and total_files >= max_files:
                            self.logger.info(f"[HEURISTIC] Reached max files limit ({max_files})")
                            break
                    
                    except (PermissionError, OSError) as e:
                        self.logger.debug(f"[HEURISTIC] Skipping {file}: {e}")
                        continue
                    except Exception as e:
                        self.logger.debug(f"[HEURISTIC] Error processing {file}: {e}")
                        continue
                
                if max_files and total_files >= max_files:
                    break
            
            # If no files found with os.walk, try alternative methods
            if total_files == 0:
                self.logger.warning("[HEURISTIC] os.walk found 0 files, trying alternative methods...")
                
                # METHOD 2: Recursive glob
                try:
                    self.logger.info("[HEURISTIC] Trying recursive glob...")
                    for pattern in ['*', '*.*', '*/*', '*/*.*']:
                        for file_path in drive_path.rglob(pattern):
                            if file_path.is_file():
                                try:
                                    file_size = file_path.stat().st_size
                                    if file_size > 0 and not self._is_system_file(file_path):
                                        total_files += 1
                                        findings = self.scan_file(file_path, collect_findings)
                                        if findings:
                                            suspicious_files += 1
                                            if collect_findings:
                                                all_findings[str(file_path)] = findings
                                except:
                                    continue
                                
                                if total_files % 100 == 0:
                                    self.logger.info(f"[HEURISTIC] Glob scanned {total_files} files...")
                                
                                if max_files and total_files >= max_files:
                                    break
                        
                        if max_files and total_files >= max_files:
                            break
                except Exception as e:
                    self.logger.debug(f"[HEURISTIC] Glob failed: {e}")
            
            # METHOD 3: Manual directory traversal for stubborn drives
            if total_files == 0:
                self.logger.info("[HEURISTIC] Trying manual traversal...")
                total_files = self._manual_scan(drive_path, all_findings, collect_findings, max_files)
                if total_files > 0:
                    suspicious_files = len(all_findings) if collect_findings else 0
        
        except Exception as e:
            self.logger.error(f"[HEURISTIC] Scan error: {e}", exc_info=True)
            return self._empty_scan_result(str(e))
        
        self.logger.info(f"[HEURISTIC] Scanned {total_files} files, {suspicious_files} suspicious")
        
        # Calculate threat level
        critical_count = 0
        if collect_findings:
            critical_count = sum(1 for findings in all_findings.values() 
                               for f in findings if f['severity'] == 'CRITICAL')
        else:
            critical_count = suspicious_files if suspicious_files > 0 else 0
        
        if critical_count > 0:
            threat_level = 'CRITICAL'
        elif suspicious_files > total_files * 0.1 and total_files > 0:
            threat_level = 'HIGH'
        elif suspicious_files > 0:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'CLEAN'
        
        result = {
            'status': threat_level,
            'total_files': total_files,
            'suspicious_files': suspicious_files,
            'findings': all_findings if collect_findings else {}
        }
        
        if threat_level in ['CRITICAL', 'HIGH']:
            self.logger.warning(f"[HEURISTIC] ⚠️  Threat level: {threat_level}")
            if collect_findings and all_findings:
                for file_path, findings in list(all_findings.items())[:5]:
                    self.logger.warning(f"[HEURISTIC]   └─ {Path(file_path).name}: {len(findings)} issues")
        else:
            self.logger.info(f"[HEURISTIC] ✓ Threat level: {threat_level}")
        
        return result
    
    def _handle_walk_error(self, error):
        """Handle os.walk errors."""
        self.logger.debug(f"[HEURISTIC] Walk error: {error}")
        # Don't raise the error, just log it
        return None
    
    def _is_system_directory(self, path):
        """Check if directory is a system directory."""
        system_dirs = {
            '$RECYCLE.BIN', 'System Volume Information', 
            '.Trash', '.Trashes', 'RECYCLER', 'RECYCLED',
            'lost+found'
        }
        return path.name.upper() in {d.upper() for d in system_dirs}
    
    def _is_system_file(self, path):
        """Check if file is a system/hidden file."""
        try:
            # Check file attributes on Windows
            if hasattr(path, 'stat'):
                attrs = path.stat().st_file_attributes
                if attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                    return True
                if attrs & 4:  # FILE_ATTRIBUTE_SYSTEM
                    return True
        except:
            pass
        
        # Check by name
        system_files = {
            'thumbs.db', 'desktop.ini', '.ds_store',
            'autorun.inf', 'boot.ini', 'ntldr', 'ntdetect.com'
        }
        return path.name.lower() in system_files
    
    def _manual_scan(self, root_path, all_findings, collect_findings, max_files):
        """Manual directory traversal for problematic drives."""
        total_files = 0
        stack = [root_path]
        
        while stack:
            current_dir = stack.pop()
            
            try:
                # List directory contents
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        try:
                            entry_path = Path(entry.path)
                            
                            if entry.is_dir():
                                # Skip system directories
                                if not self._is_system_directory(entry_path):
                                    stack.append(entry_path)
                            elif entry.is_file():
                                # Skip system files
                                if self._is_system_file(entry_path):
                                    continue
                                
                                try:
                                    file_size = entry_path.stat().st_size
                                    if file_size == 0:
                                        continue
                                except:
                                    continue
                                
                                total_files += 1
                                
                                # Scan the file
                                findings = self.scan_file(entry_path, collect_findings)
                                if findings:
                                    if collect_findings:
                                        all_findings[str(entry_path)] = findings
                                
                                # Log progress
                                if total_files % 100 == 0:
                                    self.logger.info(f"[HEURISTIC] Manual scan: {total_files} files...")
                                
                                if max_files and total_files >= max_files:
                                    return total_files
                        
                        except (PermissionError, OSError):
                            continue
                        except Exception as e:
                            self.logger.debug(f"[HEURISTIC] Manual scan error: {e}")
                            continue
            
            except (PermissionError, OSError):
                continue
            except Exception as e:
                self.logger.debug(f"[HEURISTIC] Failed to scan directory {current_dir}: {e}")
                continue
        
        return total_files
    
    def _empty_scan_result(self, error_msg=""):
        """Return empty scan result when scan fails."""
        return {
            'status': 'ERROR',
            'total_files': 0,
            'suspicious_files': 0,
            'findings': {},
            'error': error_msg
        }

class SafeFileCopier:
    """
    A utility class for copying files while filtering out potentially dangerous file types.
    """
    
    # Default dangerous file extensions
    DEFAULT_DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.ps1', '.vbs', '.dll', '.scr',
        '.cmd', '.com', '.pif', '.msi', '.jar', '.js'
    }
    
    def __init__(self, dangerous_extensions: Set[str] = None):
        """
        Initialize the SafeFileCopier.
        
        Args:
            dangerous_extensions: Set of file extensions to block (default: DEFAULT_DANGEROUS_EXTENSIONS)
        """
        self.dangerous_extensions = dangerous_extensions or self.DEFAULT_DANGEROUS_EXTENSIONS
        self.stats = self._init_stats()
    
    def _init_stats(self) -> Dict:
        """Initialize statistics dictionary."""
        return {
            'copied': 0,
            'blocked': 0,
            'errors': 0,
            'blocked_files': [],
            'copied_files': []
        }
    
    def is_safe_file(self, file_path: str) -> bool:
        """
        Check if a file has a safe extension.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            bool: True if file is safe, False otherwise
        """
        extension = Path(file_path).suffix.lower()
        return extension not in self.dangerous_extensions
    
    def add_dangerous_extension(self, extension: str):
        """
        Add a file extension to the dangerous list.
        
        Args:
            extension: File extension to add (e.g., '.xyz')
        """
        if not extension.startswith('.'):
            extension = f'.{extension}'
        self.dangerous_extensions.add(extension.lower())
    
    def remove_dangerous_extension(self, extension: str):
        """
        Remove a file extension from the dangerous list.
        
        Args:
            extension: File extension to remove
        """
        if not extension.startswith('.'):
            extension = f'.{extension}'
        self.dangerous_extensions.discard(extension.lower())
    
    def copy_safe_files(self, source_dir: str, protected_dir: str, 
                       verbose: bool = True) -> Dict:
        """
        Copy only safe files from source to protected directory.
        
        Args:
            source_dir: Source directory path
            protected_dir: Protected destination directory path
            verbose: Print progress messages (default: True)
            
        Returns:
            dict: Statistics about the operation
        """
        # Reset stats
        self.stats = self._init_stats()
        
        # Create protected directory if it doesn't exist
        os.makedirs(protected_dir, exist_ok=True)
        
        # Walk through source directory
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                source_path = os.path.join(root, file)
                
                # Calculate relative path for maintaining directory structure
                rel_path = os.path.relpath(source_path, source_dir)
                dest_path = os.path.join(protected_dir, rel_path)
                
                self._copy_file(source_path, dest_path, rel_path, verbose)
        
        return self.stats
    
    def _copy_file(self, source_path: str, dest_path: str, 
                   rel_path: str, verbose: bool):
        """
        Copy a single file if it's safe.
        
        Args:
            source_path: Source file path
            dest_path: Destination file path
            rel_path: Relative path for logging
            verbose: Print progress messages
        """
        try:
            if self.is_safe_file(source_path):
                # Create subdirectories if needed
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                # Copy the file
                shutil.copy2(source_path, dest_path)
                self.stats['copied'] += 1
                self.stats['copied_files'].append(rel_path)
                
                if verbose:
                    print(f"✓ Copied: {rel_path}")
            else:
                self.stats['blocked'] += 1
                self.stats['blocked_files'].append(rel_path)
                
                if verbose:
                    print(f"✗ Blocked: {rel_path} (dangerous file type)")
                    
        except Exception as e:
            self.stats['errors'] += 1
            if verbose:
                print(f"✗ Error copying {rel_path}: {str(e)}")
    
    def get_stats(self) -> Dict:
        """
        Get the current statistics.
        
        Returns:
            dict: Current operation statistics
        """
        return self.stats.copy()
    
    def print_summary(self):
        """Print a summary of the last copy operation."""
        print("-" * 60)
        print(f"\nSummary:")
        print(f"  Files copied: {self.stats['copied']}")
        print(f"  Files blocked: {self.stats['blocked']}")
        print(f"  Errors: {self.stats['errors']}")
        
        if self.stats['blocked_files']:
            print(f"\nBlocked files:")
            for file in self.stats['blocked_files']:
                print(f"  - {file}")
            



class ClamAVScanner:
    def __init__(self,logger):
        """ Initialize ClamAV scanner
        Args:
            LOGGER: Logger instance from parent USBQuarantine class"""
        
        self.logger = logger 
        self.clamscan_path = self.find_clamscan()
    
    def find_clamscan(self):
        """Find ClamAv clamscan executable"""
        possible_paths = [
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files (x86)\ClamAV\clamscan.exe",
            r"C:\ClamAV\clamscan.exe",
            "clamscan"  # If in PATH
        ]
        for path in possible_paths:
            try: 
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.logger.info(f"[CLAMAV] Found clamscan at: {path}")
                    self.logger.debug(f"[CLAMAV] Version: {result.stdout.strip()}")
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        self.logger.warning("[CLAMAV] clamscan executable not found. ClamAV scanning will be disabled.")
        return None
    
    def is_available(self):
        """Check if clamscan is available"""
        return self.clamscan_path is not None
    
    def scan_drive(self, drive_path):
        """
        Scan USB drive with ClamAV with better error handling.
        """
        if not self.is_available():
            return {
                "status": "skipped",
                "infected_files": [],
                "scanned": 0,
                "infected": 0,
                "error": "ClamAV not found"
            }
        
        drive_path = Path(drive_path)
        self.logger.info(f"[CLAMAV] Starting scan of {drive_path}")
        
        # First, check if there are any files to scan
        try:
            # Count files manually first
            file_count = 0
            for root, dirs, files in os.walk(str(drive_path)):
                file_count += len(files)
                if file_count > 0:
                    break
            
            if file_count == 0:
                self.logger.warning(f"[CLAMAV] No files found on {drive_path}")
                return {
                    "status": "empty",
                    "infected_files": [],
                    "scanned": 0,
                    "infected": 0,
                    "note": "Drive appears to be empty"
                }
        except Exception as e:
            self.logger.error(f"[CLAMAV] Cannot scan drive: {e}")
            return {
                "status": "error",
                "infected_files": [],
                "scanned": 0,
                "infected": 0,
                "error": str(e)
            }
        
        # Proceed with ClamAV scan
        self.logger.info("[CLAMAV] This may take several minutes...")
        
        try:
            # Create log directory
            log_dir = Path("C:\\USB_Quarantine")
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / f"clamav_scan_{drive_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            
            # Build command
            cmd = [
                self.clamscan_path,
                "-r",  # Recursive
                "-i",  # Only show infected
                "--bell",
                f"--log={log_file}",
                str(drive_path)
            ]
            
            self.logger.debug(f"[CLAMAV] Command: {' '.join(cmd)}")
            
            # Run ClamAV with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=3600
            )
            
            # Parse results
            infected_files = []
            for line in result.stdout.split('\n'):
                if 'FOUND' in line:
                    infected_files.append(line.strip())
            
            # Parse summary
            scanned = 0
            infected = 0
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if "scanned files:" in line_lower:
                    try:
                        scanned = int(line.split(':')[1].strip())
                    except:
                        pass
                elif "infected files:" in line_lower:
                    try:
                        infected = int(line.split(':')[1].strip())
                    except:
                        pass
            
            # Determine status
            if infected > 0:
                status = "infected"
                self.logger.warning(f"[CLAMAV] ⚠️  THREATS DETECTED: {infected} infected file(s)")
                for infected_file in infected_files[:5]:  # Show first 5
                    self.logger.warning(f"[CLAMAV]   └─ {infected_file}")
            elif scanned > 0:
                status = "clean"
                self.logger.info(f"[CLAMAV] ✓ Scan complete: No threats detected")
            else:
                status = "empty"
                self.logger.warning(f"[CLAMAV] No files were scanned")
            
            self.logger.info(f"[CLAMAV] Scanned {scanned} files")
            self.logger.info(f"[CLAMAV] Log saved to: {log_file}")
            
            return {
                "status": status,
                "infected_files": infected_files,
                "scanned": scanned,
                "infected": infected,
                "log_file": str(log_file),
                "output": result.stdout[:500] if result.stdout else ""  # First 500 chars for debugging
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("[CLAMAV] Scan timeout - drive may be too large")
            return {
                "status": "timeout",
                "infected_files": [],
                "scanned": 0,
                "infected": 0,
                "error": "Scan timeout"
            }
        except Exception as e:
            self.logger.error(f"[CLAMAV] Scan failed: {e}", exc_info=True)
            return {
                "status": "error",
                "infected_files": [],
                "scanned": 0,
                "infected": 0,
                "error": str(e)
            }
   
    def update_definitions(self):
        """Update ClamAV virus definitions using freshclam"""
        if not self.is_available():
            self.logger.warning("[CLAMAV] Update skipped - ClamAV not available")
            return False
        
        freshclam_path = self.clamscan_path.replace("clamscan", "freshclam")
        self.logger.info("[CLAMAV] Updating virus definitions...")
        
        try:
            result = subprocess.run(
                [freshclam_path],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode == 0:
                self.logger.info("[CLAMAV] ✓ Virus definitions updated successfully")
                return True
            else:
                self.logger.warning(f"[CLAMAV] Update completed with warnings: {result.stderr}")
                return True
                
        except subprocess.TimeoutExpired:
            self.logger.error("[CLAMAV] Update timeout")
            return False
        except Exception as e:
            self.logger.error(f"[CLAMAV] Update failed: {e}")
            return False


class USBQuarantine: 
    def __init__(self, quarantine_base="C:\\USB_Quarantine",debug=False):
        self.quarantine_base = Path(quarantine_base)
        self.debug = debug
        self.quarantine_base.mkdir(parents=True, exist_ok=True)
        self.known_drives = set()
        self.quarantine_drives = {}
        self.state_file = self.quarantine_base / "quarantine_state.json"
        self.running = False
        
        # Setup logging
        self.setup_logging()
        self.logger.info("="*60)
        self.logger.info("USB Quarantine System Initialized")
        self.logger.info(f"Quarantine Base Directory: {self.quarantine_base}")
        self.logger.info("="*60)
        
        self.load_state()
        self.clamav = ClamAVScanner(self.logger)
        if self.clamav.is_available():
            self.logger.info("[CLAMAV] ClamAV integration enabled")
            self.logger.info("[SECURITY] Scan-before-copy mode: ACTIVE")
        else:
            self.logger.warning("[SECURITY] ClamAV not available - operating in copy-only mode")
    '''
    def setup_logging(self):
        """Setup logging to both file and console"""
        log_file = self.quarantine_base / "quarantine.log"
        
        # Create logger
        self.logger = logging.getLogger('USBQuarantine')
        self.logger.setLevel(logging.DEBUG)
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Create file handler (logs everything)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Create console handler (logs INFO and above)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"Logging initialized. Log file: {log_file}")
        '''
    def setup_logging(self):
        """Setup logging to both file and console."""
        log_file = self.quarantine_base / "quarantine.log"
        
        # Create logger
        self.logger = logging.getLogger('USBQuarantine')
        self.logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_level = logging.DEBUG if self.debug else logging.INFO
        console_handler.setLevel(console_level)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"Logging initialized. Log file: {log_file}")
        if self.debug:
            self.logger.info("[DEBUG] Debug mode enabled")
            
            
    def is_admin(self):
        """Check if script is running with admin privileges"""
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            self.logger.debug(f"Admin check result: {is_admin}")
            return is_admin
        except Exception as e:
            self.logger.error(f"Failed to check admin privileges: {e}")
            return False
        
    def load_state(self):
        """Load previously quarantined drives state"""
        if self.state_file.exists():
            try:
                with open(self.state_file,'r') as f:
                    self.quarantine_drives = json.load(f)
                self.logger.info(f"Loaded state: {len(self.quarantine_drives)} previously quarantined drives")
                for drive, info in self.quarantine_drives.items():
                    self.logger.debug(f"  - {drive}: quarantined at {info.get('timestamp', 'unknown')}")
            except Exception as e:
                self.logger.error(f"Failed to load state file: {e}")
                self.quarantine_drives = {}
        else:
            self.logger.debug("No previous state file found")
            self.quarantine_drives = {}
    def protect_fat_drive(self, drive_path):
        """Protect FAT/exFAT drives (no ACL support)."""
        self.logger.info(f"[FAT] Protecting FAT/exFAT drive: {drive_path}")
        
        try:
            # Method 1: Set read-only attribute on all files
            self.logger.info("[FAT] Setting read-only attribute on files...")
            
            file_count = 0
            for root, dirs, files in os.walk(str(drive_path)):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        # Set read-only attribute
                        subprocess.run(f'attrib +R "{file_path}"', shell=True, 
                                      capture_output=True, timeout=5)
                        file_count += 1
                    except:
                        continue
            
            # Method 2: Create a LOCK file to indicate protection
            lock_file = os.path.join(drive_path, "USB_QUARANTINE_LOCK.txt")
            with open(lock_file, 'w') as f:
                f.write("This drive is protected by USB Quarantine System\n")
                f.write(f"Protected at: {datetime.now()}\n")
                f.write("Remove this file and reboot to unlock\n")
            
            # Make lock file read-only and hidden
            subprocess.run(f'attrib +R +H "{lock_file}"', shell=True, 
                          capture_output=True, timeout=5)
            
            self.logger.info(f"[FAT] Protected {file_count} files on FAT drive")
            return True
            
        except Exception as e:
            self.logger.error(f"[FAT] Failed to protect FAT drive: {e}")
            return False
    
    def unprotect_fat_drive(self, drive_path):
        """Remove protection from FAT/exFAT drives."""
        self.logger.info(f"[FAT] Unprotecting FAT/exFAT drive: {drive_path}")
        
        try:
            # Remove read-only attribute from all files
            file_count = 0
            for root, dirs, files in os.walk(str(drive_path)):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        # Remove read-only attribute
                        subprocess.run(f'attrib -R "{file_path}"', shell=True, 
                                      capture_output=True, timeout=5)
                        file_count += 1
                    except:
                        continue
            
            # Remove lock file
            lock_file = os.path.join(drive_path, "USB_QUARANTINE_LOCK.txt")
            if os.path.exists(lock_file):
                subprocess.run(f'attrib -R -H "{lock_file}"', shell=True, 
                              capture_output=True, timeout=5)
                os.remove(lock_file)
            
            self.logger.info(f"[FAT] Unprotected {file_count} files")
            return True
            
        except Exception as e:
            self.logger.error(f"[FAT] Failed to unprotect FAT drive: {e}")
            return False         
    def save_state(self):
        """Save quarantined drive state to file"""
        try:
            with open(self.state_file,'w') as f:
                json.dump(self.quarantine_drives, f, indent=4)
            self.logger.debug(f"State saved successfully: {len(self.quarantine_drives)} drives")
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
    
    def get_removable_drive(self): 
        """Get all removable drives on the system"""
        drives = []
        self.logger.debug("Scanning for removable drives...")
        for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    # Check if it's a removable drive using GetDriveType
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                    # DRIVE_REMOVABLE = 2 
                    if drive_type == 2:
                        drives.append(drive)
                        self.logger.debug(f"Found removable drive: {drive}")
                except Exception as e:
                    self.logger.debug(f"Error checking drive {drive}: {e}")
                    pass 
        return drives
    
    def disable_autorun(self, drive_path):
        """Disable autorun.inf to prevent automatic execution"""
        autorun_path = Path(drive_path) / "autorun.inf"
        if autorun_path.exists():
            try:
                # Make autorun.inf read-only and hidden to prevent execution
                subprocess.run(f'attrib +R +H "{autorun_path}"', shell=True, capture_output=True)
                self.logger.info(f"[SECURITY] Disabled autorun.inf on {drive_path}")
            except Exception as e:
                self.logger.warning(f"[SECURITY] Could not disable autorun: {e}")
    
    def copy_with_metadata(self, src, dst):
        """Copy file preserving metadata"""
        try:
            shutil.copy2(src, dst)
            self.logger.debug(f"Copied: {src} -> {dst}")
            return True 
        except Exception as e:
            self.logger.error(f"Failed to copy {src} to {dst}: {e}")
            return False
        
    def copy_drive_contents(self, drive_path, quarantine_path):
        """Copy all files from USB drive to Quarantine folder"""
        self.logger.info(f"[COPY] Starting file copy from {drive_path} to {quarantine_path}")
        copied = 0
        failed = 0 
        
        try:
            for root, dirs, files in os.walk(str(drive_path), topdown=True):
                rel_path = Path(root).relative_to(drive_path)
                dest_dir = quarantine_path / rel_path
                dest_dir.mkdir(parents=True, exist_ok=True)
                
                for file in files:
                    src_file = Path(root) / file
                    dest_file = dest_dir / file
                    if self.copy_with_metadata(src_file, dest_file):
                        copied += 1 
                    else:
                        failed += 1 
                
            self.logger.info(f"[COPY] Complete: {copied} files copied, {failed} failed")
        except Exception as e:
            self.logger.error(f"Error during file copy operation: {e}")
            
        return copied, failed
    
    def apply_readonly_acl(self, drive_path):
        """Apply read-only ACL to drive root."""
        self.logger.info(f"[ACL] Applying read-only ACL to {drive_path}")
        
        # First, check if we have admin privileges
        if not self.is_admin():
            self.logger.error("[ACL] ERROR: Administrative privileges required for ACL operations")
            self.logger.error("[ACL] Please run the script as Administrator")
            return False
        
        try:
            clean_path = drive_path.rstrip('\\')
            
            # Try multiple approaches for ACL
            approaches = [
                # Approach 1: Standard read-only
                f'icacls "{clean_path}" /inheritance:r /grant:r *S-1-1-0:(RX) /deny *S-1-1-0:(WD)',
                # Approach 2: Simpler method
                f'icacls "{clean_path}" /deny Everyone:(W)',
                # Approach 3: Alternative syntax
                f'icacls "{clean_path}" /deny *S-1-1-0:(W)'
            ]
            
            for i, cmd in enumerate(approaches, 1):
                self.logger.debug(f"[ACL] Trying approach {i}: {cmd}")
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    self.logger.info(f"[ACL] ✓ Successfully applied read-only ACL")
                    self.logger.debug(f"[ACL] Output: {result.stdout}")
                    return True
                else:
                    self.logger.warning(f"[ACL] Approach {i} failed: {result.stderr}")
            
            # If all approaches fail, try a simpler method
            self.logger.info("[ACL] Trying alternative method...")
            
            # Create a dummy file to test write permissions
            test_file = os.path.join(clean_path, "_quarantine_test.tmp")
            try:
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                self.logger.debug("[ACL] Write test successful before ACL")
            except:
                self.logger.debug("[ACL] Drive already read-only")
                return True  # Drive is already read-only
            
            self.logger.error("[ACL] All ACL application attempts failed")
            return False
            
        except subprocess.TimeoutExpired:
            self.logger.error("[ACL] ACL operation timeout")
            return False
        except Exception as e:
            self.logger.error(f"[ACL] Exception: {e}")
            return False
    
    def remove_readonly_acl(self, drive_path):
        """Force-remove ALL read-only and deny ACLs from a USB drive."""
        self.logger.info(f"[ACL] Removing read-only ACL from {drive_path}")

        if not self.is_admin():
            self.logger.error("[ACL] ERROR: Administrative privileges required")
            return False

        try:
            clean_path = drive_path.rstrip('\\')
            drive_letter = clean_path.replace(':', '')

            # ---------------------------------------------------------
            # STEP 0 — Check if drive exists and is accessible
            # ---------------------------------------------------------
            if not os.path.exists(clean_path):
                self.logger.error(f"[ACL] Drive {clean_path} does not exist")
                return False

            # ---------------------------------------------------------
            # STEP 1 — Unmount and remount (can help with locked drives)
            # ---------------------------------------------------------
            self.logger.info("[ACL] Attempting to refresh drive mount...")
            try:
                # This can help if drive is locked by explorer.exe
                subprocess.run(["mountvol", clean_path, "/P"], capture_output=True)
            except:
                pass

            # ---------------------------------------------------------
            # STEP 2 — Clear volume-level READONLY using DISKPART
            # ---------------------------------------------------------
            self.logger.info("[ACL] Clearing volume-level readonly attribute...")
            try:
                script = f"""
                select volume {drive_letter}
                attributes volume clear readonly
                exit
                """
                tmp = "diskpart_clear_readonly.txt"
                with open(tmp, "w") as f:
                    f.write(script)
                
                result = subprocess.run(
                    ["diskpart", "/s", tmp], 
                    capture_output=True, 
                    text=True, 
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Check for errors in diskpart output
                if "The volume is in use by another process" in result.stdout:
                    self.logger.warning("[ACL] Volume in use, trying to close handles...")
                    # Try to close open handles
                    subprocess.run(["handle.exe", "-p", "explorer.exe", "-a", "-c", clean_path], 
                                capture_output=True, shell=True)
                
                os.remove(tmp)
            except Exception as e:
                self.logger.warning(f"[ACL] Diskpart readonly clear failed: {e}")

            # ---------------------------------------------------------
            # STEP 3 — Check for physical write-protection
            # ---------------------------------------------------------
            self.logger.info("[ACL] Checking disk attributes...")
            try:
                # Use diskpart to check disk attributes
                script = f"""
                list disk
                select disk (find disk where drive letter={drive_letter})
                detail disk
                exit
                """
                tmp = "diskpart_check.txt"
                with open(tmp, "w") as f:
                    f.write(script)
                
                result = subprocess.run(
                    ["diskpart", "/s", tmp], 
                    capture_output=True, 
                    text=True, 
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if "Read-only" in result.stdout:
                    self.logger.error("[ACL] DISK is physically read-only! Check USB switch.")
                    return False
                    
                os.remove(tmp)
            except:
                pass

            # ---------------------------------------------------------
            # STEP 4 — Check filesystem and attempt repair
            # ---------------------------------------------------------
            self.logger.info("[ACL] Checking filesystem health...")
            try:
                chkdsk_cmd = f'chkdsk {clean_path} /F'
                result = subprocess.run(chkdsk_cmd, shell=True, capture_output=True, text=True)
                if "Cannot lock current drive" in result.stdout:
                    self.logger.warning("[ACL] Could not lock drive for repair (in use)")
            except Exception as e:
                self.logger.warning(f"[ACL] CHKDSK failed: {e}")

            # ---------------------------------------------------------
            # STEP 5 — TAKEOWN (take full ownership)
            # ---------------------------------------------------------
            self.logger.info("[ACL] Taking ownership recursively...")
            try:
                takeown_cmd = f'takeown /F "{clean_path}" /R /D Y'
                subprocess.run(takeown_cmd, shell=True, capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired:
                self.logger.warning("[ACL] Takeown timed out (many files?)")

            # ---------------------------------------------------------
            # STEP 6 — Remove ALL DENY ACEs using icacls
            # ---------------------------------------------------------
            self.logger.info("[ACL] Removing DENY permissions...")
            deny_list = ["Everyone", "Users", "Authenticated Users", "*S-1-1-0", "BUILTIN\\Users"]
            
            for identity in deny_list:
                try:
                    cmd = f'icacls "{clean_path}" /remove:d "{identity}" /T /C /Q'
                    subprocess.run(cmd, shell=True, capture_output=True, text=True)
                except:
                    pass

            # ---------------------------------------------------------
            # STEP 7 — FULL ACL RESET (most powerful)
            # ---------------------------------------------------------
            self.logger.info("[ACL] Resetting ACLs to inherit from parent...")
            reset_cmd = f'icacls "{clean_path}" /inheritance:e /T /C /Q'
            subprocess.run(reset_cmd, shell=True, capture_output=True, text=True)

            # ---------------------------------------------------------
            # STEP 8 — Grant full access to Everyone
            # ---------------------------------------------------------
            self.logger.info("[ACL] Granting full permissions to Everyone...")
            grant_cmd = f'icacls "{clean_path}" /grant:r Everyone:(OI)(CI)F /T /C /Q'
            subprocess.run(grant_cmd, shell=True, capture_output=True, text=True)

            # ---------------------------------------------------------
            # STEP 9 — Clear file-level READONLY attribute
            # ---------------------------------------------------------
            self.logger.info("[ACL] Clearing read-only file attribute...")
            attrib_cmd = f'attrib -r -s -h "{clean_path}\\*.*" /s /d'
            subprocess.run(attrib_cmd, shell=True, capture_output=True, text=True)

            # ---------------------------------------------------------
            # STEP 10 — Force directory creation test (more reliable)
            # ---------------------------------------------------------
            self.logger.info("[ACL] Testing write permissions...")
            test_dir = os.path.join(clean_path, "_write_test_dir")
            test_file = os.path.join(test_dir, "test.txt")
            
            try:
                # Try to create a directory and file
                os.makedirs(test_dir, exist_ok=True)
                with open(test_file, 'w') as f:
                    f.write("write test")
                os.remove(test_file)
                os.rmdir(test_dir)
                
                # Also test root directory
                root_test = os.path.join(clean_path, "_root_test.txt")
                with open(root_test, 'w') as f:
                    f.write("root test")
                os.remove(root_test)
                
                self.logger.info("[ACL] ✓ ACL successfully removed — write tests passed")
                return True
            except Exception as e:
                self.logger.error(f"[ACL] Write test failed: {e}")
                
                # Try one more aggressive approach - format if empty?
                try:
                    # Check if drive is empty (safe to format?)
                    files = os.listdir(clean_path)
                    if len(files) == 0:
                        self.logger.warning("[ACL] Drive is empty. Formatting might be needed.")
                except:
                    pass
                
                return False

        except Exception as e:
            self.logger.error(f"[ACL] Exception: {e}")
            import traceback
            self.logger.error(f"[ACL] Traceback: {traceback.format_exc()}")
            return False
        
        def is_admin(self):
            """Check if script is running with admin privileges - IMPROVED VERSION"""
            try:
                # Method 1: Windows API
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                
                # Method 2: Try to write to protected location
                if is_admin:
                    try:
                        # Try to write to Windows directory
                        test_file = "C:\\Windows\\Temp\\_admin_test.tmp"
                        with open(test_file, 'w') as f:
                            f.write("test")
                        os.remove(test_file)
                        self.logger.debug("[ADMIN] Admin check confirmed via write test")
                    except:
                        is_admin = False
                        self.logger.warning("[ADMIN] Admin check failed write test")
                
                self.logger.debug(f"[ADMIN] Admin check result: {is_admin}")
                return is_admin
            except Exception as e:
                self.logger.error(f"[ADMIN] Failed to check admin privileges: {e}")
                return False
        
   


    def quarantine_drive(self, drive_path, scan_collect_findings=False, max_files=None):
        """Quarantine a new USB drive with proper scanning order"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        drive_letter = str(drive_path).rstrip(":\\")
        quarantine_name = f"{drive_letter}_{timestamp}"
        quarantine_path = self.quarantine_base / quarantine_name

        self.logger.info("=" * 60)
        self.logger.info(f"[NEW DRIVE] Detected: {drive_path}")
        self.logger.info("=" * 60)

        try:
            # STEP 1: DISABLE AUTORUN (Safe to do first)
            self.logger.info("[SECURITY] STEP 1: Disabling autorun...")
            self.disable_autorun(drive_path)
            self.logger.info("[SECURITY] ✓ Autorun disabled")

            # STEP 2: SCAN FIRST (Before locking!)
            self.logger.info("[SECURITY] STEP 2: Scanning drive for threats...")
            
            # Heuristic scan
            heuristic_scanner = HeuristicScanner(self.logger)
            heuristic_result = heuristic_scanner.scan_drive(
                str(drive_path), 
                collect_findings=scan_collect_findings,
                max_files=max_files
            )
            
            # ClamAV scan
            clamav_result = self.clamav.scan_drive(drive_path)
            
            # STEP 3: ANALYZE RESULTS
            self.logger.info("[SECURITY] STEP 3: Analyzing scan results...")
            
            heuristic_threat = heuristic_result.get('status', 'CLEAN')
            clamav_status = clamav_result.get('status', '').lower()
            
            is_infected = (clamav_status == "infected" or 
                          heuristic_threat in ['CRITICAL', 'HIGH'])
            
            if is_infected:
                # INFECTED - LOCK BUT DON'T COPY
                self.logger.error("=" * 60)
                self.logger.error("⚠️  THREATS DETECTED ⚠️")
                self.logger.error("=" * 60)
                
                if clamav_status == "infected":
                    self.logger.error(f"[CLAMAV] {clamav_result.get('infected', 0)} infected file(s)")
                    for infected_file in clamav_result.get('infected_files', [])[:5]:
                        self.logger.error(f"[CLAMAV]   └─ {infected_file}")
                
                if heuristic_threat in ['CRITICAL', 'HIGH']:
                    self.logger.error(f"[HEURISTIC] Threat level: {heuristic_threat}")
                    self.logger.error(f"[HEURISTIC] {heuristic_result.get('suspicious_files', 0)} suspicious files")
                
                # STEP 4: LOCK INFECTED DRIVE
                self.logger.info("[SECURITY] STEP 4: Locking infected drive...")
                if self.apply_readonly_acl(drive_path):
                    self.logger.info("[SECURITY] ✓ Drive locked (read-only)")
                
                # Save state
                self.quarantine_drives[drive_path] = {
                    "quarantine_path": "NOT_COPIED_INFECTED",
                    "timestamp": timestamp,
                    "files_copied": 0,
                    "files_failed": 0,
                    "scan_status": "infected",
                    "heuristic_status": heuristic_threat,
                    "clamav_status": clamav_status,
                    "threat_level": "HIGH",
                    "log_file": clamav_result.get("log_file", "N/A")
                }
                self.save_state()
                
                self.logger.info("=" * 60)
                return False
                
            else:
                # CLEAN - PROCEED WITH QUARANTINE
                self.logger.info("=" * 60)
                self.logger.info("✓ CLEAN USB DRIVE")
                self.logger.info("=" * 60)
                
                # STEP 4: CREATE QUARANTINE DIRECTORY
                quarantine_path.mkdir(parents=True, exist_ok=True)
                
                # STEP 5: COPY FILES (drive is still unlocked for copying)
                self.logger.info("[SECURITY] STEP 5: Copying files to quarantine...")
                copied, failed = self.copy_drive_contents(drive_path, quarantine_path)
                
                # STEP 6: LOCK THE ORIGINAL DRIVE
                self.logger.info("[SECURITY] STEP 6: Locking original drive...")
                if self.apply_readonly_acl(drive_path):
                    self.logger.info("[SECURITY] ✓ Drive locked (read-only)")
                
                # Save state
                self.quarantine_drives[drive_path] = {
                    "quarantine_path": str(quarantine_path),
                    "timestamp": timestamp,
                    "files_copied": copied,
                    "files_failed": failed,
                    "scan_status": "clean",
                    "heuristic_status": heuristic_threat,
                    "clamav_status": clamav_status,
                    "threat_level": "CLEAN",
                    "log_file": clamav_result.get("log_file", "N/A")
                }
                self.save_state()
                
                self.logger.info(f"[SUCCESS] Drive {drive_path} quarantined successfully!")
                self.logger.info(f"[INFO] Files copied: {copied}, failed: {failed}")
                self.logger.info("[INFO] Use 'python usb_quarantine.py revert' to unlock")
                self.logger.info("=" * 60)
                return True
                
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to quarantine drive {drive_path}: {e}", exc_info=True)
            # Try to lock the drive even on error
            try:
                self.apply_readonly_acl(drive_path)
                self.logger.info("[SECURITY] Drive locked despite error")
            except:
                pass
            return False


    def copy_drive_contents(self, src_drive, dest_dir, buffer_size=16 * 1024 * 1024):
        """
        Copy files from src_drive to dest_dir in chunked mode to avoid big memory usage.
        - buffer_size: number of bytes to copy per iteration (default 16MB)
        Returns: (copied_count, failed_count)
        """
        src_drive = Path(src_drive)
        dest_dir = Path(dest_dir)
        copied = 0
        failed = 0

        # Walk the drive and copy file-by-file using streaming
        for root, dirs, files in os.walk(src_drive):
            # Recreate directory structure in dest_dir
            rel_root = os.path.relpath(root, src_drive)
            target_root = dest_dir / rel_root
            try:
                target_root.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.warning(f"[COPY] Failed to create directory {target_root}: {e}")

            for fname in files:
                src_file = Path(root) / fname
                dst_file = target_root / fname

                try:
                    # Skip special files, symlinks and device files
                    if src_file.is_symlink():
                        self.logger.debug(f"[COPY] Skipping symlink: {src_file}")
                        continue
                    # Use open+shutil.copyfileobj to stream content in chunks
                    with open(src_file, 'rb') as sf, open(dst_file, 'wb') as df:
                        shutil.copyfileobj(sf, df, length=buffer_size)
                    # Preserve metadata where possible
                    try:
                        shutil.copystat(src_file, dst_file)
                    except Exception:
                        pass
                    copied += 1
                except PermissionError as e:
                    self.logger.warning(f"[COPY] PermissionError copying {src_file}: {e}")
                    failed += 1
                except Exception as e:
                    self.logger.error(f"[COPY] Failed to copy {src_file}: {e}", exc_info=True)
                    failed += 1

        self.logger.info(f"[COPY] Files copied: {copied}, failed: {failed}")
        return copied, failed

                
    def monitor_loop(self):
        """Main monitoring loop"""
        self.logger.info("="*60)
        self.logger.info("USB Quarantine Monitor Started")
        self.logger.info("="*60 + "\n")
        
        self.known_drives = set(self.get_removable_drive())
        if self.known_drives:
            self.logger.info(f"[INIT] Current drives: {', '.join(self.known_drives)}")
        else:
            self.logger.info("[INIT] No removable drives connected")
        
        while self.running:
            try:
                current_drives = set(self.get_removable_drive())
                new_drives = current_drives - self.known_drives
                
                if new_drives:
                    self.logger.info(f"[DETECTED] New drives: {', '.join(new_drives)}")
                    for drive in new_drives:
                        self.logger.info(f"[PROCESSING] Starting quarantine for {drive}")
                        if self.quarantine_drive(drive):
                            self.logger.info(f"[COMPLETE] {drive} quarantined successfully")
                        else:
                            self.logger.warning(f"[COMPLETE] {drive} quarantine failed or infected")
                
                removed_drives = self.known_drives - current_drives
                if removed_drives:
                    for drive in removed_drives:
                        self.logger.info(f"[REMOVED] {drive}")
                
                self.known_drives = current_drives
                time.sleep(2)
                
            except KeyboardInterrupt:
                self.logger.info("\n[INFO] Stopping monitor...")
                break
            except Exception as e:
                self.logger.error(f"[ERROR] Monitor loop error: {e}")
                time.sleep(5)
                
    def start(self):
        """Start the monitoring service""" 
        if not self.is_admin():
            self.logger.error("[ERROR] This script requires administrative privileges to run.")
            self.logger.error("[INFO] Please run the script as an administrator.")
            return 
        
        self.running = True 
        try:
            self.monitor_loop()
        except KeyboardInterrupt:
            self.logger.info("\n[INFO] Monitoring stopped by user. Exiting...")
        finally:
            self.running = False 
            self.logger.info("[INFO] Monitor stopped") 
            
    def revert_drive(self, drive_path): 
        """Remove read-only protection from a drive""" 
        self.logger.info(f"[REVERT] Attempting to revert drive: {drive_path}")
        
        if drive_path in self.quarantine_drives:
            info = self.quarantine_drives[drive_path]
            
            # Warn if drive was infected
            if info.get("scan_status") == "infected":
                self.logger.error("="*60)
                self.logger.error("⚠️  WARNING: INFECTED DRIVE ⚠️")
                self.logger.error("="*60)
                self.logger.error(f"This drive was flagged as INFECTED!")
                self.logger.error(f"Infected files: {len(info.get('infected_files', []))}")
                self.logger.error("Unlocking this drive may expose your system to malware!")
                self.logger.error("="*60)
                response = input("Are you SURE you want to unlock this drive? (type 'YES' to confirm): ")
                if response != "YES":
                    self.logger.info("[CANCELLED] Drive remains locked")
                    return False
            
            self.logger.info(f"[REVERT] Removing read-only protection from {drive_path}")
            if self.remove_readonly_acl(drive_path):
                removed_info = self.quarantine_drives.pop(drive_path)
                self.save_state()
                self.logger.info(f"[SUCCESS] Drive {drive_path} reverted successfully")
                self.logger.info(f"[INFO] Quarantine data preserved at: {removed_info.get('quarantine_path', 'N/A')}")
                return True
            else:
                self.logger.error(f"[ERROR] Failed to remove ACL from {drive_path}")
                return False
        else:
            self.logger.warning(f"[WARNING] Drive {drive_path} not found in quarantine records")
            if self.remove_readonly_acl(drive_path):
                self.logger.info(f"[INFO] ACL removed successfully")
                return True
            return False
    
    def revert_all(self):
        """Remove read-only protection from all quarantined drives""" 
        self.logger.info(f"[REVERT ALL] Starting revert for {len(self.quarantine_drives)} drives")
        
        if not self.quarantine_drives:
            self.logger.info("[INFO] No drives to revert")
            return
        
        # Check if any infected drives exist
        infected_count = sum(1 for info in self.quarantine_drives.values() 
                           if info.get('scan_status') == 'infected')
        
        if infected_count > 0:
            self.logger.error(f"⚠️  WARNING: {infected_count} infected drive(s) will be unlocked!")
            response = input("Type 'YES' to confirm reverting ALL drives: ")
            if response != "YES":
                self.logger.info("[CANCELLED] No drives were reverted")
                return
            
        for drive_path in list(self.quarantine_drives.keys()):
            self.revert_drive(drive_path)
        self.logger.info("[REVERT ALL] Completed\n")
        
    def list_quarantined(self):
        """List all quarantined drives"""
        if not self.quarantine_drives:
            self.logger.info("[INFO] No drives currently quarantined")
            return
        
        self.logger.info("="*60)
        self.logger.info(f"Quarantined Drives: ({len(self.quarantine_drives)})")
        self.logger.info("="*60)
        
        for drive, info in self.quarantine_drives.items():
            status_icon = "⚠️" if info.get('scan_status') == 'infected' else "✓"
            self.logger.info(f"\n{status_icon} Drive: {drive}")
            self.logger.info(f"  Status: {info.get('scan_status', 'unknown').upper()}")
            self.logger.info(f"  Threat Level: {info.get('threat_level', 'UNKNOWN')}")
            self.logger.info(f"  Quarantined: {info.get('timestamp', 'unknown')}")
            self.logger.info(f"  Location: {info.get('quarantine_path', 'unknown')}")
            self.logger.info(f"  Files: {info.get('files_copied', 0)} copied, {info.get('files_failed', 0)} failed")
            self.logger.info(f"  Scan: {info.get('scan_summary', 'N/A')}")
            if info.get('infected_files'):
                self.logger.info(f"  Infected files: {len(info['infected_files'])}")
        self.logger.info("="*60 + "\n")
        

def main():
    """Main function to run USB quarantine and safe file operations."""
    
    # Parse command line arguments
    debug_mode = '--debug' in sys.argv

    # -------------------------------
    # COMMAND MODE (User passed args)
    # -------------------------------
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        cmd = sys.argv[1].lower()

        # ---------------- REVERT ----------------
        if cmd == "revert":
            quarantine = USBQuarantine(debug=debug_mode)
            if len(sys.argv) > 2:
                drive = sys.argv[2].upper()
                if not drive.endswith(":\\"):
                    drive += ":\\"
                quarantine.revert_drive(drive)
            else:
                quarantine.revert_all()

        # ---------------- LIST ----------------
        elif cmd == "list":
            quarantine = USBQuarantine(debug=debug_mode)
            quarantine.list_quarantined()

        # ---------------- UPDATE ----------------
        elif cmd == "update":
            print("Updating ClamAV virus definitions...")
            quarantine = USBQuarantine(debug=debug_mode)
            if quarantine.clamav.update_definitions():
                print("✓ Definitions updated successfully")
            else:
                print("✗ Definition update failed")

        # ---------------- TEST ----------------
        elif cmd == "test":
            if len(sys.argv) > 2:
                test_drive = sys.argv[2]
            else:
                test_drive = os.getcwd()

            print(f"\nTesting on: {test_drive}")
            print("=" * 60)

            quarantine = USBQuarantine(debug=True)

            if not quarantine.is_admin():
                print("\n❌ ERROR: Run as Administrator!")
                return

            print("\n[TEST 1/3] Testing file scanner...")
            test_file = os.path.join(test_drive, "_test_file.txt")
            with open(test_file, 'w') as f:
                f.write("Test content for scanning")

            heuristic = HeuristicScanner(quarantine.logger)
            result = heuristic.scan_drive(test_drive, max_files=5)
            print(f"✓ Scanned {result.get('total_files', 0)} files")

            print("\n[TEST 2/3] Testing ACL operations...")
            if quarantine.apply_readonly_acl(test_drive):
                print("✓ ACL applied successfully")

                if quarantine.remove_readonly_acl(test_drive):
                    print("✓ ACL removed successfully")
                else:
                    print("✗ ACL removal failed")
            else:
                print("✗ ACL application failed")

            try:
                os.remove(test_file)
            except:
                pass

            print("\n[TEST 3/3] Testing ClamAV...")
            if quarantine.clamav.is_available():
                print("✓ ClamAV is available")
                result = quarantine.clamav.scan_drive(test_drive)
                print(f"ClamAV scan result: {result.get('status', 'unknown')}")
            else:
                print("✗ ClamAV not available")

            print("\n" + "=" * 60)
            print("Test complete!")

        # ---------------- SCAN ----------------
        elif cmd == "scan":
            if len(sys.argv) > 2:
                target_path = sys.argv[2]
            else:
                target_path = os.getcwd()

            print(f"\nManual scan of: {target_path}")
            print("=" * 60)

            quarantine = USBQuarantine(debug=True)

            print("\n[HEURISTIC SCAN]")
            heuristic = HeuristicScanner(quarantine.logger)
            h_result = heuristic.scan_drive(target_path, max_files=50)
            print(f"Status: {h_result.get('status', 'UNKNOWN')}")
            print(f"Files scanned: {h_result.get('total_files', 0)}")
            print(f"Suspicious files: {h_result.get('suspicious_files', 0)}")

            print("\n[CLAMAV SCAN]")
            if quarantine.clamav.is_available():
                c_result = quarantine.clamav.scan_drive(target_path)
                print(f"Status: {c_result.get('status', 'UNKNOWN')}")
                print(f"Files scanned: {c_result.get('scanned', 0)}")
                print(f"Infected files: {c_result.get('infected', 0)}")
            else:
                print("ClamAV not available")

            print("\n" + "=" * 60)
            print("Scan complete!")

        # ---------------- COPY ----------------
        elif cmd == "copy":
            if len(sys.argv) > 3:
                source_directory = sys.argv[2]
                protected_directory = sys.argv[3]
            else:
                source_directory = "source_folder"
                protected_directory = "protected_folder"

            if not os.path.exists(source_directory):
                print(f"❌ Error: Source directory '{source_directory}' does not exist")
                sys.exit(1)

            copier = SafeFileCopier()

            print("Starting safe file copy...")
            print(f"Source: {source_directory}")
            print(f"Destination: {protected_directory}")
            print("-" * 60)

            copier.copy_safe_files(source_directory, protected_directory)
            copier.print_summary()

        # ---------------- DIAGNOSE ----------------
        elif cmd == "diagnose":
            if len(sys.argv) > 2:
                target_drive = sys.argv[2]
            else:
                target_drive = "D:\\"

            print(f"\nDiagnosing scanning issues on: {target_drive}")
            print("=" * 70)

            quarantine = USBQuarantine(debug=True)
            drive_path = Path(target_drive)

            # Path validity
            if not drive_path.exists():
                print(f"❌ Drive does not exist: {target_drive}")
                return

            if not drive_path.is_dir():
                print(f"❌ Not a directory: {target_drive}")
                return

            print("\n[1/5] Drive information:")
            print(f"  Path: {drive_path}")

            try:
                import win32api
                info = win32api.GetVolumeInformation(str(drive_path))
                print(f"  Volume name: {info[0]}")
                print(f"  Serial: {info[1]}")
                print(f"  Filesystem: {info[4]}")
            except:
                print("  No filesystem info (pywin32 missing or unsupported).")

            # Directory listings
            print("\n[2/5] Testing directory access...")
            try:
                items = os.listdir(str(drive_path))
                print(f"  os.listdir OK ({len(items)} items)")
            except Exception as e:
                print(f"  os.listdir FAILED: {e}")

            print("\n[3/5] Testing file scanning...")
            heuristic = HeuristicScanner(quarantine.logger)
            scan_res = heuristic.scan_drive(target_drive, max_files=10)
            print(f"  Heuristic scan status: {scan_res.get('status')}")

            print("\n[4/5] Testing ClamAV...")
            if quarantine.clamav.is_available():
                c = quarantine.clamav.scan_drive(target_drive)
                print(f"  ClamAV status: {c.get('status')}")
            else:
                print("  ClamAV unavailable")

            print("\n[5/5] Testing write permissions...")
            test_file = drive_path / "_permission_test.tmp"
            try:
                with open(test_file, "w") as f:
                    f.write("test")
                print("  ✓ Write OK")
                test_file.unlink()
            except Exception as e:
                print(f"  ✗ Write FAILED: {e}")

            print("\nDiagnosis complete!")
            return

        # ---------------- HELP ----------------
        elif cmd in ["help", "--help", "-h"]:
            print_help()

        # ---------------- UNKNOWN COMMAND ----------------
        else:
            print(f"❌ Unknown command: '{cmd}'")
            print_help()

        return  # End command mode

    # -------------------------------
    # DEFAULT MODE (No arguments)
    # -------------------------------
    print("\n" + "=" * 60)
    print("USB QUARANTINE SYSTEM")
    print("=" * 60)

    print("\n[INFO] Checking privileges...")
    quarantine = USBQuarantine(debug=debug_mode)

    if not quarantine.is_admin():
        print("❌ ERROR: Administrator privileges required!")
        return

    print("\n[INFO] Starting monitor...")
    print("Press Ctrl+C to stop.\n")

    try:
        quarantine.start()
    except KeyboardInterrupt:
        print("\n[INFO] Monitor stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if debug_mode:
            traceback.print_exc()


def print_help():
    """Display help information."""
    print("\nUSB Quarantine & File Scanner - Help")
    print("=" * 60)
    print("\nUsage: python usb_quarantine.py [command] [options]")
    print("\nCommands:")
    print("  (no command)              - Start USB monitoring")
    print("  list                      - List all quarantined drives")
    print("  revert [drive]            - Revert specific drive (e.g., E:) or all")
    print("  update                    - Update ClamAV virus definitions")
    print("  diagnose [drive]          - Diagnose scanning issues on drive")
    print("  test [path]               - Test scanner and ACL on path")
    print("  scan <path>               - Manually scan a directory")
    print("  copy [source] [dest]      - Copy safe files from source to destination")
    print("  help                      - Show this help message")
    print("\nOptions:")
    print("  --debug                   - Enable debug output")
    print("\nExamples:")
    print("  python usb_quarantine.py --debug")
    print("  python usb_quarantine.py diagnose D:\\")
    print("  python usb_quarantine.py test D:\\")
    print("  python usb_quarantine.py list")
    print()
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)