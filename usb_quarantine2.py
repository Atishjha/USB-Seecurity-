import os 
import time 
import shutil 
import subprocess
import threading 
import winreg
import psutil
from typing import Set, Dict, List, Tuple, Optional
from datetime import datetime
from pathlib import Path
import json 
import ctypes
import sys 
import logging
from collections import Counter
import math
import traceback
import hashlib
import tempfile
import zipfile
import mimetypes
from dataclasses import dataclass
from enum import Enum
import win32api
import win32file
import win32con
import win32security
import pywintypes
import pythoncom
import win32com.client

class ScanResult(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

@dataclass
class DeviceMetadata:
    """Metadata for detected USB device"""
    drive_letter: str
    vendor_id: Optional[str]
    product_id: Optional[str]
    serial_number: Optional[str]
    device_type: str
    capacity: int
    filesystem: str
    mount_time: datetime
    vid_pid: str

@dataclass
class ScanPolicy:
    """Policy configuration for scanning"""
    enable_clamav: bool = True
    enable_heuristic: bool = True
    enable_sandbox: bool = False
    max_file_size_mb: int = 100
    allowed_extensions: Set[str] = None
    blocked_extensions: Set[str] = None
    quarantine_threshold: float = 0.7  # 70% suspicious = quarantine
    transfer_mode: str = "strict"  # strict, moderate, permissive
    
    def __post_init__(self):
        if self.allowed_extensions is None:
            self.allowed_extensions = {'.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png', '.gif'}
        if self.blocked_extensions is None:
            self.blocked_extensions = {'.exe', '.bat', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif', '.com'}

class DeviceController:
    """Control USB device mounting and access"""
    
    def __init__(self, logger):
        self.logger = logger
        self.mounted_devices: Dict[str, DeviceMetadata] = {}
        
    def get_device_metadata(self, drive_path: str) -> Optional[DeviceMetadata]:
        """Extract USB device metadata with registry-only device correlation"""
        try:
            drive_path = drive_path.rstrip('\\')
            
            # Check if it's a removable drive
            drive_type = win32file.GetDriveType(drive_path)
            if drive_type != win32file.DRIVE_REMOVABLE:
                return None
            
            # Get volume information
            try:
                vol_name, vol_serial, max_comp_len, flags, filesystem = win32api.GetVolumeInformation(drive_path)
            except Exception as e:
                self.logger.debug(f"Volume info error: {e}")
                filesystem = "UNKNOWN"
            
            # Get disk capacity using better method
            capacity = 0
            try:
                # Method 1: Use GetDiskFreeSpaceEx for total space
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(drive_path),
                    None,
                    ctypes.pointer(total_bytes),
                    ctypes.pointer(free_bytes)
                )
                capacity = total_bytes.value
            except:
                # Method 2: Fallback to old method
                try:
                    sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters = \
                        win32file.GetDiskFreeSpace(drive_path)
                    capacity = total_clusters * sectors_per_cluster * bytes_per_sector
                except:
                    pass
            
            # Get the specific USB device info for THIS drive using registry only
            vid = "UNKNOWN"
            pid = "UNKNOWN"
            serial = None
            vid_pid = "UNKNOWN_UNKNOWN"
            
            try:
                # Method 1: Try to get volume GUID and match with USB devices
                import winreg
                
                drive_letter = drive_path.rstrip('\\')
                
                # Get volume GUID for this drive
                volume_guid = None
                vol_path = f"\\\\?\\{drive_letter}"
                buf = ctypes.create_unicode_buffer(1024)
                if ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(
                    vol_path, buf, ctypes.sizeof(buf)
                ):
                    volume_guid = buf.value.rstrip('\\')
                
                if volume_guid:
                    # Method 1A: Try to find the USB device by matching MountedDevices with USBSTOR
                    usb_info = self._find_usb_by_volume_guid(volume_guid, drive_letter)
                    if usb_info:
                        vid, pid, serial = usb_info
                    else:
                        # Method 1B: Fallback to general USB device matching
                        usb_info = self._find_usb_device_for_drive(drive_letter)
                        if usb_info:
                            vid, pid, serial = usb_info
                else:
                    # Method 2: Direct USB device lookup
                    usb_info = self._find_usb_device_for_drive(drive_letter)
                    if usb_info:
                        vid, pid, serial = usb_info
                
                vid_pid = f"{vid}_{pid}"
                
            except Exception as reg_error:
                self.logger.debug(f"Registry method failed: {reg_error}")
                # Continue with default values
            
            # Create metadata object
            metadata = DeviceMetadata(
                drive_letter=drive_path,
                vendor_id=vid if vid != "UNKNOWN" else None,
                product_id=pid if pid != "UNKNOWN" else None,
                serial_number=serial,
                device_type="USB",
                capacity=capacity,
                filesystem=filesystem,
                mount_time=datetime.now(),
                vid_pid=vid_pid
            )
            
            self.logger.info(
                f"[DEVICE] Detected: {drive_path} "
                f"(FS: {filesystem}, "
                f"Size: {capacity//(1024**3):,}GB, "
                f"VID/PID: {vid_pid})"
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"[DEVICE] Failed to get metadata for {drive_path}: {e}")
            self.logger.debug(traceback.format_exc())
            return None

    def _find_usb_by_volume_guid(self, volume_guid: str, drive_letter: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """Find USB device by matching volume GUID in registry"""
        try:
            import winreg
            
            # Step 1: Find which mounted device corresponds to our drive letter
            reg_base = r"SYSTEM\MountedDevices"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_base) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):  # Number of values
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        
                        # Check if this is our drive letter or volume GUID
                        if f"\\DosDevices\\{drive_letter}:" in value_name or volume_guid in str(value_data):
                            # Found our device, now try to find USB info
                            
                            # Step 2: Search USBSTOR for matching devices
                            usb_info = self._search_usbstor_for_device()
                            if usb_info:
                                return usb_info
                                
                    except:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"_find_usb_by_volume_guid failed: {e}")
        
        return None

    def _find_usb_device_for_drive(self, drive_letter: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """Find USB device info for a drive letter"""
        try:
            import winreg
            
            # Method 1: Look for recently connected USB devices that might match
            usb_devices = self._enumerate_usb_devices()
            
            if usb_devices:
                # Return the first USB device found (most likely the current one)
                # In a real implementation, you'd need to match by serial or other identifier
                device = usb_devices[0]
                return device.get('vendor_id', 'UNKNOWN'), device.get('product_id', 'UNKNOWN'), device.get('serial')
            
            # Method 2: Check for any USB storage devices
            return self._search_usbstor_for_device()
            
        except Exception as e:
            self.logger.debug(f"_find_usb_device_for_drive failed: {e}")
            return None

    def _enumerate_usb_devices(self) -> List[Dict]:
        """Enumerate all USB storage devices from registry"""
        devices = []
        
        try:
            import winreg
            
            # USB storage devices are under USBSTOR
            usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path) as usbstor_key:
                vendor_idx = 0
                while True:
                    try:
                        vendor_key_name = winreg.EnumKey(usbstor_key, vendor_idx)
                        
                        with winreg.OpenKey(usbstor_key, vendor_key_name) as vendor_key:
                            product_idx = 0
                            while True:
                                try:
                                    product_key_name = winreg.EnumKey(vendor_key, product_idx)
                                    
                                    # Parse the device information
                                    # Format: Disk&Ven_VendorName&Prod_ProductName&Rev_Revision
                                    vendor_parts = vendor_key_name.split('&')
                                    
                                    vid = "UNKNOWN"
                                    pid = "UNKNOWN"
                                    serial = None
                                    
                                    for part in vendor_parts:
                                        part_upper = part.upper()
                                        if part_upper.startswith('VEN_'):
                                            vid = part[4:]  # Remove 'Ven_' prefix
                                        elif part_upper.startswith('PROD_'):
                                            pid = part[5:]  # Remove 'Prod_' prefix
                                    
                                    # Check for instances to get serial
                                    try:
                                        with winreg.OpenKey(vendor_key, product_key_name) as product_key:
                                            instance_idx = 0
                                            while True:
                                                try:
                                                    instance_key_name = winreg.EnumKey(product_key, instance_idx)
                                                    # Instance format often includes serial
                                                    if '&' in instance_key_name:
                                                        serial_parts = instance_key_name.split('&')
                                                        if len(serial_parts) > 0:
                                                            serial = serial_parts[0]
                                                    else:
                                                        serial = instance_key_name
                                                    break
                                                except OSError:
                                                    break
                                                finally:
                                                    instance_idx += 1
                                    except:
                                        pass
                                    
                                    devices.append({
                                        'vendor_id': vid,
                                        'product_id': pid,
                                        'serial': serial,
                                        'full_path': f"{vendor_key_name}\\{product_key_name}"
                                    })
                                    
                                except OSError:
                                    break
                                finally:
                                    product_idx += 1
                                    
                    except OSError:
                        break
                    finally:
                        vendor_idx += 1
                        
        except Exception as e:
            self.logger.debug(f"_enumerate_usb_devices failed: {e}")
        
        return devices

    def _search_usbstor_for_device(self) -> Optional[Tuple[str, str, Optional[str]]]:
        """Search USBSTOR for any USB storage device"""
        devices = self._enumerate_usb_devices()
        
        if devices:
            # Return the first device found
            # Note: This assumes the first device is the current one
            # In production, you'd need better matching logic
            device = devices[0]
            return device['vendor_id'], device['product_id'], device['serial']
        
        return None

    def _find_usb_info_from_dosdevices(self, dos_name: str) -> tuple:
        """Helper to find USB info from DOS device name - updated to use registry"""
        try:
            import winreg
            
            # DOS name format: \DosDevices\D:
            if '\\DosDevices\\' in dos_name:
                # Extract drive letter
                drive_letter = dos_name.split('\\')[-1].rstrip(':')
                
                # Look for USB devices that might be associated with this drive
                # This is simplified - actual implementation would need to track
                # which USB device is mounted to which drive letter
                usb_devices = self._enumerate_usb_devices()
                
                if usb_devices:
                    # For now, return the first USB device
                    device = usb_devices[0]
                    return device.get('vendor_id', 'UNKNOWN'), device.get('product_id', 'UNKNOWN'), device.get('serial')
                    
        except Exception as e:
            self.logger.debug(f"_find_usb_info_from_dosdevices failed: {e}")
        
        return "UNKNOWN", "UNKNOWN", None
    def _find_usb_info_from_dosdevices(self, dos_name: str) -> tuple:
        """Helper to find USB info from DOS device name"""
        try:
            # DOS name format: \DosDevices\D:
            if '\\DosDevices\\' in dos_name:
                # Traverse through registry to find USB device
                reg_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as usb_key:
                    for vendor_idx in range(winreg.QueryInfoKey(usb_key)[0]):
                        vendor_key_name = winreg.EnumKey(usb_key, vendor_idx)
                        with winreg.OpenKey(usb_key, vendor_key_name) as vendor_key:
                            for product_idx in range(winreg.QueryInfoKey(vendor_key)[0]):
                                product_key_name = winreg.EnumKey(vendor_key, product_idx)
                                with winreg.OpenKey(vendor_key, product_key_name) as product_key:
                                    for instance_idx in range(winreg.QueryInfoKey(product_key)[0]):
                                        instance_key_name = winreg.EnumKey(product_key, instance_idx)
                                        # Check if this instance matches our device
                                        # This requires matching through device instance IDs
                                        pass
        except:
            return None, None, None
    
    def disable_automount(self, device_id: str) -> bool:
        """Disable Windows auto-mount for the device"""
        try:
            # Method 1: Prevent auto-run via registry
            reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            try:
                # Try to open existing key
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 0xFF)
                    self.logger.info("[DEVICE] Disabled AutoRun for removable drives")
            except FileNotFoundError:
                # Key doesn't exist, create it
                try:
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
                    winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 0xFF)
                    winreg.CloseKey(key)
                    self.logger.info("[DEVICE] Created registry key and disabled AutoRun")
                except Exception as reg_error:
                    self.logger.warning(f"[DEVICE] Failed to create registry key: {reg_error}")
            except Exception as reg_error:
                self.logger.warning(f"[DEVICE] Registry error: {reg_error}")
            
            # Method 2: Use diskpart to set attributes (if admin)
            try:
                # First, we need to find the volume number for this drive
                drive_letter = device_id.rstrip(':').upper()
                
                # Create a temporary file for diskpart script
                import tempfile
                import os
                
                # Step 1: List volumes to find our drive
                list_script = """list volume
    exit
    """
                
                # Write list script to temp file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(list_script)
                    list_script_path = f.name
                
                # Run diskpart to list volumes
                list_result = subprocess.run(
                    ["diskpart", "/s", list_script_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=True,
                    encoding='cp437'  # Diskpart uses CP437 encoding
                )
                
                # Clean up temp file
                os.unlink(list_script_path)
                
                # Parse output to find volume number
                volume_number = None
                for line in list_result.stdout.split('\n'):
                    if drive_letter in line and "Removable" in line:
                        # Line looks like: "Volume 3     E   Removable  USB Device"
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            try:
                                volume_number = parts[1]
                                break
                            except (IndexError, ValueError):
                                continue
                
                if volume_number:
                    # Create the actual diskpart script
                    diskpart_script = f"""select volume {volume_number}
    attributes volume set readonly
    exit
    """
                    
                    # Write script to temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                        f.write(diskpart_script)
                        script_path = f.name
                    
                    # Run diskpart with the script file
                    result = subprocess.run(
                        ["diskpart", "/s", script_path],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        shell=True,
                        encoding='cp437'
                    )
                    
                    # Clean up temp file
                    os.unlink(script_path)
                    
                    if result.returncode == 0:
                        self.logger.info(f"[DEVICE] Set volume {volume_number} ({drive_letter}:) as read-only via diskpart")
                        self.logger.debug(f"Diskpart output: {result.stdout}")
                    else:
                        self.logger.warning(f"[DEVICE] Diskpart failed: {result.stderr}")
                else:
                    self.logger.warning(f"[DEVICE] Could not find volume number for drive {drive_letter}:")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning("[DEVICE] Diskpart timeout - skipping")
            except FileNotFoundError:
                self.logger.warning("[DEVICE] diskpart.exe not found - skipping")
            except Exception as diskpart_error:
                self.logger.warning(f"[DEVICE] Diskpart error: {diskpart_error}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"[DEVICE] Failed to disable automount: {e}")
            return True  # Return True to continue anyway
    
    def mount_readonly(self, drive_path: str) -> bool:
        """Mount device as read-only with better timing and error handling"""
        try:
            clean_path = drive_path.rstrip('\\')
            
            # Wait for drive to be fully mounted/ready
            max_retries = 5
            retry_delay = 1  # seconds
            
            for attempt in range(max_retries):
                try:
                    # Test if drive is accessible
                    if os.path.exists(clean_path):
                        # Try to list a directory to ensure it's ready
                        test_list = os.listdir(clean_path)
                        self.logger.debug(f"[DEVICE] Drive {clean_path} is accessible (attempt {attempt+1})")
                        break
                    else:
                        self.logger.debug(f"[DEVICE] Drive {clean_path} not accessible yet, retrying...")
                except Exception as e:
                    self.logger.debug(f"[DEVICE] Drive test failed: {e}")
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
            
            # Use Windows API for read-only mounting instead of icacls
            try:
                import ctypes
                from ctypes import wintypes
                
                # Constants
                GENERIC_READ = 0x80000000
                FILE_SHARE_READ = 0x00000001
                OPEN_EXISTING = 3
                FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
                
                # Get handle to volume
                volume_path = f"\\\\.\\{clean_path.rstrip(':')}"
                
                handle = ctypes.windll.kernel32.CreateFileW(
                    volume_path,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    None
                )
                
                if handle != -1:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    self.logger.info(f"[DEVICE] Mounted {clean_path} as read-only using Windows API")
                    return True
                else:
                    self.logger.warning(f"[DEVICE] Windows API mount failed, falling back to permissions")
            except Exception as api_error:
                self.logger.debug(f"[DEVICE] Windows API method failed: {api_error}")
            
            # Fallback method: Set read-only attribute
            try:
                # Method 1: Use attrib command
                cmd = f'attrib +R "{clean_path}\\*" /S /D'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    self.logger.info(f"[DEVICE] Set read-only attribute on {clean_path}")
                    return True
                else:
                    self.logger.debug(f"[DEVICE] Attrib command failed: {result.stderr}")
            except Exception as attrib_error:
                self.logger.debug(f"[DEVICE] Attrib method failed: {attrib_error}")
            
            # Method 2: Simpler icacls command (original method with better error handling)
            try:
                # Grant read and execute, deny write and delete
                cmd = f'icacls "{clean_path}" /inheritance:r /grant:r Everyone:(OI)(CI)(RX) /deny Everyone:(OI)(CI)(WD,DE)'
                self.logger.debug(f"[DEVICE] Executing: {cmd}")
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
                
                if result.returncode == 0:
                    self.logger.info(f"[DEVICE] Mounted {clean_path} as read-only via icacls")
                    return True
                else:
                    # Try alternative syntax
                    alt_cmd = f'icacls "{clean_path}\\" /inheritance:r /grant:r *S-1-1-0:(OI)(CI)(RX)'
                    result = subprocess.run(alt_cmd, shell=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
                    
                    if result.returncode == 0:
                        self.logger.info(f"[DEVICE] Mounted {clean_path} as read-only (alternative syntax)")
                        return True
                    else:
                        self.logger.warning(f"[DEVICE] ACL failed for {clean_path}: {result.stderr}")
                        return False
                        
            except Exception as e:
                self.logger.error(f"[DEVICE] Failed to mount read-only: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"[DEVICE] Mount read-only general error: {e}")
            return False
    
    def unmount_device(self, drive_path: str) -> bool:
        """Safely unmount device"""
        try:
            # Remove read-only ACL first
            clean_path = drive_path.rstrip('\\')
            cmd = f'icacls "{clean_path}" /remove:d *S-1-1-0'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            
            # Eject using Windows API
            import ctypes
            from ctypes import wintypes
            
            format_message = ctypes.windll.kernel32.FormatMessageW
            format_message.argtypes = [wintypes.DWORD, wintypes.LPCVOID, wintypes.DWORD, wintypes.DWORD, 
                                      ctypes.POINTER(wintypes.LPWSTR), wintypes.DWORD, wintypes.LPVOID]
            format_message.restype = wintypes.DWORD
            
            # Try different methods
            try:
                # Method 1: CM_Request_Device_Eject
                import win32gui
                win32gui.SendMessageTimeout(
                    win32con.HWND_BROADCAST,
                    win32con.WM_DEVICECHANGE,
                    0x0007,  # DBT_DEVICEREMOVECOMPLETE
                    0,
                    win32con.SMTO_ABORTIFHUNG,
                    2000
                )
            except:
                pass
            
            # Method 2: mountvol /P
            try:
                subprocess.run(f"mountvol {drive_path} /P", shell=True, capture_output=True, timeout=5)
            except:
                pass
            
            self.logger.info(f"[DEVICE] Unmounted {drive_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"[DEVICE] Failed to unmount: {e}")
            return False

class SandboxAnalyzer:
    """Analyze files in sandboxed environment"""
    
    def __init__(self, logger):
        self.logger = logger
        self.sandbox_dir = Path(tempfile.gettempdir()) / "usb_sandbox"
        self.sandbox_dir.mkdir(exist_ok=True)
        
    def analyze_behavior(self, file_path: Path, timeout: int = 30) -> Dict:
        """Analyze file behavior in sandbox"""
        try:
            # Create unique sandbox for this analysis
            sandbox_id = hashlib.md5(str(file_path).encode()).hexdigest()[:8]
            sandbox_path = self.sandbox_dir / sandbox_id
            sandbox_path.mkdir(exist_ok=True)
            
            # Copy file to sandbox
            sandbox_file = sandbox_path / file_path.name
            shutil.copy2(file_path, sandbox_file)
            
            results = {
                'file_size': file_path.stat().st_size,
                'mime_type': mimetypes.guess_type(str(file_path))[0],
                'sandbox_id': sandbox_id,
                'behaviors': []
            }
            
            # Check file type and perform appropriate analysis
            if sandbox_file.suffix.lower() in ['.exe', '.dll', '.scr']:
                results['behaviors'].extend(self._analyze_executable(sandbox_file))
            elif sandbox_file.suffix.lower() in ['.doc', '.docx', '.xls', '.xlsx']:
                results['behaviors'].extend(self._analyze_office_file(sandbox_file))
            elif sandbox_file.suffix.lower() in ['.pdf']:
                results['behaviors'].extend(self._analyze_pdf(sandbox_file))
            elif sandbox_file.suffix.lower() in ['.js', '.vbs', '.ps1']:
                results['behaviors'].extend(self._analyze_script(sandbox_file))
            
            # Cleanup sandbox
            self._cleanup_sandbox(sandbox_path)
            
            return results
            
        except Exception as e:
            self.logger.error(f"[SANDBOX] Analysis failed for {file_path}: {e}")
            return {'error': str(e)}
    
    def _analyze_executable(self, file_path: Path) -> List[str]:
        """Analyze executable files"""
        behaviors = []
        
        try:
            # Check for suspicious PE characteristics
            with open(file_path, 'rb') as f:
                data = f.read(1024)
                
                # Check for MZ header
                if data[:2] == b'MZ':
                    behaviors.append("PE_executable")
                    
                    # Check for suspicious sections
                    suspicious_sections = ['.text', '.data', '.rsrc']
                    for section in suspicious_sections:
                        if section.encode() in data:
                            behaviors.append(f"contains_{section}")
                
                # Check for packed/compressed indicators
                if b'UPX' in data:
                    behaviors.append("UPX_packed")
                if b'ASPack' in data:
                    behaviors.append("ASPack_packed")
                
                # Check for suspicious strings
                suspicious_strings = [
                    b'VirtualAlloc', b'CreateProcess', b'WriteProcessMemory',
                    b'URLDownloadToFile', b'RegSetValue', b'ShellExecute'
                ]
                for s in suspicious_strings:
                    if s in data:
                        behaviors.append(f"api_{s.decode('ascii', errors='ignore')}")
                        
        except Exception as e:
            self.logger.debug(f"[SANDBOX] Executable analysis error: {e}")
            
        return behaviors
    
    def _analyze_office_file(self, file_path: Path) -> List[str]:
        """Analyze Office documents"""
        behaviors = []
        
        try:
            # For Office files, check for macros
            if file_path.suffix.lower() in ['.doc', '.xls']:
                # Old OLE format - check for macros
                with open(file_path, 'rb') as f:
                    data = f.read(4096)
                    if b'Macros' in data or b'VBA' in data:
                        behaviors.append("contains_macros")
            
            elif file_path.suffix.lower() in ['.docx', '.xlsx']:
                # New XML format - check for vbaProject.bin
                try:
                    with zipfile.ZipFile(file_path, 'r') as z:
                        if 'word/vbaProject.bin' in z.namelist() or 'xl/vbaProject.bin' in z.namelist():
                            behaviors.append("contains_macros")
                except:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"[SANDBOX] Office analysis error: {e}")
            
        return behaviors
    
    def _analyze_pdf(self, file_path: Path) -> List[str]:
        """Analyze PDF files"""
        behaviors = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)
                
                # Check PDF header
                if data[:5] == b'%PDF-':
                    behaviors.append("valid_pdf")
                    
                    # Check for JavaScript
                    if b'/JavaScript' in data or b'/JS' in data:
                        behaviors.append("contains_javascript")
                    
                    # Check for embedded files
                    if b'/EmbeddedFile' in data or b'/EmbeddedFiles' in data:
                        behaviors.append("contains_embedded_files")
                        
        except Exception as e:
            self.logger.debug(f"[SANDBOX] PDF analysis error: {e}")
            
        return behaviors
    
    def _analyze_script(self, file_path: Path) -> List[str]:
        """Analyze script files"""
        behaviors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192).lower()
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    'wscript.shell', 'shell.execute', 'adodb.stream',
                    'winhttp.request', 'xmlhttp', 'eval(', 'exec(',
                    'downloadfile', 'invoke-webrequest', 'start-process'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in content:
                        behaviors.append(f"contains_{pattern}")
                        
        except Exception as e:
            self.logger.debug(f"[SANDBOX] Script analysis error: {e}")
            
        return behaviors
    
    def _cleanup_sandbox(self, sandbox_path: Path):
        """Clean up sandbox directory"""
        try:
            if sandbox_path.exists():
                shutil.rmtree(sandbox_path, ignore_errors=True)
        except:
            pass

class PolicyEngine:
    """Make policy-based decisions based on scan results"""
    
    def __init__(self, policy: ScanPolicy, logger):
        self.policy = policy
        self.logger = logger
        
    def evaluate(self, 
                 clamav_result: Dict, 
                 heuristic_result: Dict,
                 sandbox_result: Optional[Dict] = None) -> Tuple[ScanResult, float, str]:
        """
        Evaluate all scan results and return decision
        
        Returns:
            Tuple[ScanResult, confidence_score, recommendation]
        """
        scores = []
        reasons = []
        
        # 1. Evaluate ClamAV results
        clamav_score = 0.0
        clamav_status = clamav_result.get('status', '').lower()
        
        if clamav_status == 'infected':
            clamav_score = 1.0
            reasons.append(f"ClamAV detected {clamav_result.get('infected', 0)} threats")
        elif clamav_status == 'clean':
            clamav_score = 0.1
        elif clamav_status == 'error':
            clamav_score = 0.5
            reasons.append("ClamAV scan failed")
        
        scores.append(clamav_score)
        
        # 2. Evaluate heuristic results
        heuristic_score = 0.0
        heuristic_status = heuristic_result.get('status', '').upper()
        
        if heuristic_status == 'CRITICAL':
            heuristic_score = 0.9
            suspicious = heuristic_result.get('suspicious_files', 0)
            reasons.append(f"Heuristic: {suspicious} critical/suspicious files")
        elif heuristic_status == 'HIGH':
            heuristic_score = 0.7
            suspicious = heuristic_result.get('suspicious_files', 0)
            reasons.append(f"Heuristic: {suspicious} suspicious files")
        elif heuristic_status == 'MEDIUM':
            heuristic_score = 0.4
        elif heuristic_status == 'CLEAN':
            heuristic_score = 0.1
        
        scores.append(heuristic_score)
        
        # 3. Evaluate sandbox results
        sandbox_score = 0.0
        if sandbox_result and self.policy.enable_sandbox:
            behaviors = sandbox_result.get('behaviors', [])
            if behaviors:
                sandbox_score = 0.6
                reasons.append(f"Sandbox: {len(behaviors)} suspicious behaviors")
            else:
                sandbox_score = 0.1
            scores.append(sandbox_score)
        
        # Calculate weighted average
        total_score = sum(scores) / len(scores)
        
        # Make final decision
        if total_score >= self.policy.quarantine_threshold:
            result = ScanResult.MALICIOUS
            recommendation = "QUARANTINE: High threat confidence"
        elif total_score >= 0.4:
            result = ScanResult.SUSPICIOUS
            recommendation = "RESTRICTED: Moderate threat indicators"
        else:
            result = ScanResult.CLEAN
            recommendation = "ALLOW: Low threat indicators"
        
        reasons_str = "; ".join(reasons) if reasons else "No specific threats detected"
        
        return result, total_score, f"{recommendation} ({reasons_str})"

class SecureFileTransfer:
    """Transfer safe files with strict ACLs"""
    
    def __init__(self, logger, quarantine_base: str = "C:\\USB_Quarantine"):
        self.logger = logger
        self.quarantine_base = Path(quarantine_base)
        self.quarantine_base.mkdir(parents=True, exist_ok=True)
        
    def create_secure_container(self, device_meta: DeviceMetadata) -> Path:
        """Create secure container for transferred files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        container_name = f"{device_meta.vid_pid}_{timestamp}"
        container_path = self.quarantine_base / container_name
        
        container_path.mkdir(exist_ok=True)
        
        # Save metadata
        meta_file = container_path / "device_metadata.json"
        with open(meta_file, 'w') as f:
            json.dump({
                'drive_letter': device_meta.drive_letter,
                'vid_pid': device_meta.vid_pid,
                'filesystem': device_meta.filesystem,
                'capacity': device_meta.capacity,
                'mount_time': device_meta.mount_time.isoformat(),
                'transfer_time': datetime.now().isoformat()
            }, f, indent=2)
        
        return container_path
    
    def transfer_safe_files(self, 
                           source_path: Path, 
                           container_path: Path,
                           policy: ScanPolicy,
                           scan_result: ScanResult) -> Dict:
        """
        Transfer files based on policy and scan results
        
        Returns:
            Dict with transfer statistics
        """
        stats = {
            'total_files': 0,
            'transferred': 0,
            'blocked': 0,
            'failed': 0,
            'transferred_files': [],
            'blocked_files': []
        }
        
        # Determine transfer mode based on scan result
        if scan_result == ScanResult.MALICIOUS:
            self.logger.warning("[TRANSFER] MALICIOUS: No files transferred")
            return stats
        
        transfer_mode = policy.transfer_mode
        if scan_result == ScanResult.SUSPICIOUS:
            transfer_mode = "strict"  # Force strict mode for suspicious
        
        try:
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    source_file = Path(root) / file
                    rel_path = source_file.relative_to(source_path)
                    dest_file = container_path / rel_path
                    
                    stats['total_files'] += 1
                    
                    # Check if file should be transferred
                    should_transfer, reason = self._should_transfer_file(
                        source_file, policy, transfer_mode
                    )
                    
                    if should_transfer:
                        try:
                            # Create destination directory
                            dest_file.parent.mkdir(parents=True, exist_ok=True)
                            
                            # Copy file with metadata
                            shutil.copy2(source_file, dest_file)
                            
                            # Apply strict ACLs
                            self._apply_strict_acls(dest_file)
                            
                            stats['transferred'] += 1
                            stats['transferred_files'].append(str(rel_path))
                            
                            self.logger.debug(f"[TRANSFER] ✓ {rel_path}")
                            
                        except Exception as e:
                            stats['failed'] += 1
                            self.logger.error(f"[TRANSFER] Failed to copy {rel_path}: {e}")
                    else:
                        stats['blocked'] += 1
                        stats['blocked_files'].append({
                            'file': str(rel_path),
                            'reason': reason
                        })
                        self.logger.debug(f"[TRANSFER] ✗ {rel_path} ({reason})")
                        
        except Exception as e:
            self.logger.error(f"[TRANSFER] Error during transfer: {e}")
        
        return stats
    
    def _should_transfer_file(self, file_path: Path, policy: ScanPolicy, mode: str) -> Tuple[bool, str]:
        """Determine if a file should be transferred"""
        extension = file_path.suffix.lower()
        
        # Check blocked extensions (always blocked)
        if extension in policy.blocked_extensions:
            return False, f"Blocked extension: {extension}"
        
        # Check allowed extensions
        if extension in policy.allowed_extensions:
            return True, f"Allowed extension: {extension}"
        
        # Mode-specific checks
        if mode == "strict":
            # Strict mode: only allowed extensions
            return False, f"Not in allowed extensions (strict mode)"
        elif mode == "moderate":
            # Moderate mode: check file size and type
            try:
                file_size = file_path.stat().st_size
                if file_size > policy.max_file_size_mb * 1024 * 1024:
                    return False, f"File too large: {file_size//(1024*1024)}MB"
                
                # Check MIME type
                mime_type = mimetypes.guess_type(str(file_path))[0]
                if mime_type and any(x in mime_type for x in ['executable', 'application/x-msdownload']):
                    return False, f"Suspicious MIME type: {mime_type}"
                    
                return True, "Allowed in moderate mode"
                
            except Exception as e:
                return False, f"Error checking file: {e}"
        
        elif mode == "permissive":
            # Permissive mode: allow most files except blocked extensions
            return True, "Allowed in permissive mode"
        
        return False, "Unknown mode"
    
    def _apply_strict_acls(self, file_path: Path):
        """Apply strict ACLs to transferred file"""
        try:
            # Make file read-only
            cmd = f'icacls "{file_path}" /inheritance:r /grant:r *S-1-5-32-544:(R) /grant:r *S-1-1-0:(R)'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            
            # Remove write permissions for everyone
            os.chmod(file_path, 0o444)
            
        except Exception as e:
            self.logger.debug(f"[TRANSFER] Failed to apply ACLs to {file_path}: {e}")

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

        except MemoryError:
            self.logger.error(f"[HEURISTIC] MemoryError scanning {file_path}. Skipped.")
            findings.append({
                'severity': 'ERROR',
                'type': 'MemoryError',
                'detail': 'Skipped due to memory constraints'
            })
        except Exception as e:
            self.logger.debug(f"[HEURISTIC] Failed to scan {file_path}: {e}")

        return findings

    def scan_drive(self, drive_path, collect_findings=True, max_files=None):
        """Scan all files on a drive with better error handling."""
        drive_path = Path(drive_path)
        self.logger.info(f"[HEURISTIC] Starting heuristic analysis of {drive_path}...")
        
        total_files = 0
        suspicious_files = 0
        all_findings = {} if collect_findings else None
        
        try:
            for root, dirs, files in os.walk(str(drive_path)):
                for file in files:
                    file_path = Path(root) / file
                    
                    total_files += 1
                    
                    findings = self.scan_file(file_path)
                    if findings:
                        suspicious_files += 1
                        if collect_findings:
                            all_findings[str(file_path)] = findings
                    
                    if max_files and total_files >= max_files:
                        break
                
                if max_files and total_files >= max_files:
                    break
        
        except Exception as e:
            self.logger.error(f"[HEURISTIC] Scan error: {e}")
            return self._empty_scan_result(str(e))
        
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
        
        return result
    
    def _empty_scan_result(self, error_msg=""):
        """Return empty scan result when scan fails."""
        return {
            'status': 'ERROR',
            'total_files': 0,
            'suspicious_files': 0,
            'findings': {},
            'error': error_msg
        }

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
        
        try:
            # Build command
            cmd = [
                self.clamscan_path,
                "-r",  # Recursive
                "-i",  # Only show infected
                "--bell",
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
                timeout=1800  # 30 minute timeout
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
            elif scanned > 0:
                status = "clean"
            else:
                status = "empty"
            
            self.logger.info(f"[CLAMAV] Scan complete: {status}")
            
            return {
                "status": status,
                "infected_files": infected_files,
                "scanned": scanned,
                "infected": infected,
                "output": result.stdout[:500] if result.stdout else ""
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("[CLAMAV] Scan timeout")
            return {
                "status": "timeout",
                "infected_files": [],
                "scanned": 0,
                "infected": 0,
                "error": "Scan timeout"
            }
        except Exception as e:
            self.logger.error(f"[CLAMAV] Scan failed: {e}")
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
    """Main USB Quarantine System following the workflow diagram"""
    
    def __init__(self, 
                 quarantine_base: str = "C:\\USB_Quarantine",
                 debug: bool = False,
                 policy: ScanPolicy = None):
        
        self.quarantine_base = Path(quarantine_base)
        self.debug = debug
        self.quarantine_base.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Initialize components
        self.device_controller = DeviceController(self.logger)
        self.clamav_scanner = ClamAVScanner(self.logger)
        self.heuristic_scanner = HeuristicScanner(self.logger)
        self.sandbox_analyzer = SandboxAnalyzer(self.logger)
        self.policy = policy or ScanPolicy()
        self.policy_engine = PolicyEngine(self.policy, self.logger)
        self.file_transfer = SecureFileTransfer(self.logger, quarantine_base)
        
        # State tracking
        self.active_devices: Dict[str, DeviceMetadata] = {}
        self.quarantine_records: Dict[str, Dict] = {}
        self.state_file = self.quarantine_base / "quarantine_state.json"
        self.running = False
        
        self.load_state()
        
        self.logger.info("=" * 60)
        self.logger.info("USB QUARANTINE SYSTEM INITIALIZED")
        self.logger.info(f"Policy: {self.policy.transfer_mode} mode")
        self.logger.info(f"Quarantine base: {self.quarantine_base}")
        self.logger.info("=" * 60)
    
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
    
    def load_state(self):
        """Load quarantine state from file"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    self.quarantine_records = json.load(f)
                self.logger.info(f"Loaded {len(self.quarantine_records)} quarantine records")
            except Exception as e:
                self.logger.error(f"Failed to load state: {e}")
                self.quarantine_records = {}
    
    def save_state(self):
        """Save quarantine state to file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.quarantine_records, f, indent=2)
            self.logger.debug(f"State saved: {len(self.quarantine_records)} records")
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
    
    def get_removable_drives(self) -> List[str]:
        """Get list of removable drives"""
        drives = []
        for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                    if drive_type == 2:  # DRIVE_REMOVABLE
                        drives.append(drive)
                except:
                    pass
        return drives
    
    def process_device_insertion(self, drive_path: str) -> bool:
        """
        Main workflow for processing a new USB device
        
        Returns:
            bool: True if processing successful, False otherwise
        """
        self.logger.info("=" * 60)
        self.logger.info(f"[WORKFLOW] Processing device: {drive_path}")
        self.logger.info("=" * 60)
        
        # Track resources for cleanup
        device_mounted = False
        cleanup_required = False
        
        try:
            # STEP 1: Capture device metadata & disable auto-mount
            self.logger.info("[1/7] Capturing device metadata...")
            
            # Add initial delay to ensure drive is ready
            time.sleep(2)
            
            device_meta = self.device_controller.get_device_metadata(drive_path)
            if not device_meta:
                self.logger.error("Failed to get device metadata")
                return False
            
            # Disable automount
            self.device_controller.disable_automount(drive_path)
            
            # Add another small delay
            time.sleep(1)
            
            # STEP 2: Take control of device (mount as read-only)
            self.logger.info("[2/7] Taking control of device...")
            if not self.device_controller.mount_readonly(drive_path):
                self.logger.error("Failed to mount device as read-only")
                self.logger.warning("Continuing with reduced security (device not read-only)")
                # Continue anyway, but mark for monitoring
                device_mounted = False
            else:
                device_mounted = True
                cleanup_required = True
            
            # STEP 3: Present device as read-only to scanners
            self.logger.info("[3/7] Device prepared for scanning")
            
            # STEP 4: Start scanning
            self.logger.info("[4/7] Starting security scans...")
            
            # Parallel scanning with proper thread safety
            import queue
            result_queue = queue.Queue()
            scan_threads = []
            
            def run_clamav_scan():
                try:
                    result = self.clamav_scanner.scan_drive(drive_path)
                    result_queue.put(('clamav', result))
                except Exception as e:
                    result_queue.put(('clamav', {'status': 'error', 'error': str(e)}))
            
            def run_heuristic_scan():
                try:
                    result = self.heuristic_scanner.scan_drive(drive_path)
                    result_queue.put(('heuristic', result))
                except Exception as e:
                    result_queue.put(('heuristic', {'status': 'error', 'error': str(e)}))
            
            # Start scans
            scan_results = {}
            
            if self.policy.enable_clamav:
                clamav_thread = threading.Thread(target=run_clamav_scan, name="ClamAV-Scan")
                clamav_thread.start()
                scan_threads.append(clamav_thread)
            
            if self.policy.enable_heuristic:
                heuristic_thread = threading.Thread(target=run_heuristic_scan, name="Heuristic-Scan")
                heuristic_thread.start()
                scan_threads.append(heuristic_thread)
            
            # Wait for completion with timeout
            scan_timeout = 600  # 10 minutes max
            start_time = time.time()
            
            for thread in scan_threads:
                # Calculate remaining timeout
                elapsed = time.time() - start_time
                remaining = max(1, scan_timeout - elapsed)
                thread.join(timeout=remaining)
                
                if thread.is_alive():
                    self.logger.warning(f"Scan thread {thread.name} timed out")
                    # Mark as timeout
                    result_queue.put((thread.name, {'status': 'timeout', 'error': 'Scan timed out'}))
            
            # Collect results
            while not result_queue.empty():
                try:
                    scanner_name, result = result_queue.get_nowait()
                    scan_results[scanner_name] = result
                except queue.Empty:
                    break
            
            # If no results were collected, create empty ones
            if self.policy.enable_clamav and 'clamav' not in scan_results:
                scan_results['clamav'] = {'status': 'error', 'error': 'No result collected'}
            if self.policy.enable_heuristic and 'heuristic' not in scan_results:
                scan_results['heuristic'] = {'status': 'error', 'error': 'No result collected'}
            
            # Log scan completion
            for scanner, result in scan_results.items():
                status = result.get('status', 'unknown')
                self.logger.info(f"[SCAN] {scanner}: {status}")
            
            # STEP 5: Optional sandbox analysis for suspicious files
            sandbox_result = None
            if (self.policy.enable_sandbox and 
                'heuristic' in scan_results and 
                scan_results['heuristic'].get('suspicious_files', 0) > 0):
                
                self.logger.info("[5/7] Running sandbox analysis...")
                # Sample suspicious files for sandbox analysis
                sandbox_result = self._sample_sandbox_analysis(drive_path, scan_results['heuristic'])
            
            # STEP 6: Policy evaluation
            self.logger.info("[6/7] Evaluating scan results with policy engine...")
            
            # Get results with defaults
            clamav_result = scan_results.get('clamav', {'status': 'skipped'})
            heuristic_result = scan_results.get('heuristic', {'status': 'skipped'})
            
            scan_result, confidence, recommendation = self.policy_engine.evaluate(
                clamav_result,
                heuristic_result,
                sandbox_result
            )
            
            self.logger.info(f"Scan result: {scan_result.value.upper()} (confidence: {confidence:.2f})")
            self.logger.info(f"Recommendation: {recommendation}")
            
            # STEP 7: Execute policy decision
            self.logger.info("[7/7] Executing policy decision...")
            
            if scan_result == ScanResult.MALICIOUS:
                # Quarantine and alert admin
                return self._handle_malicious_device(drive_path, device_meta, scan_results, confidence, recommendation)
            elif scan_result == ScanResult.SUSPICIOUS:
                # Transfer with restrictions
                return self._handle_suspicious_device(drive_path, device_meta, scan_results, confidence, recommendation)
            else:  # CLEAN or UNKNOWN
                # Transfer allowed files
                return self._handle_clean_device(drive_path, device_meta, scan_results, confidence, recommendation)
        
        except Exception as e:
            self.logger.error(f"[WORKFLOW] Processing failed: {e}", exc_info=True)
            
            # Cleanup on failure
            if cleanup_required and device_mounted:
                try:
                    self.device_controller.unmount_device(drive_path)
                except:
                    pass
            
            return False
    
    def _sample_sandbox_analysis(self, drive_path: str, heuristic_result: Dict) -> Optional[Dict]:
        """Perform sandbox analysis on suspicious files"""
        try:
            findings = heuristic_result.get('findings', {})
            if not findings:
                return None
            
            # Get top 3 suspicious files for sandbox analysis
            suspicious_files = list(findings.keys())[:3]
            sandbox_results = []
            
            for file_path in suspicious_files:
                result = self.sandbox_analyzer.analyze_behavior(Path(file_path))
                sandbox_results.append(result)
            
            return {'analyzed_files': len(sandbox_results), 'results': sandbox_results}
        except Exception as e:
            self.logger.error(f"[SANDBOX] Failed to analyze: {e}")
            return None
    
    def _handle_malicious_device(self, 
                                 drive_path: str, 
                                 device_meta: DeviceMetadata,
                                 scan_results: Dict,
                                 confidence: float,
                                 recommendation: str) -> bool:
        """Handle malicious device - quarantine and alert"""
        self.logger.error("=" * 60)
        self.logger.error("⚠️  MALICIOUS DEVICE DETECTED ⚠️")
        self.logger.error("=" * 60)
        
        # Create quarantine record
        quarantine_id = f"{device_meta.vid_pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        quarantine_path = self.quarantine_base / quarantine_id
        quarantine_path.mkdir(exist_ok=True)
        
        # Save evidence
        evidence_file = quarantine_path / "scan_evidence.json"
        with open(evidence_file, 'w') as f:
            json.dump({
                'device_metadata': device_meta.__dict__,
                'scan_results': scan_results,
                'confidence': confidence,
                'recommendation': recommendation,
                'quarantine_time': datetime.now().isoformat()
            }, f, indent=2)
        
        # Keep device locked (already read-only mounted)
        self.quarantine_records[drive_path] = {
            'quarantine_id': quarantine_id,
            'device_meta': device_meta.__dict__,
            'scan_result': 'MALICIOUS',
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'action': 'QUARANTINED',
            'admin_notified': False
        }
        
        self.save_state()
        
        # Alert admin (placeholder - integrate with your alerting system)
        self._alert_admin(
            f"MALICIOUS USB DEVICE DETECTED",
            f"Device: {drive_path}\n"
            f"VID/PID: {device_meta.vid_pid}\n"
            f"Confidence: {confidence:.2f}\n"
            f"Action: Device quarantined at {quarantine_path}"
        )
        
        self.logger.error(f"[ACTION] Device quarantined. Evidence saved to {quarantine_path}")
        self.logger.error(f"[ACTION] Admin notified. Device remains locked.")
        
        return False
    
    def _handle_suspicious_device(self,
                                  drive_path: str,
                                  device_meta: DeviceMetadata,
                                  scan_results: Dict,
                                  confidence: float,
                                  recommendation: str) -> bool:
        """Handle suspicious device - transfer with restrictions"""
        self.logger.warning("=" * 60)
        self.logger.warning("⚠️  SUSPICIOUS DEVICE DETECTED ⚠️")
        self.logger.warning("=" * 60)
        
        # Create secure container
        container_path = self.file_transfer.create_secure_container(device_meta)
        
        # Transfer files with strict mode
        transfer_stats = self.file_transfer.transfer_safe_files(
            Path(drive_path),
            container_path,
            self.policy,
            ScanResult.SUSPICIOUS
        )
        
        # Save quarantine record
        self.quarantine_records[drive_path] = {
            'quarantine_id': container_path.name,
            'device_meta': device_meta.__dict__,
            'scan_result': 'SUSPICIOUS',
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'action': 'RESTRICTED_TRANSFER',
            'transfer_stats': transfer_stats,
            'container_path': str(container_path)
        }
        
        self.save_state()
        
        # Alert admin about suspicious device
        self._alert_admin(
            f"SUSPICIOUS USB DEVICE PROCESSED",
            f"Device: {drive_path}\n"
            f"VID/PID: {device_meta.vid_pid}\n"
            f"Confidence: {confidence:.2f}\n"
            f"Files transferred: {transfer_stats['transferred']}/{transfer_stats['total_files']}\n"
            f"Container: {container_path}"
        )
        
        self.logger.warning(f"[ACTION] Restricted transfer complete: {transfer_stats['transferred']} files transferred")
        self.logger.warning(f"[ACTION] Container: {container_path}")
        
        # Keep device locked
        return True
    
    def _handle_clean_device(self,
                             drive_path: str,
                             device_meta: DeviceMetadata,
                             scan_results: Dict,
                             confidence: float,
                             recommendation: str) -> bool:
        """Handle clean device - transfer allowed files"""
        self.logger.info("=" * 60)
        self.logger.info("✓ CLEAN DEVICE DETECTED")
        self.logger.info("=" * 60)
        
        # Create secure container
        container_path = self.file_transfer.create_secure_container(device_meta)
        
        # Transfer files according to policy mode
        transfer_stats = self.file_transfer.transfer_safe_files(
            Path(drive_path),
            container_path,
            self.policy,
            ScanResult.CLEAN
        )
        
        # Save quarantine record
        self.quarantine_records[drive_path] = {
            'quarantine_id': container_path.name,
            'device_meta': device_meta.__dict__,
            'scan_result': 'CLEAN',
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'action': 'NORMAL_TRANSFER',
            'transfer_stats': transfer_stats,
            'container_path': str(container_path)
        }
        
        self.save_state()
        
        self.logger.info(f"[ACTION] Transfer complete: {transfer_stats['transferred']} files transferred")
        self.logger.info(f"[ACTION] Container: {container_path}")
        
        # Unlock device (optional - depends on policy)
        # self.device_controller.unmount_device(drive_path)
        
        return True
    
    def _alert_admin(self, subject: str, message: str):
        """Alert administrator (placeholder - implement your alerting system)"""
        # This could be email, Slack, syslog, Windows Event Log, etc.
        self.logger.warning(f"[ALERT] {subject}")
        self.logger.warning(f"[ALERT DETAILS] {message}")
        
        # Example: Write to Windows Event Log
        try:
            import win32evtlog
            import win32evtlogutil
            
            ph = win32evtlog.OpenEventLog(None, "Application")
            win32evtlog.ReportEvent(
                ph,
                win32evtlog.EVENTLOG_WARNING_TYPE,
                0,  # Category
                1000,  # Event ID
                None,
                ["USB Quarantine System", subject, message]
            )
            win32evtlog.CloseEventLog(ph)
        except:
            pass
    
    def monitor_loop(self):
        """Main monitoring loop"""
        self.logger.info("=" * 60)
        self.logger.info("USB QUARANTINE MONITOR STARTED")
        self.logger.info("=" * 60)
        
        known_drives = set(self.get_removable_drives())
        if known_drives:
            self.logger.info(f"Initial drives: {', '.join(known_drives)}")
        
        self.running = True
        
        try:
            while self.running:
                current_drives = set(self.get_removable_drives())
                new_drives = current_drives - known_drives
                
                for drive in new_drives:
                    self.logger.info(f"\n[+] New device detected: {drive}")
                    
                    # Process in separate thread to not block monitoring
                    process_thread = threading.Thread(
                        target=self.process_device_insertion,
                        args=(drive,),
                        name=f"Process-{drive}"
                    )
                    process_thread.start()
                
                removed_drives = known_drives - current_drives
                for drive in removed_drives:
                    self.logger.info(f"[-] Device removed: {drive}")
                    if drive in self.active_devices:
                        del self.active_devices[drive]
                
                known_drives = current_drives
                time.sleep(2)
                
        except KeyboardInterrupt:
            self.logger.info("\n[INFO] Monitor stopped by user")
        except Exception as e:
            self.logger.error(f"[ERROR] Monitor error: {e}", exc_info=True)
        finally:
            self.running = False
    
    def start(self):
        """Start the monitoring service"""
        if not self.is_admin():
            self.logger.error("ERROR: Administrative privileges required")
            self.logger.error("Please run as Administrator")
            return
        
        self.monitor_loop()
    
    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def list_quarantined(self):
        """List all quarantined devices"""
        if not self.quarantine_records:
            self.logger.info("No quarantined devices")
            return
        
        self.logger.info("=" * 60)
        self.logger.info(f"QUARANTINED DEVICES ({len(self.quarantine_records)})")
        self.logger.info("=" * 60)
        
        for drive, record in self.quarantine_records.items():
            status_icon = "⚠️" if record.get('scan_result') in ['MALICIOUS', 'SUSPICIOUS'] else "✓"
            self.logger.info(f"\n{status_icon} {drive}")
            self.logger.info(f"  Status: {record.get('scan_result', 'UNKNOWN')}")
            self.logger.info(f"  Confidence: {record.get('confidence', 0):.2f}")
            self.logger.info(f"  Time: {record.get('timestamp', 'UNKNOWN')}")
            self.logger.info(f"  Action: {record.get('action', 'UNKNOWN')}")
            
            if 'container_path' in record:
                self.logger.info(f"  Container: {record['container_path']}")
            
            if 'transfer_stats' in record:
                stats = record['transfer_stats']
                self.logger.info(f"  Files: {stats.get('transferred', 0)}/{stats.get('total_files', 0)} transferred")
    
    def revert_drive(self, drive_path: str):
        """Revert a quarantined drive"""
        if drive_path not in self.quarantine_records:
            self.logger.warning(f"Drive {drive_path} not in quarantine records")
            return False
        
        record = self.quarantine_records[drive_path]
        
        if record.get('scan_result') == 'MALICIOUS':
            self.logger.error("⚠️  WARNING: This device was marked MALICIOUS")
            response = input("Are you SURE you want to unlock this device? (type 'YES'): ")
            if response != 'YES':
                self.logger.info("Revert cancelled")
                return False
        
        self.logger.info(f"Reverting {drive_path}...")
        
        if self.device_controller.unmount_device(drive_path):
            del self.quarantine_records[drive_path]
            self.save_state()
            self.logger.info(f"✓ Drive {drive_path} reverted")
            return True
        else:
            self.logger.error(f"Failed to revert {drive_path}")
            return False

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="USB Quarantine System")
    parser.add_argument("command", nargs="?", help="Command to execute")
    parser.add_argument("target", nargs="?", help="Target drive or path")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--policy", choices=["strict", "moderate", "permissive"], 
                       default="moderate", help="Security policy mode")
    
    args = parser.parse_args()
    
    # Create policy based on argument
    policy = ScanPolicy(transfer_mode=args.policy)
    
    quarantine = USBQuarantine(debug=args.debug, policy=policy)
    
    if not quarantine.is_admin():
        print("ERROR: This program requires administrative privileges")
        print("Please run as Administrator")
        return
    
    if args.command:
        if args.command == "list":
            quarantine.list_quarantined()
        elif args.command == "revert":
            if args.target:
                quarantine.revert_drive(args.target.upper() + ":\\" if not args.target.endswith(":\\") else args.target)
            else:
                print("Usage: python usb_quarantine.py revert <drive>")
        elif args.command == "scan":
            if args.target:
                # Manual scan mode
                print(f"Manual scan of {args.target}")
                heuristic_result = quarantine.heuristic_scanner.scan_drive(args.target)
                print(f"Heuristic: {heuristic_result.get('status')}")
                
                if quarantine.clamav_scanner.is_available():
                    clamav_result = quarantine.clamav_scanner.scan_drive(args.target)
                    print(f"ClamAV: {clamav_result.get('status')}")
            else:
                print("Usage: python usb_quarantine.py scan <path>")
        elif args.command == "monitor":
            quarantine.start()
        elif args.command == "update":
            if quarantine.clamav_scanner.update_definitions():
                print("Virus definitions updated")
            else:
                print("Update failed")
        else:
            print(f"Unknown command: {args.command}")
            print("Available commands: list, revert <drive>, scan <path>, monitor, update")
    else:
        # Default: start monitoring
        quarantine.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        if '--debug' in sys.argv:
            traceback.print_exc()