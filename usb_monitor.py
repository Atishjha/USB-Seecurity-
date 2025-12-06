""" USB Mount Detector Module Monitors and detects USB device mount//unmount event """
import os 
import sys 
import time 
import platform 
import logging 
from datetime import datetime 
from ctypes import windll, wintypes 
import win32api 
import win32file 
import win32con
import string 
def setup_logging():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    log_dir = "usb_logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create log filename with current date
    log_filename = os.path.join(log_dir, f"usb_events_{datetime.now().strftime('%Y%m%d')}.log")
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return log_filename


def get_drive_info(drive_letter):
    """Get detailed information about a drive"""
    try:
        drive = f"{drive_letter}:\\"
        volume_info = win32api.GetVolumeInformation(drive)
        
        # Get drive size information
        try:
            free_bytes, total_bytes, total_free = win32api.GetDiskFreeSpaceEx(drive)
            used_bytes = total_bytes - total_free
            total_gb = total_bytes / (1024**3)
            used_gb = used_bytes / (1024**3)
            free_gb = free_bytes / (1024**3)
        except:
            total_gb = used_gb = free_gb = 0
        
        return {
            'drive': drive,
            'label': volume_info[0] if volume_info[0] else "No Label",
            'filesystem': volume_info[4],
            'serial': volume_info[1],
            'total_gb': round(total_gb, 2),
            'used_gb': round(used_gb, 2),
            'free_gb': round(free_gb, 2)
        }
    except Exception as e:
        return None
    

def get_mounted_device_linux():
    """Get currently mounted devices on Linux System """
    devices = []
    try:
        with open('/proc/mount','r') as f: 
            for line in f:
                parts = line.split() 
                if len(parts) >= 2:
                    device,mount_point = parts[0], parts[1]
                    if '/media/' in mount_point or '/mnt' in mount_point:
                        devices.append({'device':devices, 'mount_point': mount_point})
                        
    except Exception as e:
        print(f"Error reading /proc/mount: {e}")
    return devices



def get_mounted_device_windows():
    """Get currently mounted devices on Windows System """
    import string 
    from ctypes import windll 
    devices = [] 
    bitmask = windll.kernel32.GetLogicalDrives() 
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drive = f"{letter}:\\"
            drive_type = windll.kernel32.GetDriveTypeW(drive)
            #Drive type 2 indicates removable drive 
            if drive_type == 2 : 
                devices.append({'device': drive, 'mount_point': drive})
        bitmask >>= 1 
        
    return devices 

def get_mounted_devices_mac():
    """Get currently mounted devices on MacOS System """
    devices = []
    volumes_path = '/Volumes'
    try:
        if os.path.exists(volumes_path):
            for volume in os.listdir(volumes_path):
                full_path = os.path.join(volumes_path, volume)
                if os.path.ismount(full_path) and volume != 'Macintosh HD':
                    devices.append({'device': volume, 'mount_point': full_path})
    except Exception as e:
        print(f"Error reading volumes: {e}")
    return devices 
def get_usb_drives():
    """Get all currently mounted USB drives"""
    usb_drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drive = f"{letter}:\\"
            try:
                drive_type = win32file.GetDriveType(drive)
                # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3
                # Check if it's removable
                if drive_type == win32con.DRIVE_REMOVABLE:
                    info = get_drive_info(letter)
                    if info:
                        usb_drives.append(info)
            except Exception as e:
                pass
        bitmask >>= 1
    
    return usb_drives

def print_drive_info(drive_info, event_type="MOUNTED"):
    """Print formatted drive information"""
    print(f"{'='*60}")
    print(f"[{event_type}] USB Device Detected!")
    print(f"{'='*60}")
    print(f"Drive Letter:    {drive_info['drive']}")
    print(f"Volume Label:    {drive_info['label']}")
    print(f"File System:     {drive_info['filesystem']}")
    print(f"Serial Number:   {drive_info['serial']}")
    print(f"Total Space:     {drive_info['total_gb']} GB")
    print(f"Used Space:      {drive_info['used_gb']} GB")
    print(f"Free Space:      {drive_info['free_gb']} GB")
    print(f"Time:            {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")


def get_mounted_devices():
    """Get mounted devices based on platform"""
    system = platform.system()
    if system == 'Linux':
        return get_mounted_device_linux()
    elif system == 'Windows':
        return get_mounted_device_windows()
    elif system == 'Darwin':
        return get_mounted_devices_mac()
    else:
        print(f"Unsupported platform: {system}")
        return []
    
def monitor_usb_mounts(interval=2):
    """Monitor USB mount/unmount events"""
    print("USB Mount Detector Started")
    print(f"PLatform: {platform.system()}")
    print("Monitoring for USB dvices..\n")
    
    previous_devices =set() 
    try:
        while True:
            current_devices_list = get_mounted_devices() 
            current_devices = {d['mount_point'] for d in current_devices_list}
            newly_mounted = current_devices - previous_devices
            for mount_point in newly_mounted:
                device_info = next((d for d in current_devices_list if d['mount_point'] == mount_point), None)
                if device_info:
                    print(f"[Mounted] USB device detected")
                    print(f" Device: {device_info['device']}")
                    print(f" Mount Point: {device_info['mount_point']}\n")
                    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    
                    
            unmounted = previous_devices - current_devices
            for mount_point in unmounted:
                print(f"[UNMOUNTED] USB device removed!")
                print(f"  Mount Point: {mount_point}")
                print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                
            previous_devices = current_devices 
            time.sleep(interval)
    except KeyboardInterrupt:
        print("/nMonitoring stopped by user. Exiting...")
        sys.exit(0) 
def list_current_usb_drives():
    """List all currently connected USB drives"""
    print("=" * 60)
    print("Currently Connected USB Drives")
    print("=" * 60 + "\n")
    
    drives = get_usb_drives()
    if drives:
        for drive in drives:
            print_drive_info(drive, "CONNECTED")
    else:
        print("No USB drives currently connected.\n")
        
if __name__ == "__main__": 
    if platform.system() == 'Linux' and os.getevid() != 0: 
        print("Note: Running without root privileges may limit device detection capabilities.")
        print("Consider running the script with 'sudo' for better results.\n")
    log_file = setup_logging()
    logging.info("="*60)
    logging.info("USB Mount Detector Started")
    logging.info("="*60)
    print(f"Logging to: {log_file}\n")
    list_current_usb_drives()
    input("Press Enter to start monitoring for USB mount/unmount events...")
    print() 
    monitor_usb_mounts()
    
    