# USB-Seecurity-

Overview 
The USB Quarantine System is a comprehensive security solution designed to intercept, analyzez and control USB storage devices on Windows systems. It follows. Zero-trust approach to USB devices by implementing mandatory scanning and policy-based file transfer before allowing any data access. 

Key Features 
Core Security Controls 
	Automatic USB Device erection - Real-time monitoring of USB device insertion 
	Read-only Mounting - Prevent write operations during scanning 
	Multi-Layer Scanning: 
		ClamAV signature-based detection
		Heuristic behavioral analysis 
		Optional sandbox execution analysis 
	Policy-Based Decision Engine - Configurable security policies 
	Secure File Transfer - Controlled file extraction with strict ACLs 
	Quarantine Management - Isolate and analyze suspicious devices 

Scanning Capabilities 
	ClamAV Integration - Open source antivirus scanning 
	Heuristic Analysis - File entropy, embedded executables, suspicious APIs 
	File Type Detection - Executable, Office,PDF and script analysis 
	Memory-safe Scanning - Chunk-based processing for large files 

Policy Management 
	Three security modes : strict,moderate, permissive 
	Configurable file extensions 
	Adjustable quarantine threshold 
	Extension and MIME type filtering 
Required Python Package 
pywin32
psutil
pywintypes
pythoncom

Workflow  
1.Detection
2. Metadata Capture 
3. Control 
4.Scanning
5. Analysis
6.Evaluation 

Decision Matrix 

Scan Result
Confidence
Action
MALICIOUS
≥ 70%
Full quarantine, admin alert
SUSPICIOUS
40-70%
Restricted transfer, admin notification
CLEAN
< 40%
Normal transfer according to policy



File Structure 
C:\USB_Quarantine\                    # Default quarantine directory
├── quarantine_state.json             # System state and records
├── quarantine.log                    # Log file
├── 20240115_143200_Vendor_Model\     # Quarantine container
│   ├── device_metadata.json          # Device information
│   ├── scan_evidence.json            # Scan results
│   └── transferred_files\            # Extracted safe files
│       ├── document1.pdf
│       └── image1.jpg
└── usb_sandbox\                      # Sandbox analysis directory

Scanning Details 
Heuristic Detection Rules 


Detection Table
Severity
Indicators
High Entropy
HIGH
Shannon entropy > 7.⅜.0
Embedded EXECUTABLE
CRITICAL
Non eecutable file
Suspicios APIS
CRITICAL
3+
File Type Mismatch
CRITICAL
Executable header with non-executable extension
Office Macros
Medium
VBA/macro content in Office document



Technical Limitations
Windows-Only - Specifically designed for Windows APIs and registry

Administrative Privileges Required - Full functionality requires Admin rights

ClamAV Dependency - Signature scanning requires separate ClamAV installation

USB Device Correlation - Limited ability to perfectly correlate drive letters with specific USB devices

File Size Limits - Large files (>50MB by default) may have reduced scanning depth

Encrypted Files - Cannot scan encrypted or password-protected content

Security Limitations
Kernel-Level Bypasses - Could be bypassed by kernel-mode malware

Firmware Attacks - Does not protect against USB device firmware exploits

Real-time Evasion - Sophisticated malware could detect and evade the sandbox

Zero-Day Threats - Heuristic scanning may miss novel attack techniques

Social Engineering - Cannot prevent users from manually bypassing controls

Performance Considerations
Scanning Time - Large drives (>64GB) may take significant time to scan

System Resources - Scanning consumes CPU and memory resources

User Experience - Read-only mounting may confuse some applications

Concurrent Devices - Multiple simultaneous USB insertions may queue

Operational Limitations
False Positives - Heuristic scanning may flag legitimate files as suspicious

Policy Management - Requires manual configuration for specialized use cases

Log Management - Log files can grow large over time

Recovery Complexity - Reverting quarantined devices requires manual intervention

Network Dependence - ClamAV updates require internet connectivity

 Security Best Practices
For Deployment
Test in Staging - Deploy in testing environment first

Customize Policies - Adjust allowed/blocked extensions for your organization

Regular Updates - Keep ClamAV definitions updated

Monitor Logs - Regularly review quarantine.log for anomalies

User Training - Educate users about the system's purpose and limitations

For Integration
Alert Integration - Connect admin alerts to existing monitoring systems

Centralized Logging - Forward logs to SIEM/Syslog server

Backup Policies - Regularly backup quarantine_state.json

Performance Monitoring - Monitor system resources during scanning



Planned Features
Network Scanning - Submit suspicious files to cloud sandboxes

Central Management - Multi-endpoint policy management

Enhanced Device Identification - Better USB device fingerprinting

Behavioral Analysis - Runtime behavior monitoring of transferred files

Reporting Dashboard - Web-based management interface

Integration Points
SIEM Integration - Splunk, ELK, Azure Sentinel

EDR Integration - CrowdStrike, SentinelOne, Microsoft Defender

Ticketing Systems - ServiceNow, Jira for alert automation

Email/SMS Alerts - Direct notification channels




