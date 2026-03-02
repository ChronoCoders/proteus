rule Suspicious_Code_Injection
{
    meta:
        description = "Detects code injection behavior"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "suspicious"
        
    strings:
        $api1 = "VirtualAllocEx" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "NtCreateThreadEx" nocase
        $api5 = "RtlCreateUserThread" nocase
        $api6 = "QueueUserAPC" nocase
        
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Suspicious_Process_Hollowing
{
    meta:
        description = "Detects process hollowing technique"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "suspicious"
        
    strings:
        $api1 = "CreateProcess" nocase
        $api2 = "ZwUnmapViewOfSection" nocase
        $api3 = "NtUnmapViewOfSection" nocase
        $api4 = "VirtualAllocEx" nocase
        $api5 = "WriteProcessMemory" nocase
        $api6 = "SetThreadContext" nocase
        $api7 = "ResumeThread" nocase
        
    condition:
        uint16(0) == 0x5A4D and 4 of them
}

rule Suspicious_AntiVM_AntiDebug
{
    meta:
        description = "Detects anti-VM and anti-debug techniques"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "suspicious"
        
    strings:
        // Anti-debug APIs
        $api1 = "IsDebuggerPresent" nocase
        $api2 = "CheckRemoteDebuggerPresent" nocase
        $api3 = "NtQueryInformationProcess" nocase
        $api4 = "OutputDebugString" nocase
        
        // VM detection strings
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "VBOX" nocase
        $vm4 = "QEMU" nocase
        $vm5 = "Xen" nocase
        
        // Registry keys for VM detection
        $reg1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port" nocase
        $reg2 = "SOFTWARE\\VMware" nocase
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($api*) or 2 of ($vm*) or 1 of ($reg*))
}

rule Suspicious_Credential_Dumping
{
    meta:
        description = "Detects credential dumping behavior"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "suspicious"
        
    strings:
        $s1 = "lsass.exe" nocase
        $s2 = "SAM" nocase
        $s3 = "SECURITY" nocase
        $s4 = "SYSTEM" nocase
        $api1 = "MiniDumpWriteDump" nocase
        $api2 = "OpenProcess" nocase
        $api3 = "SeDebugPrivilege" nocase
        $tool1 = "mimikatz" nocase
        $tool2 = "procdump" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (($s1 and 2 of ($api*)) or 1 of ($tool*) or 2 of ($s*))
}

rule Suspicious_Persistence_Mechanism
{
    meta:
        description = "Detects persistence mechanisms"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "suspicious"
        
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $schtask1 = "schtasks" nocase
        $schtask2 = "/create" nocase
        $startup = "\\Start Menu\\Programs\\Startup" nocase
        $service1 = "CreateService" nocase
        $service2 = "OpenSCManager" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($reg*) or ($schtask1 and $schtask2) or $startup or 2 of ($service*))
}

rule Suspicious_Screenshot_Capture
{
    meta:
        description = "Detects screenshot capture capability"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "suspicious"
        
    strings:
        $api1 = "BitBlt" nocase
        $api2 = "GetDC" nocase
        $api3 = "GetDesktopWindow" nocase
        $api4 = "CreateCompatibleDC" nocase
        $api5 = "CreateCompatibleBitmap" nocase
        
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Suspicious_Keylogger
{
    meta:
        description = "Detects keylogger behavior"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "suspicious"
        
    strings:
        $api1 = "GetAsyncKeyState" nocase
        $api2 = "GetKeyState" nocase
        $api3 = "SetWindowsHookEx" nocase
        $api4 = "GetForegroundWindow" nocase
        $api5 = "AttachThreadInput" nocase
        $log1 = "keylog" nocase
        $log2 = "keys.txt" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($api*) or (2 of ($api*) and 1 of ($log*)))
}

rule Suspicious_Browser_Data_Theft
{
    meta:
        description = "Detects browser data theft"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "suspicious"
        
    strings:
        $chrome = "\\Google\\Chrome\\User Data" nocase
        $firefox = "\\Mozilla\\Firefox\\Profiles" nocase
        $edge = "\\Microsoft\\Edge\\User Data" nocase
        $sqlite = "sqlite3" nocase
        $file1 = "Login Data" nocase
        $file2 = "Cookies" nocase
        $file3 = "Web Data" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        ((1 of ($chrome, $firefox, $edge) and $sqlite) or 2 of ($file*))
}

rule Suspicious_Network_Discovery
{
    meta:
        description = "Detects network discovery and scanning"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "suspicious"
        
    strings:
        $cmd1 = "ipconfig" nocase
        $cmd2 = "net view" nocase
        $cmd3 = "net group" nocase
        $cmd4 = "net user" nocase
        $cmd5 = "nltest" nocase
        $cmd6 = "ping" nocase
        $api1 = "gethostbyname" nocase
        $api2 = "GetAdaptersInfo" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($cmd*) or (2 of ($cmd*) and 1 of ($api*)))
}

rule Suspicious_File_Encryption
{
    meta:
        description = "Detects file encryption behavior"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "suspicious"
        
    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "CryptAcquireContext" nocase
        $crypto3 = "CryptGenKey" nocase
        $crypto4 = "AES" nocase
        $crypto5 = "RSA" nocase
        $search1 = "FindFirstFile" nocase
        $search2 = "FindNextFile" nocase
        $ext1 = ".doc" nocase
        $ext2 = ".pdf" nocase
        $ext3 = ".jpg" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($crypto*) and 1 of ($search*) and 1 of ($ext*))
}
