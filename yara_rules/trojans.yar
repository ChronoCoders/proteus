rule Emotet_Trojan
{
    meta:
        description = "Detects Emotet trojan"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "trojan"
        
    strings:
        $s1 = "RegSvr32.exe" nocase
        $s2 = "WScript.Shell" nocase
        $s3 = "powershell.exe" nocase
        $api1 = "URLDownloadToFileW" nocase
        $api2 = "CreateProcessW" nocase
        $api3 = "WriteProcessMemory" nocase
        $pattern = { 64 A1 30 00 00 00 }  // PEB access
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) and 2 of ($api*)) or $pattern
}

rule TrickBot_Trojan
{
    meta:
        description = "Detects TrickBot trojan"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "trojan"
        
    strings:
        $s1 = "TrickBot" nocase
        $s2 = "pwgrab" nocase
        $s3 = "mailsearcher" nocase
        $s4 = "systeminfo" nocase
        $s5 = "injectDll" nocase
        $config = "<moduleconfig>"
        $srv = "<srv>" 
        
    condition:
        uint16(0) == 0x5A4D and (3 of ($s*) or ($config and $srv))
}

rule Dridex_Trojan
{
    meta:
        description = "Detects Dridex banking trojan"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "trojan"
        
    strings:
        $s1 = "bot.dll" nocase
        $s2 = "loader.dll" nocase
        $api1 = "SetWindowsHookEx" nocase
        $api2 = "GetKeyState" nocase
        $inject1 = "NtMapViewOfSection" nocase
        $inject2 = "ZwCreateSection" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        ((1 of ($s*) and 1 of ($api*)) or 2 of ($inject*))
}

rule Zeus_Trojan
{
    meta:
        description = "Detects Zeus banking trojan"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "trojan"
        
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" nocase
        $s2 = "winlogon.exe" nocase
        $s3 = "*.bankofamerica.com*" nocase
        $s4 = "POST" nocase
        $api1 = "HttpSendRequestA" nocase
        $api2 = "InternetReadFile" nocase
        $config = "{bot_id}" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*) and 1 of ($api*)) or $config
}

rule Formbook_Infostealer
{
    meta:
        description = "Detects Formbook infostealer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "trojan"
        
    strings:
        $s1 = "Formbook" nocase
        $s2 = "sqlite3_" nocase
        $s3 = "Login Data" nocase
        $api1 = "GetClipboardData" nocase
        $api2 = "SetClipboardData" nocase
        $api3 = "GetForegroundWindow" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($s*) and 2 of ($api*))
}

rule AgentTesla_Infostealer
{
    meta:
        description = "Detects Agent Tesla infostealer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "trojan"
        
    strings:
        $s1 = "agent" nocase
        $s2 = "tesla" nocase
        $s3 = "Passwords.txt" nocase
        $s4 = "Screen.jpeg" nocase
        $s5 = "Clipboard" nocase
        $email1 = "smtp.gmail.com" nocase
        $email2 = "smtp.office365.com" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        ((2 of ($s*)) or (1 of ($s*) and 1 of ($email*)))
}

rule Generic_Trojan_Behavior
{
    meta:
        description = "Detects generic trojan behavior"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "trojan"
        
    strings:
        $steal1 = "password" nocase
        $steal2 = "credit card" nocase
        $steal3 = "cookie" nocase
        $steal4 = "keylog" nocase
        $net1 = "HttpOpenRequest" nocase
        $net2 = "InternetConnect" nocase
        $persist1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $persist2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $hide1 = "SetFileAttributes" nocase
        $hide2 = "FILE_ATTRIBUTE_HIDDEN" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($steal*) and 1 of ($net*)) or
        (1 of ($persist*) and 1 of ($hide*) and 1 of ($net*))
}
