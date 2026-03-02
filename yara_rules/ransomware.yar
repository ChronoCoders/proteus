rule WannaCry_Ransomware
{
    meta:
        description = "Detects WannaCry ransomware"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "ransomware"
        
    strings:
        $s1 = "tasksche.exe" nocase
        $s2 = "mssecsvc.exe" nocase
        $s3 = "diskpart.exe" nocase
        $s4 = "icacls . /grant Everyone:F" nocase
        $s5 = "attrib +h ." nocase
        $s6 = ".WCRY" nocase
        $s7 = ".WNCRY" nocase
        $s8 = "WNcry@2ol7" nocase
        $url = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        
    condition:
        uint16(0) == 0x5A4D and (3 of ($s*) or $url)
}

rule Ryuk_Ransomware
{
    meta:
        description = "Detects Ryuk ransomware"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "ransomware"
        
    strings:
        $s1 = "RyukReadMe.txt" nocase
        $s2 = "ryuk" nocase
        $s3 = ".RYK" nocase
        $s4 = "Hermes" nocase
        $cmd1 = "vssadmin Delete Shadows" nocase
        $cmd2 = "vssadmin resize shadowstorage" nocase
        $cmd3 = "net stop" nocase
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or 2 of ($cmd*))
}

rule Maze_Ransomware
{
    meta:
        description = "Detects Maze ransomware"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "ransomware"
        
    strings:
        $s1 = "DECRYPT-FILES.txt" nocase
        $s2 = "maze" nocase
        $s3 = "ChaCha" nocase
        $s4 = "RSA-2048" nocase
        $mutex = "Global\\{8761ABBD-7F85-42EE-B272-A76179687C63}"
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $mutex)
}

rule Locky_Ransomware
{
    meta:
        description = "Detects Locky ransomware"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "ransomware"
        
    strings:
        $s1 = ".locky" nocase
        $s2 = ".zepto" nocase
        $s3 = ".odin" nocase
        $s4 = "_HELP_instructions.html"
        $s5 = "_WHAT_is.html"
        
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Generic_Ransomware_Behavior
{
    meta:
        description = "Detects generic ransomware behavior patterns"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "ransomware"
        
    strings:
        $encrypt1 = "AES" nocase
        $encrypt2 = "RSA" nocase
        $encrypt3 = "ChaCha" nocase
        $ransom1 = "bitcoin" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "ransom" nocase
        $ransom4 = "payment" nocase
        $file1 = ".encrypted"
        $file2 = ".locked"
        $file3 = ".crypto"
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wbadmin delete" nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled no" nocase
        
    condition:
        uint16(0) == 0x5A4D and 
        (1 of ($encrypt*) and 2 of ($ransom*)) or
        (2 of ($file*) and 1 of ($cmd*))
}
