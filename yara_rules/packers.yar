rule UPX_Packer
{
    meta:
        description = "Detects UPX packed executable"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "packer"
        
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $upx4 = "UPX2" ascii
        $section1 = ".UPX0" ascii
        $section2 = ".UPX1" ascii
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($upx*) or 2 of ($section*))
}

rule ASPack_Packer
{
    meta:
        description = "Detects ASPack packed executable"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "packer"
        
    strings:
        $s1 = "ASPack" ascii
        $s2 = ".aspack" ascii
        $s3 = ".adata" ascii
        $pattern = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
        
    condition:
        uint16(0) == 0x5A4D and (1 of ($s*) or $pattern)
}

rule Themida_Packer
{
    meta:
        description = "Detects Themida/WinLicense packer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "packer"
        
    strings:
        $s1 = "Themida" nocase
        $s2 = "WinLicense" nocase
        $s3 = "Oreans" nocase
        $section1 = ".themida" ascii
        $section2 = ".winlice" ascii
        $pattern = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 }
        
    condition:
        uint16(0) == 0x5A4D and (1 of ($s*) or 1 of ($section*) or $pattern)
}

rule VMProtect_Packer
{
    meta:
        description = "Detects VMProtect packer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "packer"
        
    strings:
        $s1 = "VMProtect" nocase
        $s2 = ".vmp0" ascii
        $s3 = ".vmp1" ascii
        $s4 = ".vmp2" ascii
        $pattern = { 9C 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 }
        
    condition:
        uint16(0) == 0x5A4D and (1 of ($s*) or $pattern)
}

rule PECompact_Packer
{
    meta:
        description = "Detects PECompact packer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "packer"
        
    strings:
        $s1 = "PECompact" nocase
        $s2 = "pec1" ascii
        $s3 = "pec2" ascii
        $pattern = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 }
        
    condition:
        uint16(0) == 0x5A4D and (1 of ($s*) or $pattern)
}

rule MPRESS_Packer
{
    meta:
        description = "Detects MPRESS packer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "packer"
        
    strings:
        $s1 = "MPRESS" nocase
        $s2 = ".MPRESS1" ascii
        $s3 = ".MPRESS2" ascii
        $pattern = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 }
        
    condition:
        uint16(0) == 0x5A4D and (1 of ($s*) or $pattern)
}

rule Petite_Packer
{
    meta:
        description = "Detects Petite packer"
        author = "Proteus"
        date = "2025-11-02"
        severity = "medium"
        family = "packer"
        
    strings:
        $s1 = "Petite" nocase
        $s2 = ".petite" ascii
        $pattern = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 }
        
    condition:
        uint16(0) == 0x5A4D and ($s1 or $s2 or $pattern)
}

rule Generic_Packer_High_Entropy
{
    meta:
        description = "Detects potentially packed executable based on entropy"
        author = "Proteus"
        date = "2025-11-02"
        severity = "low"
        family = "packer"
        
    strings:
        $unusual_section1 = ".packed" ascii
        $unusual_section2 = ".enigma" ascii
        $unusual_section3 = ".nsp" ascii
        $unusual_section4 = ".boom" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        (1 of them)
}
