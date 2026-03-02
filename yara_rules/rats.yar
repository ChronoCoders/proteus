rule NanoCore_RAT
{
    meta:
        description = "Detects NanoCore RAT"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "rat"
        
    strings:
        $s1 = "NanoCore" nocase
        $s2 = "Client.exe" nocase
        $s3 = "Plugins" nocase
        $s4 = "RunDelayed" nocase
        $s5 = "InjectionTarget" nocase
        $mutex = "PluginMutex" nocase
        $pdb = "NanoCore.pdb" nocase
        
    condition:
        uint16(0) == 0x5A4D and (3 of ($s*) or $mutex or $pdb)
}

rule njRAT
{
    meta:
        description = "Detects njRAT (Bladabindi)"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "rat"
        
    strings:
        $s1 = "Youssef" nocase
        $s2 = "njrat" nocase
        $s3 = "Bladabindi" nocase
        $s4 = "|'|'|" 
        $cmd1 = "netsh firewall" nocase
        $cmd2 = "reg add" nocase
        $base64_1 = "SEVMTEFOSmFSQUQ=" // base64: HELLANJaRAD
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($cmd1 and $cmd2) or $base64_1)
}

rule DarkComet_RAT
{
    meta:
        description = "Detects DarkComet RAT"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "rat"
        
    strings:
        $s1 = "DarkComet" nocase
        $s2 = "DCNEW" nocase
        $s3 = "#BOT#" nocase
        $s4 = "DEFAUL-PORTNO" nocase
        $mutex = "DC_MUTEX"
        $config = "GENCODE"
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $mutex or $config)
}

rule QuasarRAT
{
    meta:
        description = "Detects Quasar RAT"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "rat"
        
    strings:
        $s1 = "Quasar" nocase
        $s2 = "xRAT" nocase
        $s3 = "Client.exe" nocase
        $namespace = "xServer" nocase
        $class = "Core.Networking" nocase
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or ($namespace and $class))
}

rule AsyncRAT
{
    meta:
        description = "Detects AsyncRAT"
        author = "Proteus"
        date = "2025-11-02"
        severity = "critical"
        family = "rat"
        
    strings:
        $s1 = "AsyncClient" nocase
        $s2 = "AsyncRAT" nocase
        $s3 = "Pastebin" nocase
        $s4 = "Async_Rat" nocase
        $mutex = "AsyncMutex_"
        $pdb = "AsyncRAT.pdb" nocase
        
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $mutex or $pdb)
}

rule Generic_RAT_Behavior
{
    meta:
        description = "Detects generic RAT behavior patterns"
        author = "Proteus"
        date = "2025-11-02"
        severity = "high"
        family = "rat"
        
    strings:
        $cap1 = "GetAsyncKeyState" nocase
        $cap2 = "keybd_event" nocase
        $cap3 = "mouse_event" nocase
        $cap4 = "GetForegroundWindow" nocase
        $screen1 = "BitBlt" nocase
        $screen2 = "GetDC" nocase
        $remote1 = "WSAStartup" nocase
        $remote2 = "connect" nocase
        $remote3 = "send" nocase
        $remote4 = "recv" nocase
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($cap*) and 2 of ($remote*)) or
        (1 of ($screen*) and 3 of ($remote*) and 1 of ($cmd*))
}
