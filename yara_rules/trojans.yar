/*
Trojan and Backdoor Detection Rules
*/

rule Trojan_Process_Injection {
    meta:
        description = "Detects process injection techniques"
        author = "ZeroRisk Sentinel"
        severity = "critical"
    
    strings:
        $inject1 = "CreateRemoteThread" ascii wide
        $inject2 = "VirtualAllocEx" ascii wide
        $inject3 = "WriteProcessMemory" ascii wide
        $inject4 = "ReadProcessMemory" ascii wide
        $inject5 = "NtCreateThreadEx" ascii wide
        $inject6 = "QueueUserAPC" ascii wide
        $inject7 = "SetThreadContext" ascii wide
    
    condition:
        3 of them
}

rule Trojan_Persistence_Mechanisms {
    meta:
        description = "Detects persistence mechanisms"
        author = "ZeroRisk Sentinel"
        severity = "high"
    
    strings:
        $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg_runonce = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $startup_folder = "\\Start Menu\\Programs\\Startup" ascii wide
        $service_create = "CreateService" ascii wide
        $schtask = "schtasks" ascii wide
        $reg_set = "RegSetValueEx" ascii wide
    
    condition:
        2 of them
}

rule Trojan_Network_Communication {
    meta:
        description = "Detects network communication for C2"
        author = "ZeroRisk Sentinel"
        severity = "medium"
    
    strings:
        $net1 = "InternetOpen" ascii wide
        $net2 = "InternetConnect" ascii wide
        $net3 = "HttpSendRequest" ascii wide
        $net4 = "HttpOpenRequest" ascii wide
        $net5 = "URLDownloadToFile" ascii wide
        $net6 = "WinHttpOpen" ascii wide
        $c2_url = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    
    condition:
        3 of ($net*) or $c2_url
}

rule Trojan_Keylogger {
    meta:
        description = "Detects keylogger functionality"
        author = "ZeroRisk Sentinel"
        severity = "critical"
    
    strings:
        $hook1 = "SetWindowsHookEx" ascii wide
        $hook2 = "WH_KEYBOARD_LL" ascii wide
        $hook3 = "WH_KEYBOARD" ascii wide
        $key1 = "GetAsyncKeyState" ascii wide
        $key2 = "GetKeyState" ascii wide
        $key3 = "GetKeyboardState" ascii wide
        $key4 = "MapVirtualKey" ascii wide
        $log1 = "keylog" nocase ascii wide
        $log2 = "keystroke" nocase ascii wide
    
    condition:
        (any of ($hook*) and any of ($key*)) or (2 of ($log*))
}

rule Trojan_Screen_Capture {
    meta:
        description = "Detects screen capture functionality"
        author = "ZeroRisk Sentinel"
        severity = "high"
    
    strings:
        $screen1 = "BitBlt" ascii wide
        $screen2 = "GetDC" ascii wide
        $screen3 = "GetWindowDC" ascii wide
        $screen4 = "CreateCompatibleBitmap" ascii wide
        $screen5 = "GetDesktopWindow" ascii wide
    
    condition:
        3 of them
}