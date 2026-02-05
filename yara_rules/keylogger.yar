/*
 * ZeroRisk Sentinel - Keylogger Detection
 * Tightened for low false positives
 */

import "pe"
import "math"

// CORE: Windows hook APIs — 99% of keyloggers use these
rule keylogger_hooks {
    meta:
        description = "Keyboard hook APIs"
        severity = "critical"
    
    strings:
        $a = "SetWindowsHookEx" nocase
        $b = "WH_KEYBOARD_LL" nocase
        $c = "WH_KEYBOARD" nocase
        $d = "GetAsyncKeyState" nocase
        $e = "GetKeyboardState" nocase
        $f = "RegisterRawInputDevices" nocase
    
    condition:
        any of them
}

// CORE: Kernel-level — rootkits, invisible to normal tools
rule keylogger_kernel {
    meta:
        description = "Kernel-mode keylogging"
        severity = "critical"
    
    strings:
        $a = "Kbdclass" nocase
        $b = "KeyboardClassDriver" nocase
        $c = "KEYBOARD_INPUT_DATA" nocase
        $d = "IRP_MJ_READ" nocase
        $e = "IoAttachDevice" nocase
    
    condition:
        any of them
}

// CORE: Code injection — steals from browsers before encryption
rule keylogger_injection {
    meta:
        description = "Code injection for keylogging"
        severity = "critical"
    
    strings:
        $a = "DetourAttach" nocase
        $b = "MH_CreateHook" nocase
        $c = "WriteProcessMemory" nocase
    
    condition:
        any of them
}

// MODERATE: Visual logging — screenshots + active window tracking
// Requires BOTH screenshot AND window focus tracking
rule keylogger_visual {
    meta:
        description = "Visual keylogging"
        severity = "medium"
    
    strings:
        $screen = "BitBlt" nocase
        $dup = "IDXGIOutputDuplication" nocase
        $focus = "GetForegroundWindow" nocase
        $title = "GetWindowText" nocase
    
    condition:
        ($screen or $dup) and ($focus or $title)
}

// TIGHTENED: Targeting — needs app name AND credential keyword
rule keylogger_targeting {
    meta:
        description = "Targeting credential apps"
        severity = "high"
    
    strings:
        $app1 = "chrome.exe" nocase
        $app2 = "firefox.exe" nocase
        $app3 = "msedge.exe" nocase
        $app4 = "KeePass" nocase
        $app5 = "1Password" nocase
        $app6 = "LastPass" nocase
        $app7 = "Bitwarden" nocase
        
        $cred1 = "password" nocase
        $cred2 = "login" nocase
        $cred3 = "credential" nocase
        $cred4 = "CVV" nocase
    
    condition:
        any of ($app*) and any of ($cred*)
}

// NEW: Clipboard stealers — modern malware copies Ctrl+C
rule keylogger_clipboard {
    meta:
        description = "Clipboard monitoring"
        severity = "high"
    
    strings:
        $a = "GetClipboardData" nocase
        $b = "SetClipboardViewer" nocase
        $c = "WM_DRAWCLIPBOARD" nocase
        $d = "OpenClipboard" nocase
    
    condition:
        any of them
}

// Persistence — starts with Windows
rule keylogger_persist {
    meta:
        description = "Persistence mechanisms"
        severity = "medium"
    
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $b = "schtasks" nocase
        $c = "CreateService" nocase
        $d = "RunOnce" nocase
    
    condition:
        any of them
}

// Exfiltration — where stolen data goes
rule keylogger_exfil {
    meta:
        description = "Exfiltration channels"
        severity = "medium"
    
    strings:
        $a = "smtp." nocase
        $b = "pastebin.com" nocase
        $c = "discord.com/api/webhooks" nocase
        $d = "telegram.org/bot" nocase
        $e = "api.telegram.org" nocase
    
    condition:
        any of them
}

// Anti-analysis — tries to hide from sandboxes
rule keylogger_evasion {
    meta:
        description = "Evasion techniques"
        severity = "medium"
    
    strings:
        $a = "IsDebuggerPresent" nocase
        $b = "CheckRemoteDebuggerPresent" nocase
        $c = "vmware" nocase
        $d = "virtualbox" nocase
        $e = "Sandboxie" nocase
    
    condition:
        any of them
}

// Python keyloggers — script-based
rule keylogger_python {
    meta:
        description = "Python keylogger"
        severity = "critical"
    
    strings:
        $lib = "pynput" nocase
        $hook = "keyboard" nocase
        $cb1 = "on_press" nocase
        $cb2 = "on_release" nocase
    
    condition:
        ($lib or $hook) and ($cb1 or $cb2)
}

// PowerShell keyloggers — fileless malware
rule keylogger_powershell {
    meta:
        description = "PowerShell keylogging"
        severity = "critical"
    
    strings:
        $a = "Get-Keystrokes" nocase
        $b = "GetAsyncKeyState" nocase
        $c = "-WindowStyle Hidden" nocase
        $d = "-EncodedCommand" nocase
        $e = "Add-Type" nocase
    
    condition:
        any of ($a, $b) or (2 of ($c, $d, $e))
}

// Packed/encrypted — hides strings but still needs imports
rule keylogger_packed {
    meta:
        description = "Packed binary with keylogger imports"
        severity = "medium"
    
    condition:
        math.entropy(0, filesize) > 7.5 and
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            pe.imports("user32.dll", "SetWindowsHookEx") or
            pe.imports("user32.dll", "GetAsyncKeyState")
        )
}

// Generic keywords — last resort, lower confidence
rule keylogger_generic {
    meta:
        description = "Keylogger keywords"
        severity = "low"
    
    strings:
        $a = "keylogger" nocase
        $b = "keystroke" nocase
        $c = "keylog" nocase
        $d = "[ENTER]" nocase
        $e = "[BACKSPACE]" nocase
        $f = "[TAB]" nocase
    
    condition:
        2 of them
}