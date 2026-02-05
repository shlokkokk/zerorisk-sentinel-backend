/*
Packer and Obfuscation Detection Rules
*/

rule Packer_UPX {
    meta:
        description = "Detects UPX packed executables"
        author = "ZeroRisk Sentinel"
        severity = "info"
    
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx_sig = { 55 50 58 21 }
    
    condition:
        any of them
}

rule Packer_ASPack {
    meta:
        description = "Detects ASPack packed executables"
        author = "ZeroRisk Sentinel"
        severity = "info"
    
    strings:
        $aspack = "aspack" nocase ascii
        $aspack_section = ".aspack" ascii
    
    condition:
        any of them
}

rule Packer_VMProtect {
    meta:
        description = "Detects VMProtect packed executables"
        author = "ZeroRisk Sentinel"
        severity = "medium"
    
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $vmp2 = "VMProtect" nocase ascii
    
    condition:
        any of them
}

rule Packer_Themida {
    meta:
        description = "Detects Themida packed executables"
        author = "ZeroRisk Sentinel"
        severity = "medium"
    
    strings:
        $themida = "Themida" nocase ascii
        $sec1 = ".themida" ascii
        $sec2 = ".winlice" ascii
    
    condition:
        any of them
}

rule Suspicious_Code_Obfuscation {
    meta:
        description = "Detects code obfuscation patterns"
        author = "ZeroRisk Sentinel"
        severity = "medium"
    
    strings:
        $obf1 = { 60 9C 8B EC }
        $obf2 = { E8 00 00 00 00 }
        $obf3 = { EB 01 }
    
    condition:
        2 of them
}