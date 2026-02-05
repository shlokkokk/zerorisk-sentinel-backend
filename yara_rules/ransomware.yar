/*
Ransomware Detection Rules
*/

rule Ransomware_Bitcoin_Address {
    meta:
        description = "Detects Bitcoin addresses in files (common in ransom notes)"
        author = "ZeroRisk Sentinel"
        severity = "high"
    
    strings:
        $btc_p2pkh = /1[a-km-zA-HJ-NP-Z1-9]{25,34}/
        $btc_p2sh = /3[a-km-zA-HJ-NP-Z1-9]{25,34}/
        $btc_bech32 = /bc1[a-z0-9]{39,59}/
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $ransom_note2 = "ALL YOUR FILES ARE ENCRYPTED" nocase
        $ransom_note3 = "PAYMENT" nocase
        $ransom_note4 = "DECRYPT" nocase
        $ransom_note5 = "BITCOIN" nocase
        $ransom_note6 = "RANSOM" nocase
    
    condition:
        (any of ($btc_*)) and (2 of ($ransom_note*))
}

rule Ransomware_Shadow_Copy_Deletion {
    meta:
        description = "Detects shadow copy deletion (common ransomware behavior)"
        author = "ZeroRisk Sentinel"
        severity = "critical"
    
    strings:
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wmic shadowcopy delete" nocase
        $cmd3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled no" nocase
        $cmd5 = "wbadmin delete catalog" nocase
    
    condition:
        any of them
}

rule Suspicious_Encryption_API {
    meta:
        description = "Detects use of encryption APIs (possible ransomware)"
        author = "ZeroRisk Sentinel"
        severity = "medium"
    
    strings:
        $crypt1 = "CryptEncrypt" ascii wide
        $crypt2 = "CryptDecrypt" ascii wide
        $crypt3 = "CryptGenKey" ascii wide
        $crypt4 = "CryptImportKey" ascii wide
        $crypt5 = "CryptExportKey" ascii wide
        $aes = "AES" ascii wide
        $rsa = "RSA" ascii wide
    
    condition:
        3 of them
}