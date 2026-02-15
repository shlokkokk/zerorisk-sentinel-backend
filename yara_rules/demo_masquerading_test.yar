rule Demo_Masquerading_Invoice_EICAR
{
    meta:
        description = "Demonstration rule to detect masquerading document executables using the EICAR test string"
        author = "ZeroRisk Sentinel"
        reference = "EICAR standard antivirus test + document masquerading technique"
        scope = "educational / demo"
        severity = "high"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $doc_keyword1 = "invoice"
        $doc_keyword2 = "receipt"
        $doc_keyword3 = "payment"
        $doc_keyword4 = ".pdf"

    condition:
        // Windows executable (MZ header)
        uint16(0) == 0x5A4D and

        // Safe test malware indicator
        $eicar and

        // Common document masquerading indicators
        any of ($doc_keyword*)
}
