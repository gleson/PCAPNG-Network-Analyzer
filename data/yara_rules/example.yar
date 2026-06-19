/*
 * Sample YARA rules shipped with pcap_analyzer.
 *
 * Drop additional .yar / .yara files into this directory. They are
 * recompiled lazily on file mtime change.
 *
 * Rule meta:
 *   - severity:    critical | high | medium | low | info
 *                  Drives the alert severity surfaced in the UI.
 *   - description: human-readable note attached to the alert.
 *   - author:      free-form attribution.
 *
 * Tags also influence severity when meta.severity is missing:
 *   high-sev tags:   malware, ransomware, trojan, backdoor, apt,
 *                    exploit, webshell, rat, stealer
 *   medium-sev tags: suspicious, packed, obfuscated, pua, crypto
 */

rule EICAR_Test_File : malware
{
    meta:
        severity = "critical"
        description = "EICAR antivirus test signature transferred over HTTP"
        author = "pcap_analyzer"
        reference = "https://www.eicar.org/?page_id=3950"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule PE_Suspicious_Network_Strings : suspicious
{
    meta:
        severity = "medium"
        description = "Windows executable carved from HTTP traffic with embedded HTTP/IP strings — common in commodity loaders."
        author = "pcap_analyzer"
    strings:
        $mz   = { 4D 5A }
        $http = "http://"
        $post = "POST /"
        $beacon = /User-Agent: [A-Za-z0-9 .\-_\/]{1,40}\r\n/
    condition:
        $mz at 0
        and filesize < 5MB
        and 2 of ($http, $post, $beacon)
}
