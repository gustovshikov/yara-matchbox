rule r1_keyword_swordfish : keyword test {
    meta:
        author = "demo"
        description = "Finds the classic test phrase 'swordfish'"
        severity = "low"
    strings:
        $a = "swordfish" nocase ascii
    condition:
        $a
}

rule r2_has_url_http : network url {
    meta:
        author = "demo"
        description = "Detects http/https URLs"
        severity = "low"
    strings:
        $http = /https?:\/\/[^\s'"]+/ nocase
    condition:
        $http
}

rule r3_fake_aws_access_key : credential aws {
    meta:
        author = "demo"
        description = "Detects AWS-like Access Key IDs (AKIA + 16 chars)"
        severity = "medium"
    strings:
        $ak = /AKIA[0-9A-Z]{16}/
    condition:
        $ak
}

rule r4_png_magic : filetype magic {
    meta:
        author = "demo"
        description = "PNG file signature"
        severity = "info"
    strings:
        $png = { 89 50 4E 47 0D 0A 1A 0A }
    condition:
        $png
}

rule r5_hex_nonce_deadbeef : hex marker {
    meta:
        author = "demo"
        description = "Looks for DE AD BE EF marker"
        severity = "info"
    strings:
        $marker = { DE AD BE EF }
    condition:
        $marker
}

rule xor_demo_prints_key_and_plaintext : demo {
  meta:
    author = "demo"
    description = "Matches XOR'ed strings; on YARA 4.3+ use -X to print key/plaintext"
  strings:
    // Works on 3.11+: match any 1-byte XOR of the literal
    $a_txt = "swordfish" ascii xor
    $b_txt = "trojan"    ascii xor

    // Optional hex equivalents (also OK on 3.11)
    $a_hex = { 73 77 6F 72 64 66 69 73 68 }
    $b_hex = { 74 72 6F 6A 61 6E }
  condition:
    any of them
}

