import "math"

/**
 * <Compression/Encoding>
 * These rules attempt to identify compressed or encoded data
 * They may throw false positives for intentionally minified or
 * encoded data, e.g when embedding images as base64
 */
rule File_Entropy {
    meta:
        score = 5

    strings:
        $s1 = "data:image/png;base64"

    condition:
        math.entropy(0, filesize) > 5.58 // 5.7
        and not $s1
}
rule Long_Strings {
    meta:
        score = 5

    strings:
        $s1 = "data:image/png;base64"

    condition:
        file_longest_unbroken_string > 950
        and not $s1
}
rule Possible_Compression {
    meta:
        score = 2

    strings:
        $s1 = "+"
        $s2 = "/"
        $s3 = "+++"

        $s4 = "data:image/png;base64"

    condition:
        (
            (#s1 > 10 and #s2 > 10) and
            (#s1 + #s2)*1.0 \ filesize > 0.035 and
            (#s1 + #s2) \ file_num_lines > 2 or
            $s3
        ) and not
        $s4
}
rule Hex_Encoding {
    meta:
        score = 3

    strings:
        $re1 = /(\\x(6[1-9A-F]|7[0-9A])){3,}/ nocase

    condition:
        $re1
}
rule High_Operator_Density {
    meta:
        score = 3

    strings:
        $re1 = /[-*\/%=.|&^~<>!@`+]/

    condition:
        #re1*1.0 \ filesize > 0.25
}
rule High_Concatenation_Density {
    /**
     * To avoid using functions directly, obfuscated code
     * will often call them through concatenated strings
     * e.g $a = 'aelv'; $a[1].$a[3].$a[0].$a[2]()
     */
    meta:
        score = 3

    strings:
        $re1 = /\. *\$/

    condition:
        #re1*1.0 \ file_num_lines > 0.29
}