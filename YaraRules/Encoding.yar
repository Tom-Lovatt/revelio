import "math"

/**
 * <Compression/Encoding>
 * These rules attempt to identify compressed or encoded data
 * They may throw false positives for intentionally minified or
 * encoded data, e.g when embedding images as base64
 */
rule File_Entropy {
    meta:
        score = 3

    strings:
        $ex1 = "<script type=\"text/javascript\">"
        $ex2 = /data\:image\/[a-z0-9.\-+]*;base64/

    condition:
        math.entropy(0, filesize) > 5.58 // 5.58
        and not (1 of ($ex*))
}
rule Long_Strings {
    meta:
        score = 4

    strings:
        $ex1 = /data\:image\/[a-z0-9.\-+]*;base64/

    condition:
        file_longest_unbroken_string > 950
        and $ex1
}
rule Possible_Compression {
    /**
     * We can't search for compression via headers or
     * compressed versions of common strings because
     * they could be further encoded/obfuscated
     */
    meta:
        score = 2

    strings:
        $s1 = "+"
        $s2 = "/"
        $s3 = "+++"

        $ex1 = /data\:image\/[a-z0-9.\-+]*;base64/

    condition:
        (
            // Compressed data has a large quantity of + and / symbols
            // in roughly the same proportion
            (#s1 > 10 and #s2 > 10) and (#s1*1.0 \ #s2 > 0.9) and (
                (#s1 + #s2)*1.0 \ filesize > 0.35 or
                (#s1 + #s2)*1.0 \ file_num_lines > 2
            ) or
            $s3
        )
        and not $ex1
}
rule Hex_Encoding {
    meta:
        score = 3

    strings:
        $re1 = /((\\x)*(6[1-9A-F]|7[0-9A])){5,}/ nocase

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
        $re1 = /\.\s*\$/

    condition:
        #re1*1.0 \ file_num_lines > 0.29
}
rule High_Variable_Density {
    /**
     * As above, but searching for other uses of the variable.
     * Can be thrown off by minified embedded jQuery
     */
     meta:
        score = 4

     strings:
        $re1 = /\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*/

     condition:
        #re1*1.0 \ file_num_lines > 2.1
}
rule Reversed {
    meta:
        score = 5

    strings:
        $s1 = "(tessi(fi"
        $s2 = ";)("
        $s3 = "noitcnuf"

    condition:
        2 of them
}
rule High_Multiline_Concatenation {
    /**
     * Encoded strings are often split across many lines
     * to avoid detection. If a file is mostly made up of
     * concatenated strings, it's likely encoded.
     */
    meta:
        score = 4

    strings:
        $re1 = /\.[ \t]*\n/

    condition:
        #re1*1.0 \ file_num_lines > 0.8
}
rule Bad_MIME_Type {
    /**
     * Some scripts pretend to be image files, either
     * to bypass upload file restrictions or to avoid
     * detection once they've been uploaded.
     */
    meta:
        score = 5

    strings:
        $re1 = "/^GIF89a1/"

    condition:
        $re1
}