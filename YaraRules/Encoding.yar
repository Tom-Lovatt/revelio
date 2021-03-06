import "math"

/*
 * <Compression/Encoding>
 * These rules attempt to identify compressed or encoded data
 * They may throw false positives for intentionally minified or
 * encoded data, e.g when embedding images as base64
 */

rule File_Entropy {
    /*
     * Compressed and encoded data tends to increase a file's
     * average Shannon entropy
     */
    meta:
        score = 3

    condition:
        math.entropy(0, filesize) > 5.58
}
rule Long_Strings {
    /*
     * Compressed/encoded data is often stored as a
     * single, large string
     */
    meta:
        score = 4

    condition:
        file_longest_unbroken_string > 950
}
rule Possible_Compression {
    /*
     * Searching for compression via headers or
     * compressed versions of common strings is difficult
     * because they could be further encoded/obfuscated.
     * Looking at the format is often more effective.
     */
    meta:
        score = 2

    strings:
        $s1 = "+"
        $s2 = "/"
        $s3 = "+++"

        // Large chunks of AAAA represents base64 encoded null bytes
        $re1 = /A{10,}/

    condition:
        // Compressed data in base64 has a large quantity of + and / symbols
        // in roughly the same proportion
        (#s1 > 10 and #s2 > 10) and (#s1*1.0 \ #s2 > 0.9) and (
            (#s1 + #s2)*1.0 \ filesize > 0.35 or
            (#s1 + #s2)*1.0 \ file_num_lines > 2
        ) or
        1 of ($s3, $re1)
}
rule Hex_Encoding {
    /*
     * UTF-8 characters can be expressed as \x<XX> where <XX>
     * is the character's hex code. 61-7A is the range for
     * lowercase a-z, often used when encoding function names.
     */
    meta:
        score = 3

    strings:
        $re1 = /((\\x)*(6[1-9A-F]|7[0-9A])){5,}/ nocase

    condition:
        $re1
}
rule Ascii_Numeric_Encoding {
    /*
     * chr() returns a single ASCII character. Concatenating these
     * calls can be used to build strings.
     */
    meta:
        score = 3

    strings:
        $re1 = /(chr\([0-9]{1,3}\)\s*[.,]\s*){5,}/ nocase

    condition:
        $re1
}
rule Encoded_Short_File {
    /*
     * Files with high ratios of encoding to file size
     * are more likely to be obfuscated
     */
    meta:
        score = 3

    condition:
        file_num_lines < 50 and Hex_Encoding
}
rule High_Operator_Density {
    /*
     * Operators can be chained in interesting ways to
     * reduce readability, especially during variable assignment
     */
    meta:
        score = 3

    strings:
        $re1 = /[-*\/%=.|&^~<>!@`+]/

    condition:
        #re1*1.0 \ filesize > 0.25
}
rule High_Bitwise_Density {
    /*
     * As above, but bitwise operators are rarer
     * outside obfuscation, so we can judge a bit
     * more harshly. Can be thrown off by regex or
     * html entities.
     */
    meta:
        score = 4

    strings:
        $re1 = /[^&|][&|~^][^&|#]/ // Don't allow &&, || or html entities

    condition:
        #re1*1.0 \ file_num_lines > 0.9
        and file_num_lines < 100
}
rule High_Concatenation_Density {
    /*
     * To avoid using functions directly, obfuscated code
     * will often call them through concatenated strings
     * e.g $a = 'aelv'; $a[1].$a[3].$a[0].$a[2]()
     */
    meta:
        score = 3

    strings:
        $re1 = /\.\s*\$/
        $re2 = /\([^)]*\)\s*\.\s*/

    condition:
        (#re1+#re2)*1.0 \ file_num_lines > 0.29
        and (#re1+#re2) >= 3
}
rule High_Variable_Density {
    /*
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
rule Variable_Functions_Per_Line {
    /*
     * Calling variables as functions (e.g $a = 'eval' $a(..))
     * can help obfuscate a script, but most legitimate code
     * uses this sparingly.
     */
    meta:
        score = 5

    strings:
        $re1 = /\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\(/

    condition:
        #re1*1.0 \ file_num_lines > 0.2
}
rule Reversed {
    /*
     * Searches for the reversed content, not the process of
     * reversing. See PHPStatements.yar for strrev()
     */
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
    /*
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
    /*
     * Some scripts pretend to be image files, either
     * to bypass upload file restrictions or to avoid
     * detection once they've been uploaded.
     */
    meta:
        score = 5

    strings:
        $re1 = /^GIF89a1/
        $re2 = /^\?JFIF/

    condition:
        any of them
}