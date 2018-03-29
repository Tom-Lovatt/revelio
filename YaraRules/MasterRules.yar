import "math"

include "PHPStatements.yar"


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


rule Command_Passthrough {
    meta:
        score = 3

    strings:
        $s1 = "$_POST['cmd']"
        $s2 = "$_GET['cmd']"

    condition:
        any of them
}
rule System_Files {
    meta:
        score = 5

    strings:
        $s1 = "/etc/passwd"
        $s2 = "/bin/sh"
        $s3 = "/bin/bash"

    condition:
        any of them
}
rule File_Manipulation {
    meta:
        score = 2

    strings:
        $s1 = "htpasswd"
        $s2 = "htaccess"

    condition:
        3 of them
}

/**
 * <Code style>
 * Most programmers optimise their code style for readability
 * and maintainability; malware generators do the opposite.
 *
 */

rule Statements_Per_Line {
    /** Can produce false positive where minified JS is printed by PHP */
    meta:
        score = 3

    strings:
        $s1 = ";"
        $s2 = "<script type=\"text/javascript\">"

    condition:
        #s1 \ file_num_lines > 4
        and not $s2
}
rule Whitespace_Hiding_Injection {
    /* Whitespace following the PHP tag is often used
     to push injected code out of an editor window */
    meta:
        score = 4

    strings:
        $re1 = /^\<\?php\s{15,}\S/

    condition:
        $re1
}