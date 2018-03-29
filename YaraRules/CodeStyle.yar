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

        $ex1 = "<script type=\"text/javascript\">"

    condition:
        #s1 \ file_num_lines > 4
        and not ($ex1)
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
rule Large_Files {
    /*
     * Malicious scripts often combine all their dependencies
     * into 1 single file for maximum compatibility. This can
     * massively increase the file size.
     */
     meta:
        score = 4

     condition:
        filesize > 400KB
}