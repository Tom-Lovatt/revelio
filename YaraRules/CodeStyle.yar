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