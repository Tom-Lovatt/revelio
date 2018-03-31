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

    condition:
        #s1 \ file_num_lines > 4
        and file_num_lines > 5
}
rule Whitespace_Hiding_Injection {
    /* Whitespace following the PHP tag is often used
     to push injected code out of an editor window */
    meta:
        score = 4

    strings:
        $re1 = /^\<\?php[\t ]{15,}[^\s\n]/

    condition:
        $re1
}
rule Large_Files {
    /*
     * Malicious scripts often combine all their dependencies
     * into 1 single file for maximum compatibility. This can
     * massively increase their file size.
     */
     meta:
        score = 4

     condition:
        filesize > 400KB
}
rule Create_And_Call_Function {
    /*
     * Creating an anonymous function via create_function
     * (and often immediately calling it) can be used to hide
     * behaviour, since the function body is passed as a
     * string, not a statement.
     */
    meta:
        score = 5

    strings:
        $s1 = "call_user_func(create_function("
        $s2 = "create_function(null"

    condition:
        any of them
}
rule Hardcoded_IP_Addresses {
    /**
     * Legitimate code usually favours domain names over
     * hardcoded IP addresses, except in the local address
     * ranges.
     */
    meta:
        score = 4

    strings:
        $re1 = /http:\/\/(\d{1,3}\.){3}\d{1,3}/

        $ex1 = /http:\/\/127\.0\.\d{1,3}\.\d{1,3}/
        $ex2 = /http:\/\/169\.254\d{1,3}\.\d{1,3}/
        $ex3 = /http:\/\/192\.168\d{1,3}\.\d{1,3}/
        $ex4 = /http:\/\/10\.(\d{1,3}\.){2}\.\d{1,3}/

    condition:
        $re1 and not (1 of ($ex*))
}
rule Superglobal_Density {
    meta:
        score = 2

    strings:
        $s1 = "$GLOBALS["

    condition:
        #s1*1.0 \ file_num_lines > 0.25
        and #s1 > 10
}