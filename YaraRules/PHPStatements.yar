/*
 * <PHP Statements>
 * These rules cover commonly abused PHP statements, related
 * to obfuscation and executing commands.
 *
 */

rule Evaluate {
    meta:
        score = 1

    strings:
        $s1 = "eval("
        $s2 = "assert("

        $re1 = /['"](eval|assert)['"]/

    condition:
        any of them
}
rule Evaluate_Dynamic_Input {
    meta:
        score = 4

    strings:
        $re1 = /(eval|assert)\([^);]*(file_get_contents|\$_REQUEST|\$_GET|\$_POST|\$_COOKIE|getenv)/

    condition:
        $re1
}
rule Evaluate_Encoded {
    meta:
        score = 5

    strings:
        $re1 = /(eval|assert)\([^)]*(base64_decode|str_rot13|convert_uudecode|gz|bz)/

    condition:
        $re1
}
rule Include_Dynamic_Input {
    meta:
        score = 5

    strings:
        $s1 = "allow_url_include"

        $re1 = /include\(['"]php\:\/\/input['"]\)/
        $re2 = /include\([^)]*(\$_REQUEST|\$_GET|\$_POST|\$_COOKIE|getenv)/

    condition:
        any of them
}
rule String_Reverse {
    meta:
        score = 1

    strings:
        $s1 = "strrev("

    condition:
        $s1

}
rule Base64 {
    meta:
        score = 1

    strings:
        $s1 = "base64_decode("

    condition:
        $s1
}
rule Rot13 {
    meta:
        score = 4

    strings:
        $s1 = "str_rot13("

    condition:
        $s1
}
rule UUencoded {
    meta:
        score = 4

    strings:
        $s1 = "convert_uudecode("

    condition:
        $s1
}
rule Gzip_Decompression {
    meta:
        score = 1

    strings:
        $s1 = "gzinflate("
        $s2 = "gzuncompress("

    condition:
        any of them
}
rule Bzip_Decompression {
    meta:
        score = 2

    strings:
        $s1 = "bzdecompress("

    condition:
        $s1
}
rule OS_Commands {
    meta:
        score = 3

    strings:
        $s1 = "shell_exec("
        $s2 = "proc_open("
        $s3 = "pcntl_exec("
        $s4 = "netstat"

        $re1 = /(^|[^A-Za-z_])system\(/
        $re2 = /(^|[^A-Za-z_])passthru\(/
        $re3 = /popen\(.*?,\s['"]r['"]\s*?\)/

    condition:
        any of them
}
rule No_Keywords {
    /*
     * Some scripts obfuscate everything, including normal PHP.
     * If none of PHP's keywords appear at all, it's likely obfuscated.
     * 'as', 'do', and 'echo' don't appear below. The first two are
     * short enough to cause false positives within random data, and
     * require the while keyword anyway. The echo keyword appears
     * in even heavily obfuscated scripts, since it's the simplest output
     */
    meta:
        score = 4

    strings:
		$ex1 = "abstract"
		$ex2 = "and"
		$ex3 = "break"
		$ex4 = "callable"
		$ex5 = "clone"
		$ex6 = "const"
		$ex7 = "continue"
		$ex8 = "declare"
		$ex9 = "default"
		$ex10 = "else"
		$ex11 = "elseif"
		$ex12 = "enddeclare"
		$ex13 = "endfor"
		$ex14 = "foreach"
		$ex15 = "endif"
		$ex16 = "endswitch"
		$ex17 = "endwhile"
		$ex18 = "extends"
		$ex19 = "final"
		$ex20 = "finally"
		$ex21 = "global"
		$ex22 = "goto"
		$ex23 = "include"
		$ex24 = "instanceof"
		$ex25 = "insteadof"
		$ex26 = "namespace"
		$ex27 = "private"
		$ex28 = "protected"
		$ex29 = "public"
		$ex30 = "require"
		$ex31 = "require_once"
		$ex32 = "return"
		$ex33 = "static"
		$ex34 = "switch"
		$ex35 = "throw"
		$ex36 = "trait"
		$ex37 = "try"
		$ex38 = "use"
		$ex39 = "var"
		$ex40 = "while"
		$ex41 = "xor"
		$ex42 = "__CLASS__"
		$ex43 = "__DIR__"
		$ex44 = "__FILE__"
		$ex45 = "__FUNCTION__"
		$ex46 = "__LINE__"
		$ex47 = "__METHOD__"
		$ex48 = "__NAMESPACE__"

        $ex58 = /if\s*\(/
        $ex59 = /do\s*\{/
        $ex60 = /for\s*\{/

        $s1 = ";"

    condition:
        $s1 and not (any of ($ex*))
}
rule ExecuteRegex {
        /*
         * Passing the 'e' flag to preg_replace will evaluate the replace
         * pattern as PHP code. Deprecated in PHP 5.5.0, removed in PHP 7.0.0
         */
        meta:
            score = 5

        strings:
            $re1 = /\(["']\/[^\/]*\/e["'],/

        condition:
            $re1
}
rule Server_Info {
        /*
         * Some malicious files will just expose sensitive server information
         * for use in further attacks.
         */
        meta:
            score = 3

        strings:
            $s1 = "phpinfo();"

            $ex1 = "ob_start()"

            $re1 = /\$_SERVER\[["']SERVER_SIGNATURE["']\]/
            $re2 = /\$_SERVER\[["']SERVER_ADMIN["']\]/


        condition:
            1 of ($re1, $re2)
            or ($s1 and not $ex1)
}
rule Risky_Statements_Per_Line {
        /*
         * When legitimate code uses risky statements as
         * detected above, it usually has a large amount
         * of other functionality, making for larger files.
         */
        meta:
            score = 5

        condition:
            file_num_lines < 50 and (
                Evaluate or                 // yara-python doesn't seem to support
                Evaluate_Dynamic_Input or   // 'any of (..)' syntax for Rule references
                Evaluate_Encoded or
                String_Reverse or
                Rot13 or
                UUencoded or
                OS_Commands or
                ExecuteRegex or
                Server_Info
            )
}
rule Extract_User_Input {
        /*
         * Extract imports variables from an array, overwriting
         * existing ones if necessary, making it very dangerous
         * to use on user input.
         */
        meta:
            score = 5

        strings:
            $re1 = /extract\(\$HTTP_(GET|SERVER|POST)_VARS/
            $re2 = /extract\(\$_(GET|POST|REQUEST|COOKIE)/

        condition:
            any of them
}