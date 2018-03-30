/**
 * <PHP Statements>
 * These rules cover commonly abused PHP statements, related
 * to obfuscation and executing commands.
 *
 */
rule Evaluate {
    meta:
        score = 2

    strings:
        $s1 = "eval("
        $s2 = "assert("

    condition:
        any of them
}
rule Evaluate_Dynamic_Input {
    meta:
        score = 4

    strings:
        $re1 = /(eval|assert)\([^);]*(file_get_contents|\$_REQUEST|\$_GET|\$_POST|getenv)/

    condition:
        $re1
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
rule UUencode {
    meta:
        score = 4

    strings:
        $s1 = "convert_uudecode("

    condition:
        $s1
}
rule Gzinflate {
    meta:
        score = 1

    strings:
        $s1 = "gzinflate("

    condition:
        $s1
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
        $s1 = "passthru(" fullword // Avoid fpassthru
        $s2 = "shell_exec("
        $s3 = "popen("
        $s4 = "proc_open("
        $s5 = "pcntl_exec("
        $s6 = "netstat"

        $re1 = /(^|[^A-Za-z_])system\(/

    condition:
        any of them
}
rule NoKeywords {
    /**
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
        $ex1 = "__halt_compiler("
        $ex2 = "abstract"
        $ex3 = "and"
        $ex4 = "array("
        $ex5 = "break"
        $ex6 = "callable"
        $ex7 = "clone"
        $ex8 = "const"
        $ex9 = "continue"
        $ex10 = "declare"
        $ex11 = "default"
        $ex12 = "die("
        $ex13 = "else"
        $ex14 = "elseif"
        $ex15 = "empty("
        $ex16 = "enddeclare"
        $ex17 = "endfor"
        $ex18 = "foreach"
        $ex19 = "endif"
        $ex20 = "endswitch"
        $ex21 = "endwhile"
        $ex22 = "eval("
        $ex23 = "exit("
        $ex24 = "extends"
        $ex25 = "final"
        $ex26 = "finally"
        $ex27 = "global"
        $ex28 = "goto"
        $ex29 = "include_once"
        $ex30 = "instanceof"
        $ex31 = "insteadof"
        $ex32 = "list("
        $ex33 = "namespace"
        $ex34 = "private"
        $ex35 = "protected"
        $ex36 = "public"
        $ex37 = "require"
        $ex38 = "require_once"
        $ex39 = "return"
        $ex40 = "static"
        $ex41 = "switch"
        $ex42 = "throw"
        $ex43 = "trait"
        $ex44 = "try"
        $ex45 = "unset("
        $ex46 = "use"
        $ex47 = "var"
        $ex48 = "while"
        $ex49 = "xor"
        $ex50 = "__CLASS__"
        $ex51 = "__DIR__"
        $ex52 = "__FILE__"
        $ex53 = "__FUNCTION__"
        $ex54 = "__LINE__"
        $ex55 = "__METHOD__"
        $ex56 = "__NAMESPACE__"
        $ex57 = "__TRAIT__"

        $ex58 = /if\s*\(/
        $ex59 = /do\s*\{/
        $ex60 = /for\s*\{/

        $s1 = ";"

    condition:
        $s1 and not (any of ($ex*))
}
rule ExecuteRegex {
        meta:
            score = 5

        strings:
            $re1 = /\("\/[^\/]*\/e",/

        condition:
            $re1
}