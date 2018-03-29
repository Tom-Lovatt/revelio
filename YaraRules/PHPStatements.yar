/**
 * <PHP Statements>
 * These rules cover commonly abused PHP statements, related
 * to obfuscation and executing commands.
 *
 */
rule Eval {
    meta:
        score = 2

    strings:
        $s1 = "eval("

    condition:
        $s1
}
rule Reversed {
    meta:
        score = 2

    strings:
        $s1 = "strrev("
        $s2 = ";)("
        $s3 = "noitcnuf"

    condition:
        2 of them
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
        $s1 = "passthru("
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
     * Some scripts obfuscate everything, including normal PHP
     * If none of PHP's keywords appear at all, it's likely obfuscated
     * TODO: explain/justify removing 'as', 'do' and 'echo'. The first
     *       2 are short enough to cause false positives within random data
     *       echo is one of the few statements actually used in obfuscated scripts,
     *       maybe because it's a built-in rather than a function?
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
        $ex18 = "endforeach"
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

        $s1 = ";"

    condition:
        $s1 and not (any of ($ex*))
}


