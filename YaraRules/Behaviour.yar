/**
 * <Behaviour>
 * This looks at malicious behaviour
 *
 *
 */

rule Command_Passthrough {
    meta:
        score = 5

    strings:
        $s1 = "$_POST['cmd']"
        $s2 = "$_GET['cmd']"

        $re1 = /(passthru|system)\(\$_(REQUEST|GET|POST)/

    condition:
        any of them
}
rule System_Files {
    meta:
        score = 4

    strings:
        $s1 = "/etc/passwd"
        $s2 = "/etc/resolv.conf"

        $s3 = "/bin/sh"
        $s4 = "/bin/bash"

    condition:
        any of them
}
rule File_Manipulation {
    /**
     * Most PHP files will match at least one of these strings
     * Webshells will match a large number since they tend to
     * to give total filesystem access to the user
     */
    meta:
        score = 3

    strings:
        $s1 = "htpasswd"
        $s2 = "htaccess"
        $s3 = "getcwd()"
        $s4 = "lstat("
        $s5 = "umask("
        $s6 = "chdir("
        $s7 = "symlink("
        $s8 = "chmod("
        $s9 = "readdir("
        $s10 = "is_link("
        $s11 = "filectime("
        $s12 = "fileatime("
        $s13 = "posix_getgrgid("

    condition:
        8 of them
}
rule Self_Deletion {
    meta:
        score = 5

    strings:
        $s1 = "unlink(__FILE__)"

    condition:
        $s1
}
rule Mailers {
    meta:
        score = 5

    strings:
        $s1 = /\$smtp[-_]*password/ nocase
        $s2 = /\$smtp[-_]*server/ nocase
        $s3 = /\$email[-_]*list/ nocase

    condition:
        2 of them
}
rule NetworkListener {
    meta:
        score = 5

    strings:
        $s1 = "socket->listen("
        $s2 = "new Server("
        $s3 = "SOCKS server listening"
        $s4 = "socks://"

    condition:
        any of them
}