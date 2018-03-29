/**
 * <Behaviour>
 * This looks at malicious behaviour
 *
 *
 */

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