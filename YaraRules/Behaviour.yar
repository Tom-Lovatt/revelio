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

        $re1 = /(shell_exec|passthru|system)\(\$_(REQUEST|GET|POST)/ nocase
        $re2 = /print\s*(shell_exec|passthru)\(/ nocase

    condition:
        any of them
}
rule System_Files {
    meta:
        score = 4

    strings:
        $s1 = "/etc/passwd"
        $s2 = "/etc/shadow"
        $s3 = "/etc/resolv.conf"
        $s4 = "/bin/sh"
        $s5 = "/bin/bash"
        $s6 = "/dev/shm"
        $s7 = "/usr/local/apache/conf/httpd.conf"

        /*
         * Matches the directories (but not files within)
         * of /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
         */
        $re1 = /\/usr\/(local\/s)?bin\/[^a-zA-Z]/


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
        $s14 = "octdec("
        $s15 = "fileperms("
        $s16 = "opendir("
        $s17 = "closedir("
        $s18 = "fopen("
        $s19 = "fwrite"
        $s20 = "fclose("
        $s21 = "mkdir"

        $re1 = /chdir\(['"]../
        $re2 = /fopen\(['"]\/tmp/

    condition:
        8 of ($s*)
        or 1 of ($re*)
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
        $s3 = /\$e*mail[-_]*list/ nocase
        $s4 = /(\n|\s+)@*mail\([^)]*\);\(/
        $s5 = "MIME-Version: 1.0" nocase
        $s6 = "From:" nocase
        $s7 = "Return-Path:" nocase

    condition:
        2 of them
}
rule NetworkListener {
    meta:
        score = 5

    strings:
        $s1 = "socket->listen("
        $s2 = "new Server("
        $s3 = "SOCKS server listening" nocase
        $s4 = "socks://"
        $s5 = "IIS://localhost/"

    condition:
        any of them
}
rule MD5Password {
    /**
     * Some webshells have rudimentary login functionality.
     * Since they're standalone, they tend not to use sessions
     * for authentication.
     */
    meta:
        score = 4

    strings:
        $s1 = "md5($_REQUEST["
        $s2 = "md5($_GET["
        $s3 = "md5($_POST["
        $s4 = "md5($pass"
        $s5 = "header(\"WWW-Authenticate" nocase

    condition:
        any of them

}
rule Uploader {
    meta:
        score = 5

    strings:
        $s1 = "move_uploaded_file("
        $s2 = "file_put_contents("
        $s3 = "fopen($_"
        $s4 = "is_uploaded_file("
        $s5 = "$HTTP_POST_FILES"

        $re1 = /copy\(\$_FILES\[.*?\]\[['"]tmp_name['"]\]/

        $re2 = /<\s*form/ nocase
        $re3 = /<input[^>]*type=\\?["'](text|file)/ nocase

    condition:
        1 of ($s1, $s2, $s3, $s4, $s5, $re1) and all of ($re2, $re3)
}
rule Permissive_Directories {
    meta:
        score = 3

    strings:
        $re1 = /mkdir\([^)]*777\)/

    condition:
        $re1
}
rule Echo_User_Input {
    meta:
        score = 3

    strings:
        $s1 = "echo $_REQUEST["
        $s2 = "echo $_GET["
        $s3 = "echo $_POST["

    condition:
        any of them
}
rule Database_Interaction {
    meta:
        score = 5

    strings:
        $s1 = "mysql_connect("
        $s2 = "mysql_select_db("
        $s3 = "mysql_list_dbs("
        $s4 = "mysql_create_db("
        $s5 = "mysql_drop_db("
        $s6 = "mysql_list_tables("
        $s7 = "mysql_db_query("
        $s8 = "DROP DATABASE" nocase
        $s9 = "SHOW PRIVILEGES" nocase
        $s10 = "IDENTIFIED BY PASSWORD" nocase
        $s11 = "DROP USER" nocase
        $s12 = "mysql:host="

    condition:
        any of them
}
rule Privilege_Escalation {
    meta:
        score = 5

    strings:
        $re1 = /-perm -0?[24]00/

    condition:
        $re1
}
rule Possible_Spam {
    meta:
        score = 3

    strings:
        $ua1 = "googlebot" nocase
        $ua2 = "slurp" nocase
        $ua3 = "msnbot" nocase
        $ua4 = "pycurl" nocase
        $ua5 = "facebookexternalhit" nocase
        $ua6 = "ia_archiver" nocase
        $ua7 = "crawl" nocase
        $ua8 = "yandex" nocase
        $ua9 = "rambler" nocase
        $ua10 = "yahoo" nocase
        $ua11 = "bingbot" nocase
        $ua12 = "spider" nocase
        $ua13 = "teoma" nocase
        $ua14 = "baidu" nocase

        $s1 = "HTTP_USER_AGENT"
        $s2 = "curl_exec("


    condition:
        2 of ($ua*)
        and all of ($s*)

}
rule Content_Injection {
    meta:
        score = 5

    strings:
        $s1 = "fputs("

        $re1 = /fopen\([^)]*\.php/

    condition:
        all of them
}
rule Search_Spam {
    meta:
        score = 5

    strings:
        $s1 = "curl_exec"
        $s2 = "bing.com/search?q="

    condition:
        all of them
}
rule Ftp_Activity {
    meta:
        score = 2

    strings:
        $s1 = "ftp_connect("

    condition:
        $s1
}
rule Local_Curl {
    meta:
        score = 3

    strings:
        $re1 = /curl_setopt\([^)]*file:\/\//

    condition:
        $re1
}