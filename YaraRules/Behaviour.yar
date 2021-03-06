/*
 * <Behaviour>
 * This looks at how malicious files behave and what services
 * they offer. These are generally used by a very small minority
 * of legitimate files, if at all.
 */

rule Command_Passthrough {
    /*
     * This is the basis for interactive shells, which simply
     * execute user input as an OS-level command
     */
    meta:
        score = 5

    strings:
        $s1 = "$_POST['cmd']"
        $s2 = "$_GET['cmd']"

        $re1 = /(^|[^A-Za-z_])(shell_exec|passthru|system)\((\$_(REQUEST|GET|POST|COOKIE)|getenv)\(/ nocase
        $re2 = /print\s*(shell_exec|passthru)\(/ nocase

    condition:
        any of them
}
rule System_Files {
    /*
     * Access to sensitive system files can be used to escalate
     * privileges or pivot to other servers/services
     */
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
        $s8 = "ls -la"

        /*
         * Matches the directories (but not files within)
         * of /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
         */
        $re1 = /\/usr\/(local\/s)?bin\/[^a-zA-Z]/


    condition:
        any of them
}
rule File_Manipulation {
    /*
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
		$s6 = "symlink("
		$s7 = "chmod("
		$s8 = "octdec("
		$s9 = "fileperms("
		$s10 = "fopen("
		$s11 = "fwrite"
		$s12 = "is_link("
		$s13 = "filectime("
		$s14 = "fileatime("
		$s15 = "posix_getgrgid("
		$s16 = "posix_getegid("
		$s17 = "chdir("
		$s18 = "mkdir("
		$s19 = "opendir("
		$s20 = "readdir("
		$s21 = "dirname("

        $re1 = /chdir\(['"]../
        $re2 = /fopen\(['"]\/tmp/

    condition:
        8 of ($s*)
        or 1 of ($re*)
}
rule Directory_Lister {
    /*
     * Similar to above but less functionality. Prints a
     * directory tree on page load, hence the frequent lack of
     * a function or class definition
     */

     meta:
        score = 5

     strings:
        $s1 = "opendir("
        $s2 = "readdir("
        $s3 = "closedir("

        $ex1 = "function "
        $ex2 = "class "

        $re1 = /echo[^;]*getcwd\(/
        $re2 = /exec\(['"]pwd/
        $re3 = /echo[^;]*SCRIPT_FILENAME/
        $re4 = /(print|echo)[^;]*scandir\(/

     condition:
        (any of ($s*) and (#ex1 + #ex2 < 2))
        or any of ($re*)
}
rule Self_Deletion {
    /*
     * Some infected files propagate across the system then
     * delete the installer to reduce visibility
     */
    meta:
        score = 5

    strings:
        $s1 = "unlink(__FILE__)"

    condition:
        $s1
}
rule Mailers {
    /*
     * Lightweight mailing scripts can use the infected
     * server to spread spam.
     */
    meta:
        score = 5

    strings:
        $s1 = /\$smtp[-_]*password/ nocase
        $s2 = /\$smtp[-_]*server/ nocase
        $s3 = /\$e*mail[-_]*list/ nocase
        $s4 = /(\n|\s+)@*mail\([^)]*\);/
        $s5 = "MIME-Version: 1.0" nocase
        $s6 = "From:" nocase
        $s7 = "Return-Path:" nocase

    condition:
        2 of them
}
rule NetworkListener {
    /*
     * Setting up a network listener can allow
     * attackers out-of-band access
     */
    meta:
        score = 5

    strings:
        $s1 = "socket->listen"
        $s2 = "new Server("
        $s3 = "SOCKS server listening" nocase
        $s4 = "socks://"
        $s5 = "IIS://localhost/"
        $s6 = "socket_listen"
        $s7 = "socket_recv"

    condition:
        any of them
}
rule Password_Lock {
    /*
     * Some webshells have rudimentary login functionality.
     * Since they're standalone, they tend not to use sessions
     * for authentication.
     */
    meta:
        score = 4

    strings:
        $s1 = "md5($pass" nocase

        $re1 = /header\(["']WWW-Authenticate/ nocase
        $re2 = /\$_REQUEST\[['"]pass/
        $re3 = /md5\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]\s*\)/

    condition:
        any of them

}
rule Session_Management {
    /*
     * As above, but smart enough to use sessions.
     * Not scored as highly since sessions are used
     * far more legitimately.
     */
    meta:
        score = 2

    strings:
        $s1 = "session_start("
        $s2 = "session_destroy("

    condition:
        any of them
}
rule Uploader {
    /*
     * A simple form and upload handler in a single
     * file, making it easier to upload additional malicious files.
     */
    meta:
        score = 5

    strings:
        $s1 = "move_uploaded_file("
        $s2 = "is_uploaded_file("
        $s3 = "$HTTP_POST_FILES"
        $s4 = "file_put_contents("

        $re1 = /copy\(\$_FILES\[.*?\]\[['"]tmp_name['"]\]/

        $re2 = /<\s*form/ nocase
        $re3 = /<input[^>]*type=\\?["']?(file|text)/ nocase

        $re4 = /(fopen|fwrite|fputs)\([^)]*\$_(POST|GET|REQUEST|COOKIE)/

    condition:
        (1 of ($s*, $re1) and all of ($re2, $re3)) or
        $re4

}
rule Permissive_Directories {
    /*
     * Directories in octal mode 777 are readable and
     * writable by anyone
     */
    meta:
        score = 3

    strings:
        $re1 = /mkdir\([^)]*777\)/

    condition:
        $re1
}
rule Echo_User_Input {
    /*
     * Directly echoing user input can be used to
     * execute arbitrary code
     */
    meta:
        score = 3

    strings:
        $s1 = "echo $_REQUEST["
        $s2 = "echo $_GET["
        $s3 = "echo $_POST["
        $s4 = "echo $_COOKIE["

    condition:
        any of them
}
rule Database_Interaction {
    /*
     * Site compromises are often used to gain access
     * to the database and dump as much of it as possible
     */
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
        $s8 = "SHOW DATABASES" nocase
        $s9 = "DROP DATABASE" nocase
        $s10 = "SHOW PRIVILEGES" nocase
        $s11 = "IDENTIFIED BY PASSWORD" nocase
        $s12 = "DROP USER" nocase
        $s13 = "mysql:host="

    condition:
        any of them
}
rule Privilege_Escalation {
    /*
     * Many web shells contain features to help aid OS-level
     * privilege escalation, like searching for SUID/SGID files
     */
    meta:
        score = 5

    strings:
        $re1 = /-perm -0?[24]00/

    condition:
        $re1
}
rule Possible_Spam {
    /*
     * Some scripts display different content depending on
     * user agent, either to show spam only to search engines or
     * to hide malicious functionality from crawlers
     */
    meta:
        score = 5

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
    /*
     * Appending content to other PHP files is one method
     * for infecting or defacing them.
     */
    meta:
        score = 5

    strings:
        $s1 = "fputs("
	$s2 = "fwrite("

        $re1 = /fopen\([^)]*\.php[^,]*,\s*['"]w\+?['"]\s*\)/

    condition:
        $re1 and 1 of ($s*)
}
rule Search_Spam {
    /*
     * Some services exist to artificially inflate traffic
     * for particular search terms.
     */
    meta:
        score = 5

    strings:
        $s1 = "curl_exec"
        $s2 = "bing.com/search?q="

    condition:
        all of them
}
rule Ftp_Activity {
    /*
     * FTP connections can be used for pivoting and privilege escalation.
     */
    meta:
        score = 2

    strings:
        $s1 = "ftp_connect("

    condition:
        $s1
}
rule Local_Curl {
    /*
     * Curling local URLs can be used to bypass some security
     * measures and file include detection
     */
    meta:
        score = 3

    strings:
        $re1 = /curl_setopt\([^)]*(file|ftp):\/\//

    condition:
        $re1
}
rule Remote_Shell {
    /*
     * Scripts can combine a network listener with OS commands
     * to create a remote shell, similar to telnet/SSH
     */
    meta:
        score = 5

    strings:
        $s1 = "fsockopen("
        $s2 = "fwrite("
        $s3 = "fputs("

        $re1 = /(^|[^A-Za-z_])(shell_exec|system|passthru)\(/

    condition:
        $s1 and 1 of ($s2, $s3) and $re1
}
rule Compressor {
    /*
     * Manually writing compressed files to disk can be used to
     * quickly download entire directories without relying on
     * library functions.
     */
    meta:
        score = 4

    strings:
        $s1 = "\\x50\\x4b" // Matches ZIP signature
        $s2 = "fwrite("

    condition:
        $s1 and $s2

}
rule Self_Modification {
    /*
     * Some advanced shells can update themselves to newer
     * versions. Simpler scripts sometimes use self-modification
     * for rudimentary chatrooms or defacements
     */
    meta:
        score = 4

    strings:
        $re1 = /fopen\(__FILE__,\s*["'][wa]/

    condition:
        $re1
}
rule UDP_Traffic {
    /*
     * UDP traffic is rarely used in web applications but
     * is heavily used in DDOS attacks
     */
    meta:
        score = 4

    strings:
        $s1 = "udp://"

    condition:
        $s1
}
rule Delete_PHP_Files {
    /*
     * Similar to self-deletion, but can be used to hide other
     * infected files after use, not just the calling script.
     */
    meta:
        score = 3

    strings:
        $re1 = /unlink\([^)]*\.php/ nocase

    condition:
        $re1
}
rule Error_Page_Masquerading {
    /*
     * Many shells emulate default error pages to avoid suspicion
     * if an unsuspecting user browse to them
     */
    meta:
        score = 3

    strings:
        $s1 = "<title>404 Not Found</title>" nocase
        $s2 = "while trying to use an ErrorDocument to handle the request" nocase

    condition:
        any of them
}