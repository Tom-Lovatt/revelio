# Revelio
Identifies malicious PHP files, particularly those using obfuscation.

## How does it work?
Files are analysed with a variety of methods (primarily laid out as Yara rules) and awarded a number of points for each pattern they match. For instance, using the eval statement may be worth 1 point, whereas executing OS-level commands may be worth 3 points since they can do more damage. When a file reaches a certain level of points (the default being 5), it's reported as suspicious.

## How do I use this?
See the Releases tab and download the revelio-release tar.gz file for a 64-bit executable of Revelio with all dependencies bundled together. Alternatively:
 1. Clone this repository
 2. Install python3
 3. Run `pip3 install -r requirements.txt`
 4. Run Revelio with `python3 revelio.py`
 
 For usage instructions, see `revelio --help` or the instructions below.

```
usage: revelio [-h] [-f LOG_FILE] [-r] [-v] [-g GIT_ROOT]
                  [-w WORDPRESS_ROOT] [-a] [-p {0,1,2,3}]
                  target directory [target directory ...]

Scan for malicious PHP files, particularly those using obfuscation.

positional arguments:
  target directory

optional arguments:
  -h, --help            show this help message and exit
  -f LOG_FILE, --log-file LOG_FILE
                        Send all output to the specified file.
  -r, --recurse         Search recursively within the target directory.
  -v, --verbose         Show all debugging statements.
  -g GIT_ROOT, --git-root GIT_ROOT
                        If target is part of a Git repo, supply the root
                        directory to use Git metadata in the scan. Note: This
                        mode won't scan any files or directories listed in
                        .gitignore
  -w WORDPRESS_ROOT, --wordpress-root WORDPRESS_ROOT
                        If target is part of a Wordpress installation, specify
                        the root directory to include hash verification in the
                        scan
  -a, --aggressive-scan
                        Lower the threshold for how suspicious a file needs to
                        be before it's reported. Can be specified up to 3
                        times, increasing the level each time.
  -p {0,1,2,3}, --priority {0,1,2,3}
                        Set the priority of the scan, from 0-3. Higher
                        priorities will complete faster but use more system
                        resources.
```

For example:

`revelio -p3 -r -w /var/www/example.com/public -g /var/www/example.com /var/www/example.com`
