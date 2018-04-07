# Revelio
Identifies malicious PHP files, particularly those using obfuscation.

## How does it work?
Files are analysed with a variety of methods (primarily laid out as Yara rules) and awarded a number of points for each pattern they match. For instance, using the eval statement may be worth 1 point, whereas executing OS-level commands may be worth 3 points since they can do more damage. When a file reaches a certain level of points (the default being 5), it's reported as suspicious.
