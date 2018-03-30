import os
import re
import tempfile


COMMENT_REGEXES = [
    '/\*.*?\*/',
    '(?<=\\n)\s*//.*?(?=\\n|$)',
    '(?<=\\n)\s*#.*?(?=\\n|$)'
]


def get_temp_path(path):
    temp_dir = os.path.join(tempfile.gettempdir(), "revelio")
    if not os.path.isdir(temp_dir):
        os.mkdir(temp_dir)
    temp_path = os.path.join(temp_dir, os.path.basename(path + '.tmp'))
    return temp_path


def strip_comments(text):
    pattern = re.compile('|'.join(COMMENT_REGEXES), re.DOTALL)
    return pattern.sub("", text)


def strip_script_tags(text):
    pattern = re.compile('<script\s*type=["\']text/javascript["\'].*?</script>', re.DOTALL)
    return pattern.sub("", text)


def preprocess(file_path):
    temp_path = get_temp_path(file_path)
    content = open(file_path, "r", errors="ignore").read()

    content = strip_comments(content)
    content = strip_script_tags(content)

    f = open(temp_path, "w", errors="ignore")
    f.write(content)
    f.close()

    return temp_path
