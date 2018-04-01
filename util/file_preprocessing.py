import os
import re
import tempfile


COMMENT_REGEXES = [
    '/\*.*?\*/',
    '(?<=\\n)\s*//.*?(?=\\n|$)',
    '(?<=\\n)\s*#.*?(?=\\n|$)'
]


def strip_comments(text):
    pattern = re.compile('|'.join(COMMENT_REGEXES), re.DOTALL)
    return pattern.sub("", text)


def strip_script_tags(text):
    pattern = re.compile('<script\s*type=["\']text/javascript["\'].*?</script>', re.DOTALL)
    return pattern.sub("", text)


def strip_image_data(text):
    pattern = re.compile('data:image/.*?;base64,[^\'"]*')
    return pattern.sub("", text)


def preprocess(file_path, tmp_dir):
    if not os.path.isdir(tmp_dir):
        os.mkdir(tmp_dir)

    temp_path = os.path.join(tmp_dir, os.path.basename(file_path))
    content = open(file_path, "r", errors="ignore").read()

    content = strip_comments(content)
    content = strip_script_tags(content)
    content = strip_image_data(content)

    f = open(temp_path, "w", errors="ignore")
    f.write(content)
    f.close()

    return temp_path
