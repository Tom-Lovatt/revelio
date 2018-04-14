import os
import re

_COMMENT_REGEXES = [
    # /* */ format
    '/\*.*?\*/',
    # // format
    '(?<=\\n)\s*//.*?(?=\\n|$)',
    # # format
    '(?<=\\n)\s*#.*?(?=\\n|$)'
]


def _strip_comments(text: str) -> str:
    """
    Remove PHP-style comments from the given text
    """
    pattern = re.compile('|'.join(_COMMENT_REGEXES), re.DOTALL)
    return pattern.sub("", text)


def _strip_script_tags(text: str) -> str:
    """
    Remove JS script tags from the given text
    """
    pattern = re.compile('<script\s*type=["\']text/javascript["\'].*?</script>', re.DOTALL)
    return pattern.sub("", text)


def _strip_image_data(text: str) -> str:
    """
    Remove base64 encoded image data from the given text
    """
    pattern = re.compile('data:image/.*?;base64,[^\'"]*')
    return pattern.sub("", text)


def preprocess(file_path: str, tmp_dir: str) -> str:
    """
    Make a best-effort attempt to strip:
        * PHP comments
        * JS script tags
        * Base64 encoded images
    from the given file.

    :param file_path: File to preprocess
    :param tmp_dir: Temp directory to write the modified file to
    :return: Path to the modified file
    """
    if not os.path.isdir(tmp_dir):
        os.mkdir(tmp_dir)

    temp_path = os.path.join(tmp_dir, os.path.basename(file_path))
    content = open(file_path, "r", errors="ignore").read()

    content = _strip_comments(content)
    content = _strip_script_tags(content)
    content = _strip_image_data(content)

    f = open(temp_path, "w", errors="ignore")
    f.write(content)
    f.close()

    return temp_path
