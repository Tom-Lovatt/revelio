import shutil
import argparse
import glob
import itertools
import logging
import os
import re
import signal
import tempfile
import sys
import time
import yara
from util.file_preprocessing import preprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
TMP_DIR = os.path.join(tempfile.gettempdir(), 'revelio')
EXTERNAL_VARS_TEMPLATE = {
    'file_num_lines': 0,
    'file_longest_unbroken_string': 0
}
YARA_DETECTION_THRESHOLD = 5
YARA_RULES_PATH = os.path.join(SCRIPT_DIR, 'YaraRules/Index.yar')

log = logging.getLogger(__name__)


def main():
    start_time = time.clock()
    signal.signal(signal.SIGINT, exit_handler)
    config = process_arguments()
    configure_logger(config)

    check_yara_rules_files()
    target_files = enumerate_files(config.targets, config.recurse)
    results = scan(target_files)

    if len(results) == 0:
        msg = "No files with a .php extension were found."
        msg += " Did you mean to supply the --recurse flag?" if not config.recurse else ""
        log.warning(msg)

    print_results(results, time.clock()-start_time)


def check_yara_rules_files():
    try:
        yara.compile(filepath=YARA_RULES_PATH, externals=EXTERNAL_VARS_TEMPLATE)
    except (IOError, yara.Error) as e:
        log.critical("Failed to read or compile the Yara rules file. Ensure that "
                     "{} and all files it references are accessible. Error: {}".format(
                        YARA_RULES_PATH,
                        e))
        sys.exit(1)


def exit_handler(signal, frame):
    log.critical("Caught exit signal, cleaning up and exiting.")
    if os.path.isdir(TMP_DIR):
        try:
            shutil.rmtree(TMP_DIR)
        except IOError as e:
            log.error("Couldn't delete {}: {}".format(TMP_DIR, e))

    sys.exit(1)


def print_results(results, duration):
    flagged = 0
    for path, result in results.items():
        if result['score'] >= YARA_DETECTION_THRESHOLD:
            log.info('{} was flagged by {} rules'.format(path, len(result['rules'])))
            log.debug('{} - {}'.format(path, ','.join(result['rules'])))
            flagged += 1

    log.info("Scanned {} files in  {}s, {} malicious file(s) identified".format(
        len(results),
        round(duration, 2),
        flagged
    ))


def scan(path_list):
    results = {}
    rules = yara.compile(filepath=YARA_RULES_PATH, externals=EXTERNAL_VARS_TEMPLATE)

    for path in path_list:
        log.debug("Scanning " + path)
        if not validate_file(path):
            continue
        temp_path = preprocess(path, TMP_DIR)
        file_stats = gather_file_statistics(temp_path)
        matches = rules.match(temp_path, externals=file_stats)
        results[path] = process_matches(matches)
        os.unlink(temp_path)

    return results


def validate_file(path):
    return (
        '.php' in path.lower() and
        os.path.isfile(path)
    )


def process_matches(matches):
    result = {'rules': [], 'score': 0, 'strings': []}
    for match in matches:
        result['rules'].append(match.rule)
        result['strings'].append(match.strings)
        if 'score' in match.meta:
            result['score'] += match.meta['score']

    return result


def process_arguments():
    parser = argparse.ArgumentParser(description='Scan for malicious PHP files, particularly those using obfuscation.')
    parser.add_argument('-f', '--log-file', action='store', default=None)
    parser.add_argument('-r', '--recurse', action='store_true', default=False)
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help="Don't output to console")
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument(metavar="target directory", action="store", dest="targets", nargs='*')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def configure_logger(config):
    verbosity = logging.DEBUG if config.verbose else logging.INFO
    fmt = '[%(asctime)s] [%(levelname)s] - %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    handlers = []

    if not config.quiet:
        handlers.append(logging.StreamHandler())

    if config.log_file:
        handlers.append(logging.FileHandler(config.log_file))

    logging.basicConfig(level=verbosity, format=fmt, datefmt=datefmt, handlers=handlers)


def enumerate_files(paths, recursive=False):
    files = []
    for path in paths:
        if os.path.isdir(path):
            path = os.path.join(path, '**')
        elif os.path.isfile(path) and '.php' not in path:
            log.warning(path + " doesn't have a .php extension. Including it in the scan "
                               "but results may be inconsistent.")

        files = itertools.chain(glob.iglob(path, recursive=recursive), files)

    return files


def gather_file_statistics(file_path):
    ext_vars = dict(EXTERNAL_VARS_TEMPLATE)
    # This covers most encoded and compressed strings
    regex = re.compile('[^a-zA-Z0-9/+_]')
    with open(file_path, errors='ignore') as f:
        lus = 0
        for line in f.readlines():
            ext_vars['file_num_lines'] += 1
            lus = max(lus, len(max(regex.split(line), key=len)))
        ext_vars['file_longest_unbroken_string'] = lus
    return ext_vars


if __name__ == '__main__':
    main()
