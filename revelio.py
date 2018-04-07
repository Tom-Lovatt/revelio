import argparse
import glob
import itertools
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
from time import sleep

from util.file_preprocessing import preprocess
from util.processors import GitProcessor as Git
from util.processors import WordpressProcessor as Wordpress
from util.processors import YaraProcessor as Yara
from util.result import Result

SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
TMP_DIR = os.path.join(tempfile.gettempdir(), 'revelio')

SCORE_ALERT_THRESHOLD = 5
PROGRESS_UPDATE_PERIOD = 10

log = logging.getLogger(__name__)


def main():
    global SCORE_ALERT_THRESHOLD

    config = process_arguments()
    config.start_time = time.time()
    signal.signal(signal.SIGINT, exit_handler)
    configure_logger(config)
    SCORE_ALERT_THRESHOLD -= config.aggressive_scan
    config.show_progress = not config.log_file

    log.info("Searching for files...")
    target_files = enumerate_files(config.targets, config.recurse)
    results = scan(target_files, config)

    if len(results) == 0:
        msg = "No files with a .php extension were found."
        msg += " Did you mean to supply the --recurse flag?" if not config.recurse else ""
        log.warning(msg)

    print_results(results, time.time() - config.start_time)


def exit_handler(signal, frame):
    log.critical("Caught exit signal, cleaning up and exiting.")
    if os.path.isdir(TMP_DIR):
        try:
            shutil.rmtree(TMP_DIR)
        except IOError as e:
            log.error("Couldn't clean up temp files, failed to delete {}: {}".format(TMP_DIR, e))

    sys.exit(1)


def print_results(results, duration):
    flagged = 0
    for path, result in results.items():
        if result.score >= SCORE_ALERT_THRESHOLD:
            log.info('{} was flagged with the following notes: {}\n'.format(path, ', '.join(result.rules)))
            log.debug('{} file had a score of {}'.format(path, result.score))
            flagged += 1

    log.info("Scanned {} files in {}s, {} suspicious file(s) identified".format(
        len(results),
        round(duration, 2),
        flagged
    ))


def scan(path_list, config):
    processors = []
    yara = Yara(SCRIPT_DIR)
    results = {}

    if not yara.ready():
        log.critical("Failed to start Yara.")
        sys.exit(1)
    processors.append(yara)

    if config.wordpress_root:
        processors.append(Wordpress(config.wordpress_root))

    if config.git_root:
        processors.append(Git(config.git_root))

    if config.show_progress:
        path_list = list(path_list)
        num_targets = sum(1 for x in path_list)
        log.info("{} files and directories found. Scanning...".format(num_targets))

    last_update = time.time()
    scan_count = 0
    suspicious_count = 0
    for path in path_list:
        scan_count += 1
        if os.path.isdir(path):
            continue
        if not validate_file(path):
            log.debug(path + " doesn't look like a PHP file, skipping.")
            continue

        results[path] = Result()

        log.debug("Scanning " + path)
        temp_path = preprocess(path, TMP_DIR)

        for processor in processors:
            if processor.ready():
                log.debug("Running {} plugin".format(processor.get_processor_name()))
                results[path].merge_with(processor.process(temp_path, path))

        if results[path].score >= SCORE_ALERT_THRESHOLD:
            suspicious_count += 1

        if config.show_progress and time.time() > last_update + PROGRESS_UPDATE_PERIOD:
            last_update = time.time()
            print_progress(scan_count, num_targets, suspicious_count, config.start_time)

        os.unlink(temp_path)
        if config.priority < 3:
            sleep((3 - config.priority) * 0.05)

    return results


def print_progress(scan_count, total_count, suspicious_count, start_time):
    completion = round((scan_count * 1.0 / total_count) * 100, 2)
    completion_time = (time.time() - start_time) / scan_count * (total_count - scan_count)
    if completion_time >= 60:
        completion_time = int(completion_time / 60)
        completion_time = str(completion_time) + (" minutes" if completion_time > 1 else " minute")
    else:
        completion_time = "<1 minute"

    log.info("{} files scanned, {} suspicious files found, {}% complete. ".format(
        scan_count, suspicious_count, completion)
             + "Estimate {} until completion.".format(completion_time)
             )


def validate_file(path):
    return (
        '.php' in path.lower() and
        os.path.isfile(path)
    )


def process_arguments():
    parser = argparse.ArgumentParser(description='Scan for malicious PHP files, particularly those using obfuscation.')
    parser.add_argument('-f', '--log-file', action='store', default=None,
                        help="Send all output to the specified file.")
    parser.add_argument('-r', '--recurse', action='store_true', default=False,
                        help="Search recursively within the target directory.")
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help="Show all debugging statements.")
    parser.add_argument('-g', '--git-root', action='store', default=False,
                        help="If target is part of a Git repo, supply the root directory to "
                             "use Git metadata in the scan. Note: This mode won't scan any "
                             "files or directories listed in .gitignore")
    parser.add_argument('-w', '--wordpress-root', action='store', default=False,
                        help="If target is part of a Wordpress installation, specify "
                             "the root directory to include hash verification in the scan")
    parser.add_argument('-a', '--aggressive-scan', action='count', default=0,
                        help="Lower the threshold for how suspicious a file needs to "
                             "be before it's reported. Can be specified up to 3 times, "
                             "increasing the level each time.")
    parser.add_argument('-p', '--priority', action='count', default=0,
                        help="Increase the priority of the scan. It will run quicker "
                             "but take up more system resources. Can be specified up to 3 "
                             "times, increasing the priority each time.")
    parser.add_argument(metavar="target directory", action="store", dest="targets", nargs='+')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def configure_logger(config):
    verbosity = logging.DEBUG if config.verbose else logging.INFO
    fmt = '[%(asctime)s] [%(levelname)s] - %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    handlers = []

    if config.log_file:
        handlers.append(logging.FileHandler(config.log_file))
    else:
        handlers.append(logging.StreamHandler())

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


if __name__ == '__main__':
    main()
