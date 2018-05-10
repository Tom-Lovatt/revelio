import argparse
import datetime
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
from time import sleep
from typing import Any, List, Dict

from util.file_preprocessing import preprocess
from util.processors import BaseProcessor, GitProcessor, WordpressProcessor, YaraProcessor
from util.result import Result

SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
TMP_DIR = os.path.join(
    tempfile.gettempdir(),
    'revelio-'.format(datetime.datetime.now().strftime("%s"))
)

PROGRESS_UPDATE_PERIOD = 10

log = logging.getLogger(__name__)


def main() -> None:
    config = process_arguments()
    configure_logger(config)
    # Catch CTRL-C interrupts
    signal.signal(signal.SIGINT, exit_handler)

    log.info("Searching for files...")
    target_files = get_file_list(config.targets, config.recurse)
    results = scan(target_files, config)

    if len(results) == 0:
        msg = "No files with a .php extension were found."
        msg += " Did you mean to supply the --recurse flag?" if not config.recurse else ""
        log.warning(msg)

    print_results(results, time.time() - config.start_time)
    exit_handler()


def process_arguments() -> Any:
    """
    Process command line arguments into a single config object.

    :return: The ArgParse namespace
    """
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
    parser.add_argument('-p', '--priority', action='store', default=2,
                        help="Set the priority of the scan, from 0-3. Higher priorities "
                             "will complete faster but use more system resources.",
                        type=int, choices=[0, 1, 2, 3])
    parser.add_argument(metavar="target directory", action="store", dest="targets", nargs='+')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    config = parser.parse_args()
    config.start_time = time.time()
    config.score_alert_threshold = Result.DEFAULT_SUSPICIOUS_THRESHOLD - config.aggressive_scan
    config.show_progress = not config.log_file

    return config


def configure_logger(config: Any) -> None:
    """
    Set the appropriate verbosity and destination for logging output.
    """
    verbosity = logging.DEBUG if config.verbose else logging.INFO
    fmt = '[%(asctime)s] [%(levelname)s] - %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    handlers = []

    if config.log_file:
        handlers.append(logging.FileHandler(config.log_file))
    else:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(level=verbosity, format=fmt, datefmt=datefmt, handlers=handlers)


def get_processors(config: Any) -> List[BaseProcessor]:
    """
    Build a list of Processors to scan files with.
    """
    processors = []
    yara = YaraProcessor(SCRIPT_DIR)

    if not yara.ready():
        log.critical("Failed to start Yara.")
        sys.exit(1)
    processors.append(yara)

    if config.wordpress_root:
        processors.append(WordpressProcessor(config.wordpress_root))

    if config.git_root:
        processors.append(GitProcessor(config.git_root))

    return processors


def get_file_list(paths: List[str], recursive=False, follow_links=False) -> List[str]:
    """
    Find files from within a list of paths with optional recursion.
    Warning: Symlinks will not be followed by default.
    """
    all_files = []
    for path in paths:
        if os.path.islink(path) and not follow_links:
            log.warning("Found a symlink at {}, not following.".format(path))
            continue
        if os.path.isfile(path):
            all_files.append(path)
            continue

        for dir_path, dir_names, filenames in os.walk(path):
            for dir_name in dir_names:
                full_dir_path = os.path.join(dir_path, dir_name)
                if os.path.islink(full_dir_path):
                    log.warning("Found a symlink at {}, not following.".format(full_dir_path))
            for filename in filenames:
                all_files.append(os.path.join(dir_path, filename))
            if not recursive:
                break

    return all_files


def validate_file(path: str) -> bool:
    """
    Simple check to see if a path looks like a PHP file
    """
    return (
        '.php' in path.lower() and
        os.path.isfile(path)
    )


def scan(path_list: List[str], config: Any) -> Dict[str, Result]:
    """
    For each of the given file paths, scan it for malicious PHP
    patterns and assign it a score based on how suspicious it seems.
    """
    processors = get_processors(config)
    num_targets = -1
    scan_count = 0
    suspicious_count = 0
    results = {}

    if config.show_progress:
        path_list = list(path_list)
        num_targets = len(path_list)
        log.info("{} files found. Scanning...".format(num_targets))

    last_update = time.time()
    for path in path_list:
        scan_count += 1
        if os.path.isdir(path):
            continue
        if not validate_file(path):
            log.debug(path + " doesn't look like a PHP file, skipping.")
            continue

        results[path] = Result(config.score_alert_threshold)
        log.debug("Scanning " + path)
        temp_path = preprocess(path, TMP_DIR)
        for processor in processors:
            if processor.ready():
                results[path].merge_with(processor.process(temp_path, path))

        if results[path].is_suspicious():
            suspicious_count += 1

        if config.show_progress and time.time() > last_update + PROGRESS_UPDATE_PERIOD:
            last_update = time.time()
            print_progress(scan_count, num_targets, suspicious_count, config.start_time)

        os.unlink(temp_path)
        if config.priority < 3:
            sleep((3 - config.priority) * 0.05)

    return results


def print_progress(scanned: int, total: int, suspicious: int, start_time: float) -> None:
    """
    Display the current progress of the scan and estimated finish time.
    """
    completion = round((scanned * 1.0 / total) * 100, 2)
    completion_time = (time.time() - start_time) / scanned * (total - scanned)
    if completion_time >= 60:
        completion_time = int(completion_time / 60)
        completion_time = str(completion_time) + (" minutes" if completion_time > 1 else " minute")
    else:
        completion_time = "<1 minute"

    log.info("{} PHP files scanned, {} suspicious files found, {}% complete. ".format(
        scanned, suspicious, completion) +
             "Estimate {} until completion.".format(completion_time)
             )


def print_results(results: dict, duration: float) -> None:
    """
    Display the final list of suspicious files along with a summary of the scan.
    """
    flagged = 0
    for path, result in results.items():
        if result.is_suspicious():
            log.info('{} was flagged with the following notes: {}\n'.format(path, ', '.join(result.rules)))
            flagged += 1
        else:
            log.debug('{} file had a score of {} with the following rules: {}'.format(
                path, result.score, ', '.join(result.rules)))

    log.info("Scanned {} files in {}s, {} suspicious file(s) identified".format(
        len(results),
        round(duration, 2),
        flagged
    ))


def exit_handler(exit_signal: int=0, frame: Any=None) -> None:
    """
     Clean up any temp files before exiting.
    """
    if exit_signal:
        log.critical("Caught exit signal, cleaning up and exiting.")
    if os.path.isdir(TMP_DIR):
        try:
            shutil.rmtree(TMP_DIR)
        except IOError as e:
            log.error("Couldn't clean up temp files, failed to delete {}: {}".format(TMP_DIR, e))

    sys.exit(exit_signal)


if __name__ == '__main__':
    main()
