import abc
import json
import logging
import os
import re
import yara
from hashlib import md5

import git
import requests

from util.result import Result


class Processor(metaclass=abc.ABCMeta):
    log = logging.getLogger(__name__)

    def ready(self):
        return False

    def process(self, temp_path, real_path):
        raise NotImplementedError()

    def get_processor_name(self):
        raise NotImplementedError()


class YaraProcessor(Processor):

    EXTERNAL_VARS_TEMPLATE = {
        'file_num_lines': 0,
        'file_longest_unbroken_string': 0
    }
    yara_rules_path = 'YaraRules/Index.yar'

    log = logging.getLogger(__name__)
    init_succeeded = False

    def __init__(self, project_root):
        self.yara_rules_path = os.path.join(project_root, self.yara_rules_path)
        self.init_succeeded = self.check_rules_files()

    def check_rules_files(self):
        try:
            yara.compile(filepath=self.yara_rules_path, externals=YaraProcessor.EXTERNAL_VARS_TEMPLATE)
        except (IOError, yara.Error) as e:
            self.log.critical("Failed to read or compile the Yara rules file. Ensure that "
                              "{} and all files it references are accessible. Error: {}".format(
                                self.yara_rules_path, e))
            return False
        return True

    def gather_file_statistics(self, file_path):
        ext_vars = dict(self.EXTERNAL_VARS_TEMPLATE)
        # This covers most encoded and compressed strings
        regex = re.compile('[^a-zA-Z0-9/+_]')
        with open(file_path, errors='ignore') as f:
            lus = 0
            for line in f.readlines():
                ext_vars['file_num_lines'] += 1
                lus = max(lus, len(max(regex.split(line), key=len)))
            ext_vars['file_longest_unbroken_string'] = lus
        return ext_vars

    def ready(self):
        return self.init_succeeded

    def process(self, temp_path, real_path):
        externals = self.gather_file_statistics(temp_path)
        rules = yara.compile(filepath=self.yara_rules_path, externals=externals)
        matches = rules.match(temp_path)
        result = self.process_matches(matches)

        return result

    @staticmethod
    def process_matches(matches):
        result = Result()
        for match in matches:
            result.merge_with({
                'rules': [match.rule],
                'strings': match.strings,
                'score': match.meta['score']
            })

        return result

    @staticmethod
    def get_processor_name():
        return 'Yara'


class GitProcessor:
    # How much to increase/decrease the result score by
    # for (un)committed files
    UNCOMMITTED_FILES_WEIGHTING = 5
    COMMITTED_FILES_WEIGHTING = 2

    git_root = ""
    repo = None

    log = logging.getLogger(__name__)

    @staticmethod
    def is_git_dir(path):
        if not (os.path.exists(path) and os.path.isdir(path)):
            return False

        try:
            git.Repo(path)
        except git.exc.InvalidGitRepositoryError as e:
            return False

        return True

    def __init__(self, project_root):
        if not self.is_git_dir(project_root):
            self.log.warning(project_root + " doesn't look like a Git repo, disabling the Git plugin.")
        else:
            self.repo = git.Repo(project_root)
            self.git_root = project_root

    def ready(self):
        return len(self.git_root) > 0

    def is_file_changed(self, path):
        return (
            path in self.repo.untracked_files or
            self.repo.git.diff(None, 'HEAD', path)
        )

    def process(self, temp_path, real_path):
        result = Result()
        path = real_path.replace(self.git_root, '')
        if self.is_file_changed(path):
            result.score = self.UNCOMMITTED_FILES_WEIGHTING
            result.rules = ['Git_Uncommitted_Changes']
        else:
            result.score = -self.COMMITTED_FILES_WEIGHTING

        return result

    @staticmethod
    def get_processor_name():
        return 'Git'


class WordpressProcessor:
    log = logging.getLogger(__name__)

    WP_CHECKSUM_URL = "https://api.wordpress.org/core/checksums/1.0/?version={}&locale=en_GB"
    WP_VERSION_FILE = "wp-includes/version.php"

    # How much to increase/decrease the result score by
    HASH_SCORE_WEIGHTING = 3

    wp_root = ""
    checksums = {}

    @staticmethod
    def is_wordpress_root(path):
        return os.path.isfile(os.path.join(path, WordpressProcessor.WP_VERSION_FILE))

    @staticmethod
    def get_file_checksum(path):
        checksum = md5()
        with open(path, "rb") as f:
            for line in f:
                checksum.update(line)

        return checksum.hexdigest()

    def get_wordpress_version(self):
        version = None
        path = os.path.join(self.wp_root, self.WP_VERSION_FILE)
        with open(path, mode='r') as f:
            for line in f:
                if '$wp_version = ' in line:
                    return line.split("'")[1]

    def __init__(self, project_root):
        self.wp_root = project_root
        version = self.get_wordpress_version()
        self.log.debug("Fetching checksums for Wordpress v" + version)

        try:
            self.checksums = requests.get(WordpressProcessor.WP_CHECKSUM_URL.format(version)).json()['checksums']
        except (requests.exceptions.ConnectionError, json.decoder.JSONDecodeError):
            self.log.error("Couldn't fetch Wordpress checksums, please ensure you have an "
                           "active internet connection. Continuing without hash verification.")

    def ready(self):
        return len(self.checksums) > 0

    def process(self, temp_path, real_path):
        result = Result()
        wp_path = real_path.replace(self.wp_root, '')

        if wp_path not in self.checksums:
            return result
        elif self.checksums[wp_path] != self.get_file_checksum(real_path):
            result.rules.append('Hash_Verification_Failure')
            result.score = self.HASH_SCORE_WEIGHTING
        else:
            result.rules.append('Hash_Verification_Success')
            result.score = -self.HASH_SCORE_WEIGHTING

        return result

    @staticmethod
    def get_processor_name():
        return 'Wordpress'
