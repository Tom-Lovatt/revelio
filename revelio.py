import glob
import os
import re
import sys
import yara
from pprint import pprint
from util.file_preprocessing import preprocess

EXTERNAL_VARS_TEMPLATE = {
    'file_num_lines': 0,
    'file_longest_unbroken_string': 0
}
all_files = {}

rules = yara.compile(filepaths={
    'php_statements': 'YaraRules/Index.yar'
}, externals=EXTERNAL_VARS_TEMPLATE)


def enumerate_files(root_dir):
    for file_path in glob.iglob(root_dir, recursive=True):
        all_files[file_path] = {'score': 0, 'patterns': [], 'strings': []}

        temp_path = preprocess(file_path)
        external_vars = populate_external_vars(temp_path)
        matches = rules.match(temp_path, externals=external_vars)

        for match in matches:
            parse_match(file_path, match)

        # os.unlink(temp_path)


def parse_match(file_path, match):
    all_files[file_path]['patterns'].append(match.rule)
    if 'score' in match.meta:
        all_files[file_path]['score'] += match.meta['score']
    # all_files[file_path]['strings'].append(match.strings)


def populate_external_vars(file_path):
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


def print_results():
    fn, fp, tn, tp = {}, {}, {}, {}
    for path, match_data in all_files.items():
        if match_data['score'] >= 5:
            if 'Malicious' in path or 'BAD' in path:
                tp[path] = match_data
            else:
                fp[path] = match_data
        else:
            if 'Malicious' in path or 'BAD' in path:
                fn[path] = match_data
            else:
                tn[path] = match_data

    # print("True positives:")
    # pprint(tp)
    if len(fn):
        print("False negatives:")
        pprint(fn)
    if len(fp):
        print("False positives:")
        pprint(fp)
    # print("True negatives: ")
    # pprint(tn)

    rate_tp = (float(len(tp)) / (len(tp) + len(fn))) * 100 if len(tp) > 0 else 0
    rate_fp = (float(len(fp)) / (len(fp) + len(tn))) * 100 if len(tn) > 0 else 0

    print("True positive rate: ({} tagged out of {}) {}%".format(len(tp), len(tp)+len(fn),round(rate_tp, 3)))
    print("False positive rate: ({} tagged out of {}) {}%".format(len(fp), len(fp) + len(tn), round(rate_fp, 3)))


for x in range(1, len(sys.argv)):
    target = sys.argv[x]
    if os.path.isdir(target):
        target = os.path.join(target, '**/*.php')
    elif not os.path.isfile(target):
        print(target + " + is not a valid file or directory. Skipping.")
        continue
    enumerate_files(target)


print_results()



