import glob
import os
import re
import sys
import yara
from pprint import pprint

all_files = {}
EXTERNAL_VARS_TEMPLATE = {
    'file_num_lines': 0,
    'file_longest_unbroken_string': 0
}


def populate_external_vars(path):
    ext_vars = dict(EXTERNAL_VARS_TEMPLATE)
    # This covers most encoded and compressed strings
    regex = re.compile('[^a-zA-Z0-9/+_]')
    with open(path, errors='ignore') as f:
        lus = 0
        for line in f.readlines():
            ext_vars['file_num_lines'] += 1
            lus = max(lus, len(max(regex.split(line), key=len)))
        ext_vars['file_longest_unbroken_string'] = lus
    return ext_vars


rules = yara.compile(filepaths={
    'php_statements': 'YaraRules/Index.yar'
}, externals=EXTERNAL_VARS_TEMPLATE)

MAX_MATCHES = -1
target = sys.argv[1]
if os.path.isdir(target):
    target = os.path.join(target, '**/*.php')


for path in glob.iglob(target, recursive=True):
    external_vars = populate_external_vars(path)
    all_files[path] = {'score': 0, 'patterns': []}
    # if len(matches) >= MAX_MATCHES > 0:
    #     break
    for match in rules.match(path, externals=external_vars):
        all_files[path]['patterns'].append(match.rule)
        if 'score' in match.meta:
            all_files[path]['score'] += match.meta['score']


fn, fp, tn, tp = {}, {}, {}, {}

for path, match_data in all_files.items():
    if match_data['score'] >= 10:
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
print("False negatives:")
pprint(fn)
print("False positives:")
pprint(fp)
# print("True negatives: ")
# pprint(tn)


rate_tp = (float(len(tp)) / (len(tp)+len(fn))) * 100 if len(tp) > 0 else 0
rate_tn = (float(len(tn)) / (len(tn)+len(fp))) * 100 if len(tn) > 0 else 0
rate_fp = (float(len(fp)) / (len(fp) + len(tn))) * 100 if len(fp) > 0 else 0
rate_fn = (float(len(fn)) / (len(fn) + len(tp))) * 100 if len(fn) > 0 else 0

print("True positive rate: " + str(round(rate_tp, 3)) + "%")
print("True negative rate: " + str(round(rate_tn, 3)) + "%")
print("False positive rate: " + str(round(rate_fp, 3)) + "%")
print("False negative rate: " + str(round(rate_fn, 3)) + "%")
