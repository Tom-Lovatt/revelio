import math
import glob
import sys

def get_entropy(string):
    "Calculates the Shannon entropy of a string"

    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy


# i = 0

for path in glob.iglob(sys.argv[1], recursive=True):
    file = open(path, errors='replace')
    entropy = get_entropy(file.read())
    print(path + '\t' + str(entropy))
    file.close()
    # i += 1
    # if i > 500:
    #     break

