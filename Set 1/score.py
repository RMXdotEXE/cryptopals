#string_data = "RKWESJGFUYNHSIEDUCVNJH"

import os

def score(string_data, gram_order):
    class Gram:
        MONO = 1
        BI = 2
        TRI = 3
        QUAD = 4
        QUINT = 5

    order_to_file = {
        1: "english_monograms.txt",
        2: "english_bigrams.txt",
        3: "english_trigrams.txt",
        4: "english_quadgrams.txt",
        5: "english_quintgrams.txt"
    }

    score = 0
    despaced = string_data.replace(" ", "")
    despaced = despaced.upper()

    for order in range(1, gram_order + 1):
        here = os.path.dirname(os.path.abspath(__file__))
        _path = os.path.join(here, "data/" + order_to_file[order])
        with open(_path, "r") as f:
            total = 0
            data = {}
            for line in f:
                x = line.split()
                total += int(x[1])
                data[x[0]] = x[1]
            grams = [despaced[i:i+order] for i in range(0, len(despaced))]
            for gram in grams:
                try:
                    score += int(data[gram])
                except KeyError:
                    score -= int(list(data.values())[0])

    return score