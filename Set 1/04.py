# py

""" https://cryptopals.com/sets/1/challenges/4

Detect single-character XOR

One of the 60-character strings in this file (four.txt) has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""

import codecs
import base64
import score
import os

# Decodes a hex string
# Returns: bytearray
def hexToBytes(_str):
    result = bytearray.fromhex(_str)
    return result

# Takes two bytearrays and XORs them.
# Returns: bytearray
def xor(ba1, ba2):
    result = bytearray(len(ba1))

    # This implementation allows for two different length bytearrays to be XORed,
    # with the second bytearray being shorter.
    ba2_limit = len(ba2)
    ba2_current = 0
    for byte in range(len(ba1)):
        result[byte] = ba1[byte] ^ ba2[ba2_current]
        ba2_current += 1
        if ba2_current == ba2_limit:
            ba2_current = 0

    return result

# Takes a bytearray and turns it to ascii.
# Returns: str
def bytesToAscii(ba):
    result = codecs.decode(ba, 'UTF-8')
    return result

# Brute forces single-byte XOR encryption.
# Passed bytearray is XORed against a single ASCII value and is scored.
# Highest score gets returned.
# Returns: int, str
def bruteForceXOR(ba):
    highest_score = 0
    highest_score_ascii = 0
    likely_str = ""
    for i in range(0, 126 + 1):
        result = xor(ba, chr(i).encode())
        result = bytesToAscii(result)
        current = score.score(result, 2)

        if current > highest_score:
            highest_score = current
            highest_score_ascii = i
            likely_str = result

    return (highest_score_ascii, likely_str)

here = os.path.dirname(os.path.abspath(__file__))
_path = os.path.join(here, "data/04.txt")

likely_str = ""
highest_score = 0
best_ascii = 0

with open(_path, "r") as f:
    count = 0
    for line in f:
        l = line.rstrip()
        try:
            ascii, decoded = bruteForceXOR(hexToBytes(l))
            scr = score.score(decoded, 2)
            #print("Line {}: {}".format(count, decoded))
            if scr > highest_score:
                highest_score = scr
                best_ascii = ascii
                likely_str = decoded
        except UnicodeDecodeError:
            pass
        count += 1

print("Best ASCII:", best_ascii)
print("Key:", chr(best_ascii))
print("Decoded string:", likely_str)