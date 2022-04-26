# py

""" https://cryptopals.com/sets/1/challenges/8

Detect AES in ECB mode

In this file (eight.txt) are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext. 
"""

import codecs
import base64
import score
import os
import sys
import binascii
from Cryptodome.Cipher import AES

# Decodes a hex string
# Returns: bytearray
def hexToBytes(_str):
    result = bytearray.fromhex(_str)
    return result

# Encoded a bytearray
# Returns: str (hex)
def bytesToHex(ba):
    result = ba.hex()
    return result

# Takes two bytearrays and XORs them.
# Returns: bytearray
def xor(ba1, ba2):
    result = bytearray(len(ba1))

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

# Takes a str and turns it to a bytearray.
# Returns: bytearray
def asciiToBytes(_str):
    result = _str.encode('utf-8')
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
_path = os.path.join(here, "data/08.txt")
ciphertexts = []
with open(_path, "r") as f:
    for line in f:
        l = line.rstrip()
        ciphertexts.append(l)

blocked_ciphertexts = []
for line in ciphertexts:
    bound = int(len(line) / 16)
    blocked_line = [ line[16*i : 16*(i+1)] for i in range(bound)]
    blocked_ciphertexts.append(blocked_line)

for line_no in range(len(blocked_ciphertexts)):
    if len(blocked_ciphertexts[line_no]) != len(set(blocked_ciphertexts[line_no])):
        print("HIT ON LINE", line_no)
        print("Line {} ciphertext: {}".format(line_no, ciphertexts[line_no]))
