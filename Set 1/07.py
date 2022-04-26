# py

""" https://cryptopals.com/sets/1/challenges/7

AES in ECB mode

The Base64-encoded content in this file (seven.txt) has been encrypted via AES-128 in ECB mode
under the key
"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because
it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB
working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
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
_path = os.path.join(here, "data/07.txt")
b64_text = ""
with open(_path, "r") as f:
    for line in f:
        l = line.rstrip()
        b64_text += l

ciphertext = base64.b64decode(b64_text)
key = "YELLOW SUBMARINE"

cipher = AES.new(asciiToBytes(key), AES.MODE_ECB)

plaintext = cipher.decrypt(ciphertext)

print(bytesToAscii(plaintext))