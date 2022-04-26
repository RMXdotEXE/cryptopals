# py

""" https://cryptopals.com/sets/1/challenges/5

Implement repeating-key XOR

Here is the opening stanza of an important work of the English language: 
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key;
the first byte of plaintext will be XOR'd against I, the next C, the next E,
then I again for the 4th byte, and so on.

It should come out to:
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272 \
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail.
Encrypt your password file. Your .sig file. Get a feel for it. I promise,
we aren't wasting your time with this. 
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
        print(result[byte])
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

inp = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

out = xor(asciiToBytes(inp), asciiToBytes("ICE"))
print(bytesToHex(out))