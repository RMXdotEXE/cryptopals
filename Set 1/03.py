# py

""" https://cryptopals.com/sets/1/challenges/3

Single-byte XOR cipher

The hex encoded string:
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message. 

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency
is a good metric. Evaluate each output and choose the one with the best score. 

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter. 
"""

import base64
import score
import codecs

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

inp = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

best_ascii, decoded = bruteForceXOR(hexToBytes(inp))

print("Best ASCII:", best_ascii)
print("Key:", chr(best_ascii))
print("Decoded string:", decoded)