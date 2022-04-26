# py

""" https://cryptopals.com/sets/1/challenges/6

Break repeating-key XOR

It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding.
The other challenges in this set are there to bring you up to speed. This one is
there to qualify you. If you can do this one, you're probably just fine up to Set 6. 

There's a file here (six.txt). It's been base64'd after being encrypted with repeating-key XOR.
Decrypt it.

Here's how:

    1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

    2. Write a function to compute the edit distance/Hamming distance between two
       strings. The Hamming distance is just the number of differing bits. The distance between:

       this is a test

       and

       wokka wokka!!!

       is 37. Make sure your code agrees before you proceed.

    3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE
       worth of bytes, and find the edit distance between them. Normalize this result
       by dividing by KEYSIZE.

    4. The KEYSIZE with the smallest normalized edit distance is probably the key.
       You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE
       blocks instead of 2 and average the distances. 

    5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of
       KEYSIZE length. 

    6. Now transpose the blocks: make a block that is the first byte of every block, and
       a block that is the second byte of every block, and so on.

    7. Solve each block as if it was single-character XOR. You already have code to do this.

    8. For each block, the single-byte XOR key that produces the best looking histogram
       is the repeating-key XOR key byte for that block. Put them together and you have
       the key. 

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key
XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
But more people "know how" to break it than can actually break it, and a similar technique
breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We
promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!"
edit distance really is 37. 
"""

import codecs
import base64
import score
import os
import sys
import binascii

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
_path = os.path.join(here, "data/06.txt")
b64_text = ""
with open(_path, "r") as f:
    for line in f:
        l = line.rstrip()
        b64_text += l

text = base64.b64decode(b64_text)

best_ks = -1
best_hem = float('inf')
for ks in range(2, 41):
    total_hem = 0
    times = 0
    last_be = 0
    while True:
        try:
            a_s = last_be
            a_e = last_be + ks
            b_s = last_be + ks
            b_e = last_be + ks * 2
            last_be = b_e
            a = text[ a_s : a_e ]
            b = text[ b_s : b_e ]
            axb_by = xor(a, b)
            axb_h = axb_by.hex()
            axb_i = int(axb_h, 16)
            axb_bi = bin(axb_i)
            hem = axb_bi.count('1') / ks

            total_hem += hem
            times += 1

        except Exception as e:
            break
    total_hem /= times
    
    if total_hem < best_hem:
        best_hem = total_hem
        best_ks = ks

print("Best KEYSIZE: {}\nBest Hemming distance: {}".format(best_ks, best_hem))

blocked_text = [text[best_ks*i:best_ks*i+best_ks] for i in range(len(text) // best_ks + 1)]

transposed_blocks = [b""] * best_ks

for byte in range(best_ks):
    for block in blocked_text:
        try:
            transposed_blocks[byte] += bytes([block[byte]])
        except IndexError:
            pass

count = 0
best_asciis = []
for block in transposed_blocks:
    best_ascii, decoded = bruteForceXOR(block)
    best_asciis.append(best_ascii)
    count += 1

result = ""
for x in best_asciis:
    result += chr(x)
print("Key:", result)

result = bytesToAscii(xor(text, bytes(best_asciis)))
print("Text:\n=========================")
print(result + "\n")
