# py

""" https://cryptopals.com/sets/2/challenges/11

An ECB/CBC detection oracle

Now that you have ECB and CBC working: 

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that
generates a random key and encrypts under it.

The function should look like:
>>> encryption_oracle(your-input)
==> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the
plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other
half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a
piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells
you which one is happening.
"""

import base64
import codecs
import os
import random
import string
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# Takes a bytearray and pads it with "\x04" bytes *padding* times.
# Returns: bytearray
def padBA(ba, padding, pos):
    if pos == 'before':
        result = b'\x04' * padding
        result += bytearray(ba)
    elif pos == 'after':
        result = bytearray(ba)
        result += b'\x04' * padding
    
    return result

# Takes a str and turns it to a bytearray.
# Returns: bytearray
def asciiToBytes(_str):
    result = _str.encode('utf-8')
    return result

# Takes a bytearray and turns it to ascii.
# Returns: str
def bytesToAscii(ba):
    result = codecs.decode(ba, 'UTF-8')
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

# Takes blocked plaintext, an initialization vector, a key in bytes, and 0 and
# performs CBC decryption by hand by repeating ECB decryption.
# Returns: bytearray (plaintext)
def cbcDecrypt(text, iv, key, blockno):
    if blockno >= len(text):
        return b"\x00"
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(text[blockno])
    if blockno == 0:
        xored_res = xor(decrypted, iv)
    else:
        xored_res = xor(decrypted, text[blockno - 1])
    return xored_res + cbcDecrypt(text, iv, key, blockno + 1)

# Takes blocked plaintext, an initialization vector, a key in bytes, 0, and an empty
# array and performs CBC encryption by hand by repeating ECB encryption.
# Returns: array of bytearrays (ciphertext)
def cbcEncrypt(text, iv, key, blockno, ciphertext):
    if blockno >= len(text):
        return ciphertext
    if blockno == 0:
        xored_res = xor(text[blockno], iv)
    else:
        xored_res = xor(text[blockno], ciphertext[blockno - 1])
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(xored_res)
    ciphertext.append(encrypted)
    return cbcEncrypt(text, iv, key, blockno + 1, ciphertext)

# Generates a random key for AES encryption that's 16 bytes.
# Returns: bytearray
def getRandomAESKey():
    result = "".join([random.choice(string.ascii_letters) for i in range(16)])
    return asciiToBytes(result)

# Encrypts a bytearray under either ECB or CBC.
# Returns: bytearray
def encryptionOracle(ba):
    key = getRandomAESKey()                         # Random AES key
    ba = padBA(ba, random.randint(5, 10), 'before') # Random number of padding bytes before
    ba = padBA(ba, random.randint(5, 10), 'after')  # Random number of padding bytes after
    if len(ba) % len(key) != 0:                     # Irregularly-sized message; need to pad after
        ba = padBA(ba, 16 - (len(ba) % len(key)), 'after')
    mode = random.randint(1, 2)                     # 1 is ECB, 2 is CBC
    if mode == 1:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(ba)
    elif mode == 2:
        bound = int(len(ba) / 16)
        blocked_plaintext = [ bytearray(ba[16*i : 16*(i+1)]) for i in range(bound)]
        iv = b"\x00" * 16
        ciphertext = cbcEncrypt(blocked_plaintext, iv, key, 0, [])
    else:
        print("Invalid mode chosen in encryptionOracle()")
        exit()
    return ciphertext, mode


# Takes a str and turns it to a bytearray.
# Returns: bytearray
def asciiToBytes(_str):
    result = _str.encode('utf-8')
    return bytearray(result)

# Decodes a hex string
# Returns: bytearray
def hexToBytes(_str):
    result = bytearray.fromhex(_str)
    return result


inp = "X" * 64
inp_b = asciiToBytes(inp)

success = 0
failure = 0
trials = 10000

for x in range(trials):
    if (x+1) % 100 == 0: print("Trial {}".format(x+1))
    ciphertext, mode = encryptionOracle(inp_b)

    bound = int(len(ciphertext) / 16)   # Round up
    blocked_ciphertext = [ bytes(ciphertext[16*i : 16*(i+1)]) for i in range(bound)]
    total = len(blocked_ciphertext)
    set_total = len(set(blocked_ciphertext))
    if total != set_total:
        # ECB
        if mode == 1:
            success += 1
        else:
            failure += 1
    else:
        # CBC
        if mode == 2:
            success += 1
        else:
            failure += 1

print("\nTrials: {}\nSuccesses: {}\nFailures: {}".format(trials, success, failure))
