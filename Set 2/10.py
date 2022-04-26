# py

""" https://cryptopals.com/sets/2/challenges/10

Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the
next call to the cipher core. 

The first plaintext block, which has no associated previous ciphertext block, is
added to a "fake 0th ciphertext block" called the initialization vector, or IV. 

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it
encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
and using your XOR function from the previous exercise to combine them.

The file here (two.txt) is intelligible (somewhat) when CBC decrypted against
"YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00...)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the
point of even doing this stuff if you aren't going to learn from it?
"""

import base64
import codecs
import os
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

here = os.path.dirname(os.path.abspath(__file__))
_path = os.path.join(here, "data/10.txt")
text = ""
with open(_path, "r") as f:
    for line in f:
        l = line.rstrip()
        text += l

iv = b"\x00" * 16
ciphertext = base64.b64decode(text)
key = "YELLOW SUBMARINE"

bound = int(len(ciphertext) / 16)
blocked_ciphertext = [bytearray(ciphertext[16*i : 16*(i+1)]) for i in range(bound)]

plaintext = cbcDecrypt(blocked_ciphertext, iv, asciiToBytes(key), 0)
print("Plaintext: \n", plaintext.decode())

bound = int(len(plaintext) / 16)
blocked_plaintext = [bytearray(plaintext[16*i : 16*(i+1)]) for i in range(bound)]

new_ciphertext = b"".join(cbcEncrypt(blocked_plaintext, iv, asciiToBytes(key), 0, []))
print("Forming new ciphertext from calculated plaintext: \n", new_ciphertext)

if ciphertext == new_ciphertext:
    print("Validation passed; new ciphertext is equal to old.")
