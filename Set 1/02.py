# py

""" https://cryptopals.com/sets/1/challenges/2

Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string: 
1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against: 
686974207468652062756c6c277320657965

... should produce: 
746865206b696420646f6e277420706c6179

"""

import base64

# Decodes a hex string
# Returns: bytearray
def hexToBytes(_str):
    result = bytearray.fromhex(_str)
    return result

# Encodes a bytearray to base64
# Returns: bytearray
def bytesToB64(ba):
    result = bytearray(base64.b64encode(ba))
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

inpa = "1c0111001f010100061a024b53535009181c"
inpb = "686974207468652062756c6c277320657965"

inpa_b = hexToBytes(inpa)
inpb_b = hexToBytes(inpb)

out_b = xor(inpa_b, inpb_b)

print(out_b)