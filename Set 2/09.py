# py

""" https://cryptopals.com/sets/2/challenges/9

Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,
"YELLOW SUBMARINE"

... padded to 20 bytes would be: 

"YELLOW SUBMARINE\x04\x04\x04\x04"
"""

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

inp = "YELLOW SUBMARINE"
inp_b = asciiToBytes(inp)
print("len(inp_b):", len(inp_b))

out_b = padBA(inp_b, 4)
print("out_b:", out_b)
print("len(out_b):", len(out_b))