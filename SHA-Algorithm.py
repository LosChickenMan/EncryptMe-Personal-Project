import struct
import binascii

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

#fractional part of the cube root of the first 64 prime numbers 

INITIAL_HASH_VALUE = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]
# fractional parts of the square root of the first 8 prime numbers

# bit = a binary digit having a value of 1 or 0

# byte = a group of 8 bits

# word = a group of 32 bits (4 bytes) or 64 bits dependent on the hash algorithm

# a,b,c....h = working variables that are the w-bit-words used in the computation of the hash values

# H(i) = the ith hash value. H(0) is the initial hash value; H(N) is the final hash value and is used 
# to determine the message digest

# H(j) = The jth word of the ith hash value
# where H i0 is the left-most word of hash value i.

# K(t) = Constant value to be used for iteration t of the hash computation. 

# k =  Number of zeroes appended to a message during the padding step

# l = Length of the message, M, in bits. 

# m = Number of bits in a message block, M(i). 

#M =  Message to be hashed.

# M(i) = Message block i, with a size of m bits.

# M(i) = The jth word of the ith message block, where M(i) is the left-most word ofmessage block i.

# n = Number of bits to be rotated or shifted when a word is operated upon.

#N = Number of blocks in the padded message.

#T  = Temporary w-bit word used in the hash computation.

#w = Number of bits in a word.

#Wt = The tth w-bit word of the message schedule.

# << = Left-shift operation, where x << n is obtained by discarding the left-most n
#bits of the word x and then padding the result with n zeroes on the right.

# >> = Right-shift operation, where x >> n is obtained by discarding the rightmost n bits of the word x and then padding the result with n zeroes on the
#left. 
 
class EncryptMyData:
    def __init__(self):
        self._plaindata = ''
        self._cipherdata = ''
        self._encryptionalg = ''
        self._processComplete = False
        self._timeOfExecution = ''

    def _inputdata(self, data: str):
        self._plaindata = data

    def _setTimeofExecution(self, timestamp: str):
        self._timeOfExecution = timestamp

    def _setCompletion(self, status: bool):
        self._processComplete = status

    def setAlgor(self, algorithm: str):
        self._encryptionalg = algorithm


class SHA256Hasher(EncryptMyData):
    def _right_rotate_bits(self, x: int, n: int) -> int: ''' rotates by 32 bits '''
        return (x >> n | x << 32 - n) & 0xFFFFFFFF

    
# message schedule 

    def _SHA_compress(self, chunk: bytes, currenthash: list) -> list:
        wcount = [0] * 64
        for t in range(16):
            wcount[t] = struct.unpack('>I', chunk[t * 4:t * 4 + 4])[0]
        for t in range(16, 64):
            sigma0 = self._right_rotate_bits(wcount[t - 15], 7) ^ self._right_rotate_bits(wcount[t - 15], 18) ^ wcount[t - 15] >> 3
            sigma1 = self._right_rotate_bits(wcount[t - 2], 17) ^ self._right_rotate_bits(wcount[t - 2], 19) ^ wcount[t - 2] >> 10
            wcount[t] = wcount[t - 16] + sigma0 + wcount[t - 7] + sigma1 & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = currenthash
        for t in range(64):
            sigma1 = self._right_rotate_bits(e, 6) ^ self._right_rotate_bits(e, 11) ^ self._right_rotate_bits(e, 25)
            ch = e & f ^ ~e & g
            temp1 = h + sigma1 + ch + K[t] + wcount[t] & 0xFFFFFFFF
            sigma0 = self._right_rotate_bits(a, 2) ^ self._right_rotate_bits(a, 13) ^ self._right_rotate_bits(a, 22)
            maj = a & b ^ a & c ^ b & c
            temp2 = sigma0 + maj & 0xFFFFFFFF
            a,b,c,d,e,f,g,h = (
                (temp1+temp2) & 0xFFFFFFFF,
                a,b,c
                (d+temp1) & 0xFFFFFFFF,
                e,f,g
            )
        currenthash[0] = currenthash[0] + a & 0xFFFFFFFF
        currenthash[1] = currenthash[1] + b & 0xFFFFFFFF
        currenthash[2] = currenthash[2] + c & 0xFFFFFFFF
        currenthash[3] = currenthash[3] + d & 0xFFFFFFFF
        currenthash[4] = currenthash[4] + e & 0xFFFFFFFF
        currenthash[5] = currenthash[5] + f & 0xFFFFFFFF
        currenthash[6] = currenthash[6] + g & 0xFFFFFFFF
        currenthash[7] = currenthash[7] + h & 0xFFFFFFFF
        return currenthash

    def compute_digest_bytes(self, data: bytes) -> bytes:
        plaintext = data
        length_of_plaintext = len(plaintext) * 8
        plaintext += b'\x80'
        while (len(plaintext) + 8) % 64 != 0:
            plaintext += b'\x00'
        plaintext += struct.pack('>Q', length_of_plaintext)
        currenthash = INITIAL_HASH_VALUE.copy()
        for i in range(0, len(plaintext), 64):
            chunk = plaintext[i:i + 64]
            currenthash = self._SHA_compress(chunk, currenthash.copy())
        return b''.join((struct.pack('>I', h) for h in currenthash))

    def hash_bytes(self, data: bytes) -> str:
        digest = self.compute_digest_bytes(data)
        self._cipherdata = binascii.hexlify(digest).decode()
        self._setCompletion(True)
        return self._cipherdata

    def hash(self, data: str) -> str:
        self._inputdata(data)
        return self.hash_bytes(data.encode('utf-8'))
