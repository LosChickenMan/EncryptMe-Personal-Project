import struct
import binascii

K = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298]

# fractional part of the cube root of the first 64 prime numbers 

INITIAL_HASH_VALUE = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225] #''' fractional parts of the square root of the first 8 prime numbers '''


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
    def _right_rotate_bits(self, x: int, n: int) -> int: #''' rotates by 32 bits '''
        return (x >> n | x << 32 - n) & 0xFFFFFFFF

    
#''' message schedule '''

    def _SHA_compress(self, chunk: bytes, currenthash: list) -> list:
        wcount = [0] * 64
        for t in range(16):
            wcount[t] = struct.unpack('>I', chunk[t * 4:t * 4 + 4])[0]
        for t in range(16, 64):
            sigma0 = self._right_rotate_bits(wcount[t - 15], 7) ^ self._right_rotate_bits(wcount[t - 15], 18) ^ wcount[t - 15] >> 3
            sigma1 = self._right_rotate_bits(wcount[t - 2], 17) ^ self._right_rotate_bits(wcount[t - 2], 19) ^ wcount[t - 2] >> 10
            wcount[t] = wcount[t - 16] + sigma0 + wcount[t - 7] + sigma1 & 4294967295
        a, b, c, d, e, f, g, h = currenthash
        for t in range(64):
            sigma1 = self._right_rotate_bits(e, 6) ^ self._right_rotate_bits(e, 11) ^ self._right_rotate_bits(e, 25)
            ch = e & f ^ ~e & g
            temp1 = h + sigma1 + ch + K[t] + wcount[t] & 0xFFFFFFFF
            sigma0 = self._right_rotate_bits(a, 2) ^ self._right_rotate_bits(a, 13) ^ self._right_rotate_bits(a, 22)
            maj = a & b ^ a & c ^ b & c
            temp2 = sigma0 + maj & 0xFFFFFFFF
            a, b, c, d, e, f, g, h = (
            (temp1 + temp2) & 0xFFFFFFFF,
            a, b, c,
            (d + temp1) & 0xFFFFFFFF,
               e, f, g
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

hasher = SHA256Hasher()

message  = b"abc"

result = hasher.compute_digest_bytes(message).hex()

expected = (
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad"
)

print("Result:  ", result)
print("Expected:", expected)

if result != expected:
    print("hash function failed")
else: 
    print("hash function passed")
