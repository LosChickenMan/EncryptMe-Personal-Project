# SHA-256 Hashing Algorithm — Implementation Explanation

## 1. Overview

This project contains a Python implementation of **SHA-256 (Secure Hash Algorithm 256-bit)**, a cryptographic hash function in the SHA-2 family.

SHA-256 accepts an input message and produces a fixed-size **256-bit (32-byte) digest**, commonly represented as 64 hexadecimal characters. The same input always produces the same digest, while a small change to the input should produce a substantially different result.

SHA-256 is a hash function, not an encryption algorithm. It does not use a secret key, does not conceal the input, and does not provide a decryption operation. Its design is specified in the NIST Secure Hash Standard, FIPS 180-4.

## 2. SHA-256 at a glance

| Property | Description |
|---|---|
| Algorithm family | SHA-2 |
| Digest size | 256 bits (32 bytes) |
| Hexadecimal output | 64 characters |
| Internal word size | 32 bits |
| Message block size | 512 bits (64 bytes) |
| Rounds per block | 64 |
| Working state | Eight 32-bit words |
| Key required | No |

The algorithm has three main stages:

1. **Pre-processing:** pad the message, append its original length, and divide it into 512-bit blocks.
2. **Compression:** expand each block into a message schedule and process it through 64 rounds of calculations.
3. **Digest generation:** combine the final eight 32-bit state words into the 256-bit digest.

## 3. Imports and constants

The supplied methods use Python's `struct` and `binascii` modules. They need to be imported:

```python
import struct
import binascii
```

### 3.1 Round constants — `K`

`K` contains 64 fixed 32-bit constants. One constant is used in each of the 64 compression rounds. These values are part of the SHA-256 specification; they are derived from the fractional parts of the cube roots of the first 64 prime numbers.

The expression `K[t]` selects the constant used by the current round, where `t` ranges from 0 to 63.

### 3.2 Initial hash values

```python
INITIAL_HASH_VALUE = [
    1779033703, 3144134277, 1013904242, 2773480762,
    1359893119, 2600822924, 528734635, 1541459225
]
```

SHA-256 begins with eight predefined 32-bit values. Together, these values form the initial hash state. They are fixed by the standard and are derived from the fractional parts of the square roots of the first eight prime numbers.

The implementation uses:

```python
currenthash = INITIAL_HASH_VALUE.copy()
```

Copying the list prevents a previous hash operation from modifying the initial values used by a later operation.

### 3.3 Batch-size constant

```python
FETCH_BATCH_ROWS = 2000
```

This constant is declared in the supplied code but is not used by the SHA-256 methods shown. It may be used elsewhere in the project for database or batch-processing work.

## 4. Object-oriented structure

### 4.1 Parent class — `EncryptMyData`

```python
class EncryptMyData:
    def __init__(self):
        self._plaindata = ''
        self._cipherdata = ''
        self._encryptionalg = ''
        self._processComplete = False
        self._timeOfExecution = ''
```

The parent class provides shared storage for data and process information:

| Attribute | Purpose |
|---|---|
| `_plaindata` | Stores the original input. |
| `_cipherdata` | Stores the operation's output. In this subclass it contains a hash digest, not ciphertext. |
| `_encryptionalg` | Stores an algorithm name if the application sets it. |
| `_processComplete` | Records whether processing has completed. |
| `_timeOfExecution` | Provides a place to store an execution timestamp. |

Its helper methods update these attributes:

- `_inputdata(data)` stores the original input.
- `_setTimeofExecution(timestamp)` stores a timestamp.
- `_setCompletion(status)` updates the completion flag.
- `setAlgor(algorithm)` stores the algorithm name.

### 4.2 SHA-256 subclass

```python
class SHA256Hasher(EncryptMyData):
```

`SHA256Hasher` inherits from `EncryptMyData`, reusing its data and process-tracking attributes while implementing SHA-256-specific operations.

Although the parent class is named `EncryptMyData`, hashing is not encryption. Likewise, `_cipherdata` is a general output-storage field here; its contents are a digest, not encrypted data.

## 5. 32-bit arithmetic and bit rotation

SHA-256 performs calculations on unsigned 32-bit words. Python integers can grow beyond 32 bits, so the implementation masks results with:

```python
4294967295  # 0xFFFFFFFF = 2**32 - 1
```

Applying `& 0xFFFFFFFF` keeps only the lowest 32 bits. This is equivalent to reducing an integer modulo \(2^{32}\), as required by SHA-256's word arithmetic.

### 5.1 Right rotation — `_right_rotate_bits`

```python
def _right_rotate_bits(self, x: int, n: int) -> int:
    return (x >> n | x << 32 - n) & 4294967295
```

This performs a 32-bit right rotation, also written `ROTR`. Bits that move off the right-hand end are brought back around at the left-hand end. This differs from a normal right shift, which discards those bits.

- `x >> n` shifts the word right.
- `x << (32 - n)` moves the wrapped bits to the left.
- `|` combines the two parts.
- `& 0xFFFFFFFF` restricts the result to 32 bits.

SHA-256 uses rotations of different sizes to mix bits throughout the message schedule and working state.

## 6. Compression function — `_SHA_compress`

```python
def _SHA_compress(self, chunk: bytes, currenthash: list) -> list:
```

This method performs the core SHA-256 calculation for one 512-bit message block. It transforms the current eight-word hash state using the block's contents and returns the updated state.

The method has two main stages: expanding the block into 64 words, and performing 64 rounds of state calculations.

### 6.1 Converting the block into 16 words

```python
wcount = [0] * 64
for t in range(16):
    wcount[t] = struct.unpack('>I', chunk[t * 4:t * 4 + 4])[0]
```

Each 512-bit block contains 64 bytes. The first 16 entries of `wcount` are populated by reading four bytes at a time and interpreting each group as an unsigned 32-bit integer.

- `>` specifies big-endian byte order (most significant byte first).
- `I` specifies an unsigned 32-bit integer.
- `[0]` extracts the integer from the tuple returned by `struct.unpack`.

SHA-256 specifies big-endian interpretation for these message words.

### 6.2 Expanding the message schedule

```python
for t in range(16, 64):
    sigma0 = (
        self._right_rotate_bits(wcount[t - 15], 7)
        ^ self._right_rotate_bits(wcount[t - 15], 18)
        ^ wcount[t - 15] >> 3
    )
    sigma1 = (
        self._right_rotate_bits(wcount[t - 2], 17)
        ^ self._right_rotate_bits(wcount[t - 2], 19)
        ^ wcount[t - 2] >> 10
    )
    wcount[t] = (
        wcount[t - 16] + sigma0 + wcount[t - 7] + sigma1
    ) & 4294967295
```

The first 16 words come directly from the message block. The remaining 48 are calculated from earlier words using two small sigma functions:

\[
\sigma_0(x)=ROTR^7(x)\oplus ROTR^{18}(x)\oplus SHR^3(x)
\]

\[
\sigma_1(x)=ROTR^{17}(x)\oplus ROTR^{19}(x)\oplus SHR^{10}(x)
\]

`ROTR` means rotate right, `SHR` means logical shift right, and `⊕` means bitwise exclusive OR (XOR).

The new word is:

\[
W_t=W_{t-16}+\sigma_0(W_{t-15})+W_{t-7}+\sigma_1(W_{t-2})\pmod{2^{32}}
\]

Expanding the original 16 words into 64 schedule words spreads information from the complete message block across all 64 rounds.

### 6.3 Initialising the working variables

```python
a, b, c, d, e, f, g, h = currenthash
```

The eight current hash values are copied into temporary working variables. These variables change during the rounds, while `currenthash` retains the state that will be combined with the result after all rounds have finished.

### 6.4 The 64 compression rounds

```python
for t in range(64):
```

Each round uses the eight working variables, the current schedule word `wcount[t]`, and the round constant `K[t]`.

#### Large sigma function 1

```python
sigma1 = (
    self._right_rotate_bits(e, 6)
    ^ self._right_rotate_bits(e, 11)
    ^ self._right_rotate_bits(e, 25)
)
```

This implements:

\[
\Sigma_1(e)=ROTR^6(e)\oplus ROTR^{11}(e)\oplus ROTR^{25}(e)
\]

#### Choice function

```python
ch = e & f ^ ~e & g
```

This implements:

\[
Ch(e,f,g)=(e\land f)\oplus(\neg e\land g)
\]

For each bit position, the function selects the corresponding bit from `f` when the bit in `e` is 1, or from `g` when the bit in `e` is 0.

Python's `~` operator works on arbitrary-precision signed integers. In this expression, the result is ANDed with the 32-bit value `g`, so only the relevant low 32 bits contribute.

#### Temporary value 1

```python
temp1 = (h + sigma1 + ch + K[t] + wcount[t]) & 4294967295
```

This calculates:

\[
T_1=h+\Sigma_1(e)+Ch(e,f,g)+K_t+W_t\pmod{2^{32}}
\]

It combines the current state, the round constant, and the current expanded message word.

#### Large sigma function 0

```python
sigma0 = (
    self._right_rotate_bits(a, 2)
    ^ self._right_rotate_bits(a, 13)
    ^ self._right_rotate_bits(a, 22)
)
```

This implements:

\[
\Sigma_0(a)=ROTR^2(a)\oplus ROTR^{13}(a)\oplus ROTR^{22}(a)
\]

#### Majority function

```python
maj = a & b ^ a & c ^ b & c
```

This implements:

\[
Maj(a,b,c)=(a\land b)\oplus(a\land c)\oplus(b\land c)
\]

For each bit position, the result is 1 when at least two of the three input bits are 1. This is the majority function.

#### Temporary value 2

```python
temp2 = (sigma0 + maj) & 4294967295
```

This calculates:

\[
T_2=\Sigma_0(a)+Maj(a,b,c)\pmod{2^{32}}
\]

`T1` and `T2` are then used to update all eight working variables.

### 6.5 Updating the working variables — important source-code issue

The supplied snippet contains this fragment:

```python
result = []g, f, e, d + temp1 & 4294967295, c, b, a, temp1 + temp2 & 4294967295
```

As pasted, this is **not valid Python syntax** and does not show a valid assignment to the eight working variables. The `result = []` text also appears misplaced. Check the original source before relying on this part of the implementation.

The standard SHA-256 update consistent with the calculations above is:

```python
a, b, c, d, e, f, g, h = (
    (temp1 + temp2) & 0xFFFFFFFF,
    a,
    b,
    c,
    (d + temp1) & 0xFFFFFFFF,
    e,
    f,
    g
)
```

Conceptually, the update is:

\[
\begin{aligned}
a' &= T_1+T_2 \pmod{2^{32}}\\
b' &= a\\
c' &= b\\
d' &= c\\
e' &= d+T_1 \pmod{2^{32}}\\
f' &= e\\
g' &= f\\
h' &= g
\end{aligned}
\]

This update is performed once in each of the 64 rounds.

### 6.6 Adding the result back into the hash state

After all 64 rounds, each working variable is added to its corresponding original state word:

```python
currenthash[0] = currenthash[0] + a & 4294967295
currenthash[1] = currenthash[1] + b & 4294967295
currenthash[2] = currenthash[2] + c & 4294967295
currenthash[3] = currenthash[3] + d & 4294967295
currenthash[4] = currenthash[4] + e & 4294967295
currenthash[5] = currenthash[5] + f & 4294967295
currenthash[6] = currenthash[6] + g & 4294967295
currenthash[7] = currenthash[7] + h & 4294967295
```

Each addition is modulo \(2^{32}\). The updated state is returned and becomes the starting state for the next message block.

## 7. Padding and digest generation — `compute_digest_bytes`

```python
def compute_digest_bytes(self, data: bytes) -> bytes:
```

This method prepares the input, processes every 512-bit block, and returns the raw 32-byte digest.

### 7.1 Record the original message length

```python
plaintext = data
length_of_plaintext = len(plaintext) * 8
```

`len(plaintext)` gives the input size in bytes. Multiplying by eight converts the size into bits. The original length, before padding, is stored in the final 64 bits of the padded message.

### 7.2 Append the first padding bit

```python
plaintext += b'\x80'
```

`0x80` is binary `10000000`. Appending this byte adds the required `1` bit followed by seven zero bits, marking the start of the padding.

### 7.3 Pad to the required block position

```python
while (len(plaintext) + 8) % 64 != 0:
    plaintext += b'\x00'
```

Zero bytes are appended until the message is eight bytes short of a multiple of 64 bytes. The remaining eight bytes are reserved for the original 64-bit message length.

Once the length field is appended, the padded message can be divided into complete 64-byte (512-bit) blocks.

### 7.4 Append the original bit length

```python
plaintext += struct.pack('>Q', length_of_plaintext)
```

This stores the original message length as an unsigned 64-bit big-endian integer. `>` selects big-endian order and `Q` selects an unsigned 64-bit integer.

### 7.5 Process the message blocks

```python
currenthash = INITIAL_HASH_VALUE.copy()
for i in range(0, len(plaintext), 64):
    chunk = plaintext[i:i + 64]
    currenthash = self._SHA_compress(chunk, currenthash.copy())
```

The padded message is processed in 64-byte slices. Each block is passed to `_SHA_compress`, and its returned state is used when processing the next block. This chaining means that every block contributes to the final digest.

### 7.6 Return the raw digest

```python
return b''.join((struct.pack('>I', h) for h in currenthash))
```

Each of the eight final state words is converted into four big-endian bytes. Joining the eight values produces:

\[
8\text{ words}\times4\text{ bytes}=32\text{ bytes}
\]

This is the raw 256-bit digest.

## 8. Public hashing methods

### 8.1 `hash_bytes`

```python
def hash_bytes(self, data: bytes) -> str:
    digest = self.compute_digest_bytes(data)
    self._cipherdata = binascii.hexlify(digest).decode()
    self._setCompletion(True)
    return self._cipherdata
```

This method accepts bytes and returns the digest as a hexadecimal string:

1. `compute_digest_bytes` calculates the raw 32-byte digest.
2. `binascii.hexlify` converts the digest into hexadecimal bytes.
3. `.decode()` converts those bytes into a normal Python string.
4. `_setCompletion(True)` marks the operation as complete.
5. The 64-character hexadecimal digest is returned.

The digest is stored in the inherited `_cipherdata` attribute. This is a storage convention, not ciphertext.

### 8.2 `hash`

```python
def hash(self, data: str) -> str:
    self._inputdata(data)
    return self.hash_bytes(data.encode('utf-8'))
```

This is the convenient interface for ordinary Python strings. It stores the original string in `_plaindata`, encodes the text as UTF-8 bytes, and passes those bytes to `hash_bytes`.

The byte-oriented method is also useful for files and other binary data that are not naturally represented as text.

## 9. End-to-end execution flow

```text
Input string
    |
    v
hash(data)
    |-- Store original input using _inputdata()
    |-- Encode the string as UTF-8 bytes
    v
hash_bytes(data)
    v
compute_digest_bytes(data)
    |-- Calculate original message length in bits
    |-- Append the 1-bit marker (0x80)
    |-- Append zero padding
    |-- Append original 64-bit message length
    |-- Split padded data into 64-byte blocks
    v
_SHA_compress(block, currenthash)
    |-- Parse block into 16 big-endian words
    |-- Expand the schedule to 64 words
    |-- Initialise working variables a-h
    |-- Perform 64 SHA-256 rounds
    |-- Add working variables to the hash state
    v
Final eight 32-bit hash words
    v
32-byte digest
    v
Convert digest to hexadecimal
    v
64-character SHA-256 hash
```

## 10. Important mathematical operations

| Operation | Purpose |
|---|---|
| `ROTR` | Rotates a 32-bit word to the right. |
| `SHR` | Shifts bits right and fills new left-hand positions with zeroes. |
| `XOR` (`^`) | Combines bits using exclusive OR. |
| `AND` (`&`) | Performs a bitwise AND. |
| `Ch(x, y, z)` | Selects bits from `y` or `z` based on `x`. |
| `Maj(x, y, z)` | Produces the majority bit from three inputs. |
| `Σ0`, `Σ1` | Large sigma functions used in compression rounds. |
| `σ0`, `σ1` | Small sigma functions used to expand the message schedule. |
| `& 0xFFFFFFFF` | Keeps arithmetic results within 32 bits. |

## 11. Implementation considerations and limitations

### 11.1 The compression update needs checking

The state-update fragment in the supplied snippet is syntactically invalid as pasted. It must be checked and corrected before the implementation can run. The replacement in section 6.5 follows the standard SHA-256 round update.

### 11.2 Required imports

The implementation uses `struct` and `binascii`. Both modules must be imported, or Python will raise a `NameError` when those names are used.

### 11.3 Input length

The implementation stores the message length in an unsigned 64-bit field. SHA-256's message length must fit in that field. Python's `struct.pack('>Q', ...)` raises an error if the supplied value is outside the unsigned 64-bit range.

### 11.4 Memory use

`compute_digest_bytes` constructs the padded message in memory before processing it. This is straightforward for coursework and ordinary inputs, but large files could require substantial memory. A streaming implementation could process blocks incrementally without holding the entire padded message at once.

### 11.5 Parent-class tracking

In the methods shown:

- `hash()` stores the original text using `_inputdata()`.
- `hash_bytes()` stores the hexadecimal digest in `_cipherdata` and sets `_processComplete` to `True`.
- `_timeOfExecution` is not populated.
- `_encryptionalg` is not populated.

The surrounding application could set those metadata fields where required.

### 11.6 Hashing is not encryption

A SHA-256 digest cannot be decrypted to recover the original input. SHA-256 provides a fixed-length digest, not confidentiality.

For password storage, a fast general-purpose hash such as SHA-256 should not be used on its own. Use a password-hashing algorithm designed to resist guessing attacks, such as Argon2id, scrypt or bcrypt, with an appropriate salt and configuration.

For message authentication, use HMAC-SHA-256 rather than treating a plain hash as proof that a message came from a trusted sender. For production systems, a well-tested cryptographic library is preferable to a custom implementation. A custom implementation should be tested against multiple known test vectors.

## 12. Testing against a known SHA-256 value

A useful initial test is the known SHA-256 digest for the ASCII text `abc`:

```python
hasher = SHA256Hasher()
print(hasher.hash("abc"))
```

Expected output (shown on two lines for readability):

```text
ba7816bf8f01cfea414140de5dae2223
b00361a396177a9cb410ff61f20015ad
```

The actual return value is one continuous 64-character string:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Also test an empty byte string (`b""`), a message exactly one block long, messages immediately below and above a 64-byte boundary, a multi-block message, and non-ASCII text encoded as UTF-8. One matching test vector is useful, but multiple vectors are needed to check padding, block handling and compression behaviour.

## 13. References

- **NIST FIPS 180-4 — Secure Hash Standard (SHS):** https://csrc.nist.gov/pubs/fips/180-4/upd1/final
- **NIST — Secure Hash Standard publication page:** https://www.nist.gov/publications/secure-hash-standard

FIPS 180-4 defines the SHA-256 initial values, round constants, logical functions, message schedule, padding requirements and compression process described in this document.

## 14. Summary

The `SHA256Hasher` class implements the main stages of SHA-256 in Python. It converts the input into bytes, applies the SHA-256 padding scheme, divides the result into 512-bit blocks, expands each block into a 64-word message schedule, and performs 64 rounds of compression using 32-bit arithmetic and bitwise functions.

After all blocks have been processed, the eight final 32-bit state words are combined into a 32-byte digest and returned as a 64-character hexadecimal string. The implementation demonstrates bitwise manipulation, modular arithmetic, message padding, big-endian data representation, iterative compression and object-oriented code reuse.
