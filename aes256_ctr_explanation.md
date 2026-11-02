# AES-256-CTR: Algorithm and Implementation Explanation

## 1. Overview

This implementation recreates the core AES-256 block-encryption
operations in Python and uses Counter (CTR) mode to encrypt data of
arbitrary length.

AES is specified by **NIST FIPS 197**. CTR mode is specified in **NIST
SP 800-38A**.

The implementation has two distinct parts:

1.  **AES-256 block cipher** -- transforms a 128-bit block using a
    256-bit secret key.
2.  **CTR mode** -- creates a keystream by encrypting successive counter
    blocks, then combines that keystream with the plaintext using XOR.

AES-256 uses: - A 256-bit (32-byte) encryption key. - A 128-bit
(16-byte) internal state/block. - 14 encryption rounds. - 15 round keys:
one initial key plus one for each round.

CTR mode allows data longer than 16 bytes to be processed without
padding.

> **Terminology:** AES is a cryptographic standard published by NIST,
> not an "AES framework". FIPS 197 specifies AES itself; SP 800-38A
> specifies CTR mode.

## 2. Important constants

### `S_BOX` -- Substitution Box

`S_BOX` is a lookup table containing 256 byte values, from 0 to 255. It
is used to replace each byte with another byte during the AES `SubBytes`
transformation and during key expansion.

For example, the first entries include:

``` python
S_BOX[0] == 99
S_BOX[1] == 124
S_BOX[2] == 119
```

The AES S-Box is constructed mathematically. Each non-zero byte is
mapped to its multiplicative inverse in the finite field GF(2\^8), and
an affine transformation is then applied. Zero is handled separately.

The S-Box introduces **non-linearity**. This makes the relationship
between input and output more complex and helps AES resist forms of
cryptanalysis that exploit simple linear relationships.

### `RoundConst` -- Round constants

`RoundConst` contains the constants used during AES key expansion. The
values are XORed into selected words so that the expanded key schedule
does not consist of simple repetitions or rearrangements of the original
key.

The constants in this implementation are stored as 32-bit values, with
the relevant byte in the most significant position. For example:

       Decimal    Hexadecimal
  ------------ --------------
      16777216   `0x01000000`
      33554432   `0x02000000`
      67108864   `0x04000000`
     134217728   `0x08000000`
     268435456   `0x10000000`
     536870912   `0x20000000`
    1073741824   `0x40000000`
    2147483648   `0x80000000`
     452984832   `0x1B000000`
     905969664   `0x36000000`

The values are derived using finite-field arithmetic. In the code, the
relevant constant is selected with `RoundConst[i // Nk]`.

### `Nb`, `Nk` and `Nr`

``` python
Nb, Nk, Nr = 4, 8, 14
```

  Constant     Value Meaning
  ---------- ------- --------------------------------------------
  `Nb`             4 Number of 32-bit columns in the AES state.
  `Nk`             8 Number of 32-bit words in the AES-256 key.
  `Nr`            14 Number of AES-256 encryption rounds.

Each word contains four bytes (32 bits). The 256-bit key therefore
contains eight words. The key expansion creates 60 words, which are
grouped into 15 round keys of 16 bytes each.

## 3. Object-oriented structure

### `EncryptMyData`

`EncryptMyData` is the parent class. It establishes attributes that can
be shared by different encryption implementations.

  Attribute            Intended purpose
  -------------------- ------------------------------------------------
  `_plaindata`         Stores the original plaintext.
  `_cipherdata`        Intended to store the encrypted result.
  `_encryptionalg`     Stores the algorithm name.
  `_processComplete`   Tracks whether processing has completed.
  `_timeOfExecution`   Stores a timestamp associated with processing.

The leading underscore indicates that these attributes are intended for
internal use.

### Parent-class methods

-   `__init__(self)` initialises the attributes with default values.
-   `_inputdata(self, data)` stores the supplied plaintext.
-   `_setTimeofExecution(self, timestamp)` stores a timestamp.
-   `_setCompletion(self, status)` updates the completion flag.
-   `setAlgor(self, algorithm)` records the algorithm name.

The AES class inherits from the parent:

``` python
class AES256CTR(EncryptMyData):
```

This allows the AES implementation to reuse the shared attributes and
methods. This demonstrates **inheritance**. The class structure provides
a basis for adding other algorithms that share the same parent
interface. Strictly speaking, inheritance alone does not demonstrate
polymorphism; polymorphism would be shown if multiple subclasses
implemented the same method, such as `encrypt()`, in different ways.

## 4. Initialising AES-256-CTR

### `AES256CTR.__init__(self, key)`

``` python
def __init__(self, key):
    super().__init__()
    self.key = key if isinstance(key, bytes) else bytes.fromhex(key)
    self.round_keys = self.aes256_key_expansion(self.key)
    self.setAlgor('AES-256-CTR')
```

This constructor:

1.  Calls `super().__init__()` to initialise the inherited attributes.
2.  Accepts the key as bytes or converts a hexadecimal string into
    bytes.
3.  Expands the original key into the AES round-key schedule.
4.  Records the algorithm name as `AES-256-CTR`.

AES-256 requires a key of exactly 32 bytes. The supplied code converts
the key but does not explicitly check its length, so a length check
should be added.

## 5. Byte and word conversion functions

AES operates on bytes and 32-bit words, while its internal
transformations use a 4 × 4 state matrix. These functions convert
between those representations.

### `xor_bytes(self, a, b)`

Performs a byte-by-byte XOR operation and returns the result as `bytes`.

XOR has the useful property:

``` text
A XOR B = C
C XOR B = A
```

This makes it suitable for combining plaintext with a CTR keystream and
recovering plaintext during decryption. The function also expects the
two inputs to have compatible lengths; in this implementation the caller
slices the keystream to match the data block.

### `bytes_to_state(self, b)`

Converts a 16-byte block into a 4 × 4 AES state matrix:

``` python
state[r][c] = b[4 * c + r]
```

AES fills the state **column by column**. This ordering is important:
using row-major ordering would produce an incorrect AES state and
incorrect ciphertext.

### `state_to_bytes(self, state)`

Performs the reverse operation. It reads the state column by column and
returns a 16-byte sequence. This is used to convert the encrypted state
back into a byte block for CTR mode.

### `rotate_word(self, word)`

Rotates a 32-bit word left by eight bits (one byte). A byte that moves
off the left side wraps around to the right side.

This is used during key expansion to rearrange the bytes before S-Box
substitution.

### `sub_word(self, word)`

Extracts the four bytes of a 32-bit word, substitutes each byte through
the AES S-Box, and recombines them into a 32-bit word.

It introduces non-linearity into the key expansion process.

### `bytes_to_word(self, b)`

Combines four bytes into one 32-bit integer using big-endian ordering.
Key expansion operates on 32-bit words, so this converts the original
key into the required representation.

### `word_to_bytes(self, w)`

Reverses `bytes_to_word()`: it extracts the four bytes from a 32-bit
word in big-endian order. The result is used to assemble round keys.

## 6. AES-256 key expansion

### `aes256_key_expansion(self, key_bytes)`

AES-256 does not use the original key unchanged for every round. It
expands the 32-byte key into 60 32-bit words.

The function first allocates space:

``` python
words = [0] * (Nb * (Nr + 1))
```

Since `Nb = 4` and `Nr = 14`, this creates 60 words.

The first eight words are populated from the original 256-bit key:

``` python
for i in range(Nk):
    words[i] = self.bytes_to_word(key_bytes[4 * i:4 * i + 4])
```

The remaining words are generated from earlier words. For each new word,
the previous word is copied into `temp`. Depending on the word index:

-   If `i % Nk == 0`, the algorithm rotates the word, applies S-Box
    substitution, and XORs it with the appropriate round constant.
-   If `i % Nk == 4`, the algorithm applies S-Box substitution without
    rotation or a round constant. This is an additional step specific to
    the AES-256 key schedule.
-   Otherwise, no extra transformation is applied to `temp`.

The new word is then calculated as:

``` python
words[i] = words[i - Nk] ^ temp
```

This process continues until all 60 words have been generated.

### `words_to_round_keys(self, words)`

Groups the 60 expanded words into 15 round keys. Each round key contains
four words, or 16 bytes.

The function converts each word back into bytes using `word_to_bytes()`
and combines the four words into one round-key byte string.

The resulting keys are used by the AES encryption rounds.

## 7. AES state transformations

AES uses four main transformations during its encryption rounds. They
operate on the 4 × 4 state matrix.

### `add_round_key(self, matrice_a, matrice_b)`

XORs every byte of the current state with the byte in the same position
in the round key.

This is the point at which the secret-derived round key is combined with
the state. The `& 255` operation ensures that the result remains within
the range of one byte.

### `substitute_bytes(self, state)`

Replaces every state byte with its corresponding value from `S_BOX`.

This is the `SubBytes` transformation. It introduces non-linearity into
the AES state.

### `shift_rows(self, state)`

Cyclically shifts each row of the state to the left:

  Row         Shift
  ------- ---------
  Row 0     0 bytes
  Row 1      1 byte
  Row 2     2 bytes
  Row 3     3 bytes

This rearranges bytes across columns. In combination with `MixColumns`,
it helps spread the influence of input bytes throughout the state.

### `gf_multiply(self, a, b)`

Performs multiplication in the finite field GF(2\^8), rather than
ordinary integer multiplication.

AES represents bytes as polynomials with binary coefficients. Addition
in this field is implemented using XOR. Multiplication is polynomial
multiplication followed by reduction using the irreducible polynomial:

``` text
x^8 + x^4 + x^3 + x + 1
```

This polynomial is represented by `0x11B`. When the high bit is shifted
out, the implementation XORs with `0x1B` (decimal 27), which is the
low-byte portion of `0x11B`.

The function processes eight bits of the multiplier. It conditionally
XORs the current multiplicand into the result, shifts the multiplicand,
performs field reduction when required, and shifts the multiplier right.

This finite-field multiplication is required by the `MixColumns`
transformation.

### `mix_columns(self, state)`

Multiplies each state column by the fixed AES matrix:

``` text
[2 3 1 1]
[1 2 3 1]
[1 1 2 3]
[3 1 1 2]
```

This is matrix multiplication over GF(2\^8), not ordinary integer matrix
multiplication. Each coefficient is multiplied by a state byte using
`gf_multiply()`, and the resulting products are combined using XOR.

The transformation provides **diffusion**: changes to input bytes spread
across multiple output bytes.

## 8. AES block encryption

### `AES_256_encrypt_block(self, plaintext_state)`

This is the central AES-256 block-encryption function. It takes one
16-byte block represented as a state matrix and applies the AES
transformations.

First, the expanded words are grouped into round keys and each key is
converted into a state matrix.

The initial state is combined with round key 0 using `AddRoundKey`.

Rounds 1 to 13 each perform:

1.  `SubBytes`
2.  `ShiftRows`
3.  `MixColumns`
4.  `AddRoundKey`

The final, fourteenth round performs:

1.  `SubBytes`
2.  `ShiftRows`
3.  `AddRoundKey`

The final round deliberately omits `MixColumns`, as required by the AES
specification.

The function returns the encrypted 4 × 4 state. It implements the **AES
encryption block operation**, not CTR mode by itself.

## 9. Counter (CTR) mode

CTR mode turns the AES block cipher into a way of encrypting data of
arbitrary length.

For each data block, the implementation creates a 128-bit counter block
from:

-   A 96-bit nonce (12 bytes).
-   A 32-bit counter (4 bytes).

AES encrypts this counter block to produce a 128-bit keystream block.
The keystream is XORed with the plaintext to produce ciphertext.

The mathematical relationship is:

``` text
Keystream_i = AES_Encrypt(key, nonce || counter_i)
Ciphertext_i = Plaintext_i XOR Keystream_i
Plaintext_i  = Ciphertext_i XOR Keystream_i
```

Here, `||` means concatenation.

### `_keystream_for(self, nonce, counter)`

This function:

1.  Converts the counter into four big-endian bytes.
2.  Concatenates the 12-byte nonce and four-byte counter to form a
    16-byte block.
3.  Converts that block into an AES state.
4.  Encrypts it using `AES_256_encrypt_block()`.
5.  Converts the encrypted state back into 16 bytes.

The result is one keystream block.

### `AES_256_CTR_encrypt_bytes(self, plaintext_bytes)`

This function encrypts the supplied bytes:

1.  Generates a 12-byte random nonce using `os.urandom(12)`.
2.  Starts the counter at zero.
3.  Iterates over the plaintext in chunks of up to 16 bytes.
4.  Generates a keystream block for the current nonce and counter.
5.  XORs the plaintext chunk with the matching number of keystream
    bytes.
6.  Increments the counter for the next chunk.
7.  Returns the nonce followed by the ciphertext.

CTR mode does not require padding. If the final plaintext chunk is
shorter than 16 bytes, only the corresponding number of keystream bytes
is used.

The output format is:

``` text
[12-byte nonce][ciphertext bytes]
```

### `AES_256_CTR_decrypt_bytes(self, ciphertext_bytes)`

Decryption reverses the CTR process:

1.  Extracts the first 12 bytes as the nonce.
2.  Treats the remaining bytes as ciphertext.
3.  Resets the counter to zero.
4.  Regenerates the same keystream blocks using the same key, nonce and
    counter values.
5.  XORs each ciphertext chunk with its keystream bytes.
6.  Returns the recovered plaintext.

CTR mode uses the AES **encryption** operation to generate the keystream
for both encryption and decryption. A separate AES block-decryption
function is not required.

## 10. How the functions work together

The overall encryption process is:

1.  The user supplies plaintext and an AES-256 key.
2.  The key is converted into bytes and expanded into 60 words.
3.  The words are grouped into 15 round keys.
4.  A random 96-bit nonce is generated.
5.  The plaintext is divided into chunks of up to 16 bytes.
6.  For each chunk, the nonce and counter are combined into a 128-bit
    block.
7.  The block is encrypted using the AES-256 transformations.
8.  The resulting keystream is XORed with the plaintext chunk.
9.  The nonce is prepended to the ciphertext and returned.

During decryption, the nonce is extracted and the same counter sequence
is recreated. XORing the ciphertext with the regenerated keystream
recovers the original plaintext.

## 11. Mathematical concepts demonstrated

  --------------------------------------------------------------------------
  Concept                 Functions                  Role in the
                                                     implementation
  ----------------------- -------------------------- -----------------------
  Linear algebra          `mix_columns()`            Applies a matrix
                                                     transformation to each
                                                     AES state column.

  Discrete mathematics    `xor_bytes()`,             Uses bitwise XOR to
  and Boolean logic       `add_round_key()`          combine binary values.

  Finite-field arithmetic `gf_multiply()`            Implements
                                                     multiplication in
                                                     GF(2\^8).

  Substitution            `substitute_bytes()`,      Uses the S-Box to
                          `sub_word()`               introduce
                                                     non-linearity.

  Permutation and         `shift_rows()`,            Changes the positions
  rearrangement           `rotate_word()`            of bytes.

  Key scheduling          `aes256_key_expansion()`   Derives the round keys
                                                     from the original
                                                     secret key.
  --------------------------------------------------------------------------

These concepts demonstrate how mathematical operations can be translated
into executable Python functions to implement a cryptographic algorithm.

## 12. Implementation limitations and security considerations

This code is useful for studying the internal structure of AES-256-CTR,
but it should not be treated as a production-ready cryptographic library
without further work.

### Key length validation

AES-256 requires exactly 32 key bytes. The constructor should reject
keys of any other length. A hexadecimal key string should contain
exactly 64 hexadecimal characters.

### Nonce uniqueness

A nonce must never be reused with the same AES key in CTR mode. Reusing
a nonce repeats the keystream, which can expose relationships between
plaintexts and compromise confidentiality.

The implementation generates a random 96-bit nonce. Random generation
makes collisions unlikely, but does not guarantee uniqueness. A
production system needs a suitable nonce-management strategy, especially
when encrypting many messages with the same key.

### No authentication or integrity protection

CTR mode provides confidentiality, but it does not authenticate the
ciphertext. An attacker can alter ciphertext bits and cause
corresponding changes in the decrypted plaintext without the alteration
being detected.

For real applications, use an authenticated-encryption scheme such as
**AES-GCM**, through a well-maintained cryptographic library.
Authentication detects tampering as well as providing confidentiality.

### Counter overflow and input validation

The counter is encoded into four bytes, so it has a finite range. The
implementation should prevent counter wraparound and reject malformed
ciphertext that is shorter than the 12-byte nonce.

### Performance and independent verification

A pure-Python implementation is useful for understanding the algorithm
but is unlikely to be as fast or as thoroughly reviewed as a standard
cryptographic library. It should be tested against recognised AES test
vectors and an independent implementation before relying on its
correctness.

### Missing import

The code uses `os.urandom(12)`, so it must include:

``` python
import os
```

### Parent-class attributes

The base class defines `_plaindata`, `_cipherdata`, `_processComplete`
and `_timeOfExecution`, but the encryption and decryption methods shown
do not update these attributes. If they are intended to track the
complete encryption lifecycle, the relevant methods should be connected
to those attributes.

## 13. Standards and further reading

-   **NIST FIPS 197 -- Advanced Encryption Standard (AES):**
    https://doi.org/10.6028/NIST.FIPS.197-upd1
-   **NIST SP 800-38A -- Recommendation for Block Cipher Modes of
    Operation:** https://doi.org/10.6028/NIST.SP.800-38A
-   **NIST SP 800-38D -- Recommendation for Block Cipher Modes of
    Operation: Galois/Counter Mode (GCM):**
    https://doi.org/10.6028/NIST.SP.800-38D

------------------------------------------------------------------------

**Summary:** This implementation combines AES-256 block encryption with
CTR mode. It translates the mathematical principles of substitution,
permutation, linear transformations, finite-field arithmetic and XOR
operations into Python functions. Key expansion supplies the round keys,
AES transforms each counter block into a keystream block, and CTR mode
combines that keystream with the input data to encrypt or recover the
original bytes.
