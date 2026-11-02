''' based on the NIST Framework of the Advanced Ecnryption System, my algorithms took the Linear Algebra and Discrete Mathematics 
and applied and converted it into proper functions that could be used in python 
and in my program with actual inputs from the user'''

class EncryptMyData:  ''' Using OOP and Polymorphism and Inheritance to allow for modularity '''
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

S_BOX = (99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22)  ''' S_BOX used for byte substitution (essentially a lookup table, to sub bytes into the state array)'''

RoundConst = [0, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 452984832, 905969664] ''' used in the key schedule'''
Nb, Nk, Nr = 4, 8, 14 ''' variables used for the key schedule, Nb defines number of columns in a matrix, Nk, number of "words" in the key, Nr number of rounds per block of data'''

class AES256CTR(EncryptMyData): '''inherits parent classes attributes and methods'''
    def __init__(self, key):
        super().__init__()
        self.key = key if isinstance(key, bytes) else bytes.fromhex(key)
        self.round_keys = self.aes256_key_expansion(self.key)
        self.setAlgor('AES-256-CTR')

    def xor_bytes(self, a, b):   '''simple xor of matrixes'''
        result = bytearray(len(a))
        for i in range(len(a)):
            result[i] = a[i] ^ b[i]
        return bytes(result)

    def bytes_to_state(self, b): ''' converts bytes into a matrix''' 
        state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                state[r][c] = b[4 * c + r]
        return state

    def state_to_bytes(self, state): ''' converts a matrix back to 16 bytes'''
        out = bytearray(16)
        idx = 0
        for c in range(4):
            for r in range(4):
                out[idx] = state[r][c]
                idx += 1
        return bytes(out)

    def rotate_word(self, word): '''rotates 32 bit word by 8 bits'''
        return word << 8 & 4294967295 | word >> 24 & 255

    def sub_word(self, word): ''' subs the 4 bytes into the s-box'''
        return S_BOX[word >> 24 & 255] << 24 | S_BOX[word >> 16 & 255] << 16 | S_BOX[word >> 8 & 255] << 8 | S_BOX[word & 255]

    def bytes_to_word(self, b): ''' converts the bytes into a single 32 bit integer'''
        return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]

    def word_to_bytes(self, w): 
        return bytes([w >> 24 & 255, w >> 16 & 255, w >> 8 & 255, w & 255])

    def aes256_key_expansion(self, key_bytes): ''' generates a series of keys for each round'''
        words = [0] * (Nb * (Nr + 1))
        for i in range(Nk):
            words[i] = self.bytes_to_word(key_bytes[4 * i:4 * i + 4])
        for i in range(Nk, Nb * (Nr + 1)):
            temp = words[i - 1]
            if i % Nk == 0:
                temp = self.sub_word(self.rotate_word(temp)) ^ RoundConst[i // Nk]
            elif i % Nk == 4:
                temp = self.sub_word(temp)
            words[i] = words[i - Nk] ^ temp
        return words

    def words_to_round_keys(self, words): ''' takes expanded words into 15 keys for encryption '''
        round_keys = []
        for r in range(Nr + 1):
            w4 = []
            for i in range(4):
                index = 4 * r + i
                w4.append(words[index])
            byte_blocks = b''
            for word in w4:
                byte_blocks += self.word_to_bytes(word)
            round_keys.append(byte_blocks)
        return round_keys

    def add_round_key(self, matrice_a, matrice_b):  ''' XORs key with target block of data '''
        result = []
        for r in range(4):
            row = []
            for c in range(4):
                row.append((matrice_a[r][c] ^ matrice_b[r][c]) & 255)
            result.append(row)
        return result

    def substitute_bytes(self, state): ''' subs block of data in S-Box
        new_state = []
        for row in state:
            new_state.append([S_BOX[byte] for byte in row])
        return new_state

    def shift_rows(self, state):
        return [state[0], [state[1][1], state[1][2], state[1][3], 
                state[1][0]], [state[2][2], state[2][3], state[2][0], 
                state[2][1]], [state[3][3], state[3][0], state[3][1], 
                state[3][2]]]

''' shifts all rows, incrementing each time, chose to do it linearly to decrease time complexity '''

    def gf_multiply(self, a, b): ''' function allowing for galois fields in py'''
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 128 ''' irreducible polynomial theorem '''
            a <<= 1
            if hi_bit_set:
                a ^= 27
            a &= 255
            b >>= 1
        return p & 255

    def mix_columns(self, state): ''' mixes columns with a fixed vector ''' 
        fixed_matrix = [[2, 3, 1, 1], 
                       [1, 2, 3, 1], 
                       [1, 1, 2, 3], 
                       [3, 1, 1, 2]]
        new_state = []
        for row in range(4):
            new_row = []
            for column in range(4):
                value = 0
                for i in range(4): '''uses GF(2^8) to reduce the binary numbers to output the result'''
                    value ^= self.gf_multiply(fixed_matrix[row][i], state[i][column])
                new_row.append(value)
            new_state.append(new_row)
        return new_state

    def AES_256_encrypt_block(self, plaintext_state): '''combines all functions'''
        round_keys = self.words_to_round_keys(self.round_keys)
        round_key_states = [self.bytes_to_state(rk) for rk in round_keys]
        temp = self.add_round_key(plaintext_state, round_key_states[0])
        for i in range(1, 14):
            temp = self.substitute_bytes(temp)
            temp = self.shift_rows(temp)
            temp = self.mix_columns(temp)
            temp = self.add_round_key(temp, round_key_states[i])
        temp = self.substitute_bytes(temp) 
    ''' skips mix column on final round for further permutaiton'''
        temp = self.shift_rows(temp)
        temp = self.add_round_key(temp, round_key_states[14])
        return temp

    def _keystream_for(self, nonce: bytes, counter: int) -> bytes:
        counter_bytes = counter.to_bytes(4, 'big')
        ctr_block = nonce + counter_bytes 
        keystream_state = self.bytes_to_state(ctr_block)
        keystream_state = self.AES_256_encrypt_block(keystream_state)
        return self.state_to_bytes(keystream_state)

    def AES_256_CTR_encrypt_bytes(self, plaintext_bytes: bytes) -> bytes:
        nonce = os.urandom(12) ''' random number for keystream '''
        counter = 0
        out = bytearray()
        for i in range(0, len(plaintext_bytes), 16):
            ks = self._keystream_for(nonce, counter)
            block = plaintext_bytes[i:i + 16]
            out.extend(self.xor_bytes(block, ks[:len(block)]))
            counter += 1
        return nonce + bytes(out)

    def AES_256_CTR_decrypt_bytes(self, ciphertext_bytes: bytes) -> bytes:
        nonce = ciphertext_bytes[:12]
        ciphertext = ciphertext_bytes[12:]
        counter = 0
        out = bytearray()
        for i in range(0, len(ciphertext), 16):
            ks = self._keystream_for(nonce, counter)
            block = ciphertext[i:i + 16]
            out.extend(self.xor_bytes(block, ks[:len(block)]))
            counter += 1
        return bytes(out)
